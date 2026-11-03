#!/usr/bin/env bash
# Copyright Coraza Kubernetes Operator contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

: "${ENVOY_IMAGE:?set ENVOY_IMAGE to the locally built derived image}"
image_platform=${ENVOY_PLATFORM:-linux/arm64}
expected_arch=${image_platform##*/}

for command in comm curl docker python3 readelf sort ss; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'error: %s is required\n' "$command" >&2
        exit 1
    }
done

arch=$(docker image inspect --format '{{.Architecture}}' "$ENVOY_IMAGE")
[[ $arch == "$expected_arch" ]] || {
    printf 'error: image %s has architecture %s, expected %s\n' "$ENVOY_IMAGE" "$arch" "$expected_arch" >&2
    exit 1
}
for port in 9901 10001 3000; do
    if ss -H -ltn "sport = :$port" | grep --quiet .; then
        printf 'error: port %s is occupied; not starting the arm64 smoke stack\n' "$port" >&2
        exit 1
    fi
done

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
temp_dir=$(mktemp -d)
backend_pid=
envoy_pid=
probe_container=
cleanup() {
    local exit_code=$?
    trap - EXIT
    if [[ -n $envoy_pid ]]; then
        kill "$envoy_pid" 2>/dev/null || true
        wait "$envoy_pid" 2>/dev/null || true
    fi
    if [[ -n $backend_pid ]]; then
        kill "$backend_pid" 2>/dev/null || true
        wait "$backend_pid" 2>/dev/null || true
    fi
    if [[ -n $probe_container ]]; then
        docker rm "$probe_container" >/dev/null 2>&1 || true
    fi
    if (( exit_code != 0 )) && [[ -f $temp_dir/envoy.log ]]; then
        tail --lines=80 "$temp_dir/envoy.log" >&2 || true
    fi
    rm -rf "$temp_dir"
    exit "$exit_code"
}
trap cleanup EXIT

probe_container=$(docker create --platform "$image_platform" "$ENVOY_IMAGE")
docker cp "$probe_container:/usr/local/bin/envoy" "$temp_dir/envoy"
docker cp "$probe_container:/opt/envoy/modules/libenvoy_coraza_dynamic.so" "$temp_dir/module.so"
docker rm "$probe_container" >/dev/null
probe_container=
readelf --wide --dyn-syms "$temp_dir/module.so" \
    | awk '$7 == "UND" && $8 ~ /^envoy_dynamic_module_callback_/ {print $8}' \
    | sort -u >"$temp_dir/imports.txt"
readelf --wide --dyn-syms "$temp_dir/envoy" \
    | awk '($5 == "GLOBAL" || $5 == "WEAK") && $7 != "UND" {print $8}' \
    | sort -u >"$temp_dir/exports.txt"
comm -23 "$temp_dir/imports.txt" "$temp_dir/exports.txt" >"$temp_dir/unresolved.txt"
if [[ -s $temp_dir/unresolved.txt ]]; then
    cat "$temp_dir/unresolved.txt" >&2
    printf 'error: Envoy does not export all imported dynamic-module callbacks\n' >&2
    exit 1
fi

python3 - "$repo_root/examples/envoy-coraza-dynamic/envoy.yaml" "$temp_dir/envoy.yaml" <<'PY'
import json
import pathlib
import sys

source, destination = map(pathlib.Path, sys.argv[1:])
text = source.read_text().replace("address: backend\n", "address: 127.0.0.1\n", 1)
policy = json.dumps({
    "directives_map": {
        "smoke": [
            "SecRuleEngine On",
            'SecRule REQUEST_URI "@streq /deny" "id:1,phase:1,deny,status:403"',
        ]
    },
    "default_directives": "smoke",
}, indent=2)
placeholder = "                        value: '{}'\n"
if text.count(placeholder) != 1:
    raise SystemExit("expected one dynamic-module configuration placeholder")
value = "                        value: |\n" + "".join(
    "                          " + line + "\n" for line in policy.splitlines()
)
destination.write_text(text.replace(placeholder, value, 1))
PY

python3 - "$temp_dir/envoy.yaml" "$temp_dir/invalid.yaml" <<'PY'
import pathlib
import sys

valid, invalid = map(pathlib.Path, sys.argv[1:])
text = valid.read_text()
if text.count("filter_name: coraza") != 1:
    raise SystemExit("expected one Coraza filter-name entry")
invalid.write_text(text.replace("filter_name: coraza", "filter_name: invalid", 1))
PY
if docker run --rm --platform "$image_platform" --network none \
    --volume "$temp_dir/invalid.yaml:/etc/envoy/invalid.yaml:ro" \
    "$ENVOY_IMAGE" -c /etc/envoy/invalid.yaml --log-level critical \
    >"$temp_dir/invalid.log" 2>&1; then
    printf 'error: derived image accepted an unknown native filter name\n' >&2
    exit 1
fi

python3 - "$temp_dir/backend-count" <<'PY' >"$temp_dir/backend.log" 2>&1 &
import pathlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

count_file = pathlib.Path(sys.argv[1])

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with count_file.open("a") as count:
            count.write(self.path + "\n")
        body = b"arm64-smoke-allow"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

ThreadingHTTPServer(("127.0.0.1", 3000), Handler).serve_forever()
PY
backend_pid=$!

docker run --rm --platform "$image_platform" --network host \
    --volume "$temp_dir/envoy.yaml:/etc/envoy/envoy.yaml:ro" \
    "$ENVOY_IMAGE" -c /etc/envoy/envoy.yaml --log-level warning \
    >"$temp_dir/envoy.log" 2>&1 &
envoy_pid=$!

ready=false
for _attempt in {1..120}; do
    if ! kill -0 "$envoy_pid" 2>/dev/null; then
        printf 'error: derived Envoy exited before readiness\n' >&2
        exit 1
    fi
    if curl --silent --fail --max-time 2 http://127.0.0.1:9901/ready >/dev/null; then
        ready=true
        break
    fi
    sleep 1
done
[[ $ready == true ]] || {
    printf 'error: derived Envoy did not become ready\n' >&2
    exit 1
}

deny_status=$(curl --silent --show-error --max-time 10 --output "$temp_dir/deny" --write-out '%{http_code}' http://127.0.0.1:10001/deny)
[[ $deny_status == 403 ]] || {
    printf 'error: deny returned HTTP %s, expected 403\n' "$deny_status" >&2
    exit 1
}
[[ ! -s $temp_dir/backend-count ]] || {
    printf 'error: denied request reached the backend\n' >&2
    exit 1
}

allow_status=$(curl --silent --show-error --max-time 10 --output "$temp_dir/allow" --write-out '%{http_code}' http://127.0.0.1:10001/allow)
[[ $allow_status == 200 && $(cat "$temp_dir/allow") == arm64-smoke-allow ]] || {
    printf 'error: allow did not return the backend response (HTTP %s)\n' "$allow_status" >&2
    exit 1
}
[[ $(cat "$temp_dir/backend-count") == /allow ]] || {
    printf 'error: expected only the allowed request to reach the backend\n' >&2
    exit 1
}

docker run --rm --platform "$image_platform" --entrypoint sh "$ENVOY_IMAGE" \
    -c 'ldd /opt/envoy/modules/libenvoy_coraza_dynamic.so' >"$temp_dir/ldd.txt"
if grep --quiet 'not found' "$temp_dir/ldd.txt"; then
    cat "$temp_dir/ldd.txt" >&2
    printf 'error: arm64 module dependency is unresolved\n' >&2
    exit 1
fi

printf '%s derived Envoy smoke passed: ELF imports, invalid-config rejection, load, deny-before-backend, allow, ldd\n' "$expected_arch"
