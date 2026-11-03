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

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
temp_dir=$(mktemp -d)
module_name="coraza-rs-stage-f-rollback-$$.so"
module_path="$repo_root/target/$module_name"
native=(docker compose -f "$repo_root/examples/envoy-coraza-dynamic/compose.yaml" -p "coraza-stage-f-rollback-native-$$")
wasm=(docker compose -f "$repo_root/examples/envoy-coraza/compose.yaml" -p "coraza-stage-f-rollback-wasm-$$")

cleanup() {
    local exit_code=$?
    trap - EXIT
    "${native[@]}" down --volumes >/dev/null 2>&1 || true
    "${wasm[@]}" down --volumes >/dev/null 2>&1 || true
    rm -f "$module_path"
    rm -rf "$temp_dir"
    exit "$exit_code"
}
trap cleanup EXIT

for port in 9901 10001; do
    if ss -H -ltn "sport = :$port" | grep --quiet .; then
        printf 'error: port %s is occupied; not starting rollback harnesses\n' "$port" >&2
        exit 1
    fi
done

make -C "$repo_root" build-envoy-dynamic build-envoy-wasm
cp "$repo_root/target/release/libenvoy_coraza_dynamic.so" "$module_path"

python3 - "$repo_root/examples/envoy-coraza-dynamic/envoy.yaml" "$temp_dir" <<'PY'
import json
import pathlib
import sys

source, directory = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
policy = json.dumps({
    "directives_map": {
        "smoke": [
            "SecRuleEngine On",
            "SecRequestBodyAccess On",
            "SecRequestBodyLimit 16777216",
            'SecAction "id:1,phase:1,ctl:requestBodyProcessor=RAW,pass"',
            'SecRule REQUEST_URI "@streq /phase1-deny" "id:2,phase:1,deny,status:451"',
            'SecRule REQUEST_BODY "@contains body-attack" "id:3,phase:2,deny,status:429"',
        ]
    },
    "default_directives": "smoke",
}, separators=(",", ":"))
base = source.read_text()
placeholder = "                        value: '{}'\n"
if base.count(placeholder) != 1:
    raise SystemExit("expected one native filter configuration placeholder")
native_value = "                        value: |\n" + "".join(
    "                          " + line + "\n" for line in policy.splitlines()
)
(directory / "native.yaml").write_text(base.replace(placeholder, native_value, 1))
start = base.index("                  - name: envoy.filters.http.dynamic_modules\n")
end = base.index("                  - name: envoy.filters.http.router\n", start)
wasm_filter = '''                  - name: envoy.filters.http.wasm
                    typed_config:
                      "@type": type.googleapis.com/udpa.type.v1.TypedStruct
                      type_url: type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
                      value:
                        config:
                          name: coraza-stage-f-rollback
                          root_id: coraza-stage-f-rollback
                          failure_policy: FAIL_CLOSED
                          allow_on_headers_stop_iteration: true
                          vm_config:
                            runtime: envoy.wasm.runtime.v8
                            code:
                              local:
                                filename: /etc/envoy/envoy_coraza.wasm
                          configuration:
                            "@type": type.googleapis.com/google.protobuf.StringValue
                            value: |
''' + "".join("                              " + line + "\n" for line in policy.splitlines())
(directory / "wasm.yaml").write_text(base[:start] + wasm_filter + base[end:])
(directory / "policy.json").write_text(policy)
PY

wait_ready() {
    for _attempt in {1..60}; do
        if curl --silent --fail --max-time 2 http://127.0.0.1:9901/ready >/dev/null; then
            return
        fi
        sleep 1
    done
    printf 'error: Envoy did not become ready\n' >&2
    exit 1
}

backend_count() {
    curl --silent --show-error --header 'Host: stats.local' --get \
        --data-urlencode "path=$1" http://127.0.0.1:10001/__stats
}

smoke() {
    local status before
    before=$(backend_count /phase1-deny)
    status=$(curl --silent --show-error --output "$temp_dir/deny" --write-out '%{http_code}' \
        --header 'Host: example.test' http://127.0.0.1:10001/phase1-deny)
    [[ $status == 451 && $(backend_count /phase1-deny) == "$before" ]] || {
        printf 'error: %s phase-1 deny failed (status=%s)\n' "$1" "$status" >&2
        exit 1
    }

    before=$(backend_count /echo)
    status=$(curl --silent --show-error --output "$temp_dir/body-deny" --write-out '%{http_code}' \
        --header 'Host: example.test' --header 'Content-Type: text/plain' \
        --data-binary body-attack http://127.0.0.1:10001/echo)
    [[ $status == 429 && $(backend_count /echo) == "$before" ]] || {
        printf 'error: %s phase-2 deny failed (status=%s)\n' "$1" "$status" >&2
        exit 1
    }

    status=$(curl --silent --show-error --output "$temp_dir/allow" --write-out '%{http_code}' \
        --header 'Host: example.test' --header 'Content-Type: text/plain' \
        --data-binary rollback-allow http://127.0.0.1:10001/echo)
    if [[ $status != 200 ]] || ! cmp --silent "$temp_dir/allow" <(printf rollback-allow); then
        printf 'error: %s allow failed (status=%s)\n' "$1" "$status" >&2
        exit 1
    fi
    printf '%s filter: same policy SHA-256 %s; deny and allow passed\n' \
        "$1" "$(sha256sum "$temp_dir/policy.json" | cut -d' ' -f1)"
}

ENVOY_CORAZA_DYNAMIC_CONFIG="$temp_dir/native.yaml" \
ENVOY_CORAZA_DYNAMIC_MODULE="target/$module_name" "${native[@]}" up --detach --build
wait_ready
smoke native
"${native[@]}" down --volumes >/dev/null

ENVOY_CORAZA_CONFIG="$temp_dir/wasm.yaml" \
ENVOY_CORAZA_WASM="$repo_root/target/wasm32-wasip1/release/envoy_coraza.wasm" \
    "${wasm[@]}" up --detach --build
wait_ready
smoke wasm

printf 'rollback proof passed: native filter swapped to Wasm, policy bytes unchanged\n'
