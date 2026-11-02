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
script_dir="$repo_root/examples/envoy-coraza-dynamic"
compose=(docker compose -f "$script_dir/compose.yaml" -p envoy-coraza-dynamic-stage-c)
target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
if [[ $target_dir != /* ]]; then
    target_dir="$repo_root/$target_dir"
fi
panic_target_dir="$target_dir/stage-c-panic-$$_$RANDOM"
module_name="envoy-coraza-dynamic-stage-c-$$_$RANDOM.so"
panic_module_name="envoy-coraza-dynamic-stage-c-panic-$$_$RANDOM.so"
module_file="$repo_root/target/$module_name"
panic_module_file="$repo_root/target/$panic_module_name"
temp_dir=$(mktemp -d)

cleanup() {
    local exit_code=$?
    trap - EXIT
    if (( exit_code != 0 )); then
        "${compose[@]}" logs --no-color envoy backend 2>&1 | tail --lines=80 >&2 || true
    fi
    "${compose[@]}" down --rmi local --volumes >/dev/null 2>&1 || true
    rm -f "$module_file" "$panic_module_file"
    rm -rf "$panic_target_dir" "$temp_dir"
    exit "$exit_code"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'python3 is required for controlled HTTP/1.1 framing'
command -v curl >/dev/null 2>&1 || fail 'curl is required'
command -v docker >/dev/null 2>&1 || fail 'docker is required'
if ss -ltn 2>/dev/null | grep --quiet ':9901'; then
    fail 'port 9901 is already occupied; stop only the harness that owns it, then retry'
fi

request() {
    local output=$1
    shift
    curl --silent --show-error --output "$output" --write-out '%{http_code}' "$@"
}

backend_count() {
    local path=$1
    curl --silent --show-error --get --data-urlencode "path=$path" http://127.0.0.1:10001/__stats
}

envoy_logs() {
    "${compose[@]}" logs --no-color --no-log-prefix envoy 2>/dev/null || true
}

check_status() {
    local expected=$1
    local actual=$2
    local label=$3
    [[ $actual == "$expected" ]] || fail "$label returned HTTP $actual, expected $expected"
}

wait_ready() {
    for _attempt in {1..60}; do
        status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
            http://127.0.0.1:9901/ready || true)
        [[ $status == 200 ]] && return
        sleep 1
    done
    fail 'Envoy did not become ready with the native filter installed'
}

write_bootstrap() {
    local first_config=$1
    local output=$2
    local second_config=${3:-}
    python3 - "$script_dir/envoy.yaml" "$first_config" "$output" "$second_config" <<'PY'
import json
import pathlib
import sys

source, first, output, second = sys.argv[1:]
text = pathlib.Path(source).read_text()

def filter_block(config):
    indent = " " * 18
    return (
        indent + "- name: envoy.filters.http.dynamic_modules\n"
        + indent + "  typed_config:\n"
        + indent + '    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter\n'
        + indent + "    dynamic_module_config:\n"
        + indent + "      name: envoy_coraza_dynamic\n"
        + indent + "      do_not_close: true\n"
        + indent + "      load_globally: false\n"
        + indent + "    filter_name: coraza\n"
        + indent + "    filter_config:\n"
        + indent + '      "@type": type.googleapis.com/google.protobuf.StringValue\n'
        + indent + "      value: |\n"
        + "".join(indent + "        " + line + "\n" for line in config.splitlines())
    )

first_line = "                        value: '{}'"
if first == "__INVALID_UTF8__":
    text = text.replace(
        "type.googleapis.com/google.protobuf.StringValue",
        "type.googleapis.com/google.protobuf.BytesValue",
        1,
    ).replace(first_line, '                        value: "/w=="', 1)
else:
    scalar = "                        value: |\n"
    scalar += "".join("                          " + line + "\n" for line in first.splitlines())
    text = text.replace(first_line, scalar, 1)

if second:
    router = "                  - name: envoy.filters.http.router"
    text = text.replace(router, filter_block(second) + router, 1)
pathlib.Path(output).write_text(text)
PY
}

start_envoy() {
    local config=$1
    "${compose[@]}" down --volumes >/dev/null 2>&1 || true
    ENVOY_CORAZA_DYNAMIC_CONFIG="$config" "${compose[@]}" up --detach
    wait_ready
}

expect_startup_rejection() {
    local label=$1
    local config=$2
    if ENVOY_CORAZA_DYNAMIC_CONFIG="$config" "${compose[@]}" run --rm --no-deps --service-ports envoy \
        >"$temp_dir/$label.log" 2>&1; then
        fail "$label unexpectedly started Envoy"
    fi
    if curl --silent --show-error --max-time 1 http://127.0.0.1:10001/should-not-be-unfiltered \
        >"$temp_dir/$label.response" 2>/dev/null; then
        fail "$label served a request after rejected startup"
    fi
    printf 'negative-control %s: startup rejected; listener did not serve traffic\n' "$label"
}

phase_policy='{"directives_map":{"main":["SecRuleEngine On","SecRequestBodyAccess On","SecRequestBodyLimit 16777216","SecAction \"id:1,phase:1,ctl:requestBodyProcessor=RAW,pass\"","SecRule REQUEST_URI \"@contains phase1-deny\" \"id:2,phase:1,deny,status:451\"","SecRule REQUEST_BODY \"@contains body-attack\" \"id:3,phase:2,deny,status:429\"","SecRule REQUEST_URI \"@contains redirect-deny\" \"id:4,phase:1,redirect:https://example.test/blocked,status:307\"","SecRule REQUEST_URI \"@contains no-content\" \"id:5,phase:1,deny,status:204\"","SecRule REQUEST_URI \"@contains not-modified\" \"id:6,phase:1,deny,status:304\""]},"default_directives":"main"}'
write_bootstrap "$phase_policy" "$temp_dir/phase-policy.yaml"

cargo build --locked --release -p envoy-coraza-dynamic
cp "$target_dir/release/libenvoy_coraza_dynamic.so" "$module_file"
export ENVOY_CORAZA_DYNAMIC_MODULE="target/$module_name"
"${compose[@]}" build backend envoy

start_envoy "$temp_dir/phase-policy.yaml"
status=$(request "$temp_dir/default-panic" --header 'x-coraza-probe: panic' http://127.0.0.1:10001/healthy)
check_status 200 "$status" 'default build with the panic-probe header'
if envoy_logs | grep --quiet --fixed-strings 'caught panic'; then
    fail 'default build executed the feature-gated panic probe'
fi

before=$(backend_count /phase1-deny)
status=$(request "$temp_dir/phase1" http://127.0.0.1:10001/phase1-deny)
check_status 451 "$status" 'phase-1 rule denial'
[[ $(backend_count /phase1-deny) == "$before" ]] || fail 'phase-1 denied request reached the backend'

before=$(backend_count /phase1-deny)
python3 - <<'PY'
import http.client

connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=10)
try:
    connection.request("HEAD", "/phase1-deny")
    response = connection.getresponse()
    body = response.read()
    if response.status != 451 or body:
        raise RuntimeError(f"HEAD denial returned status={response.status}, body={body!r}")
finally:
    connection.close()
PY
[[ $(backend_count /phase1-deny) == "$before" ]] || fail 'HEAD denial reached the backend'

status=$(request "$temp_dir/redirect" --dump-header "$temp_dir/redirect.headers" \
    http://127.0.0.1:10001/redirect-deny)
check_status 307 "$status" 'rule-configured redirect status'
grep --ignore-case --quiet --fixed-strings 'location: https://example.test/blocked' "$temp_dir/redirect.headers" \
    || fail 'configured redirect location was missing'
[[ ! -s "$temp_dir/redirect" ]] || fail 'redirect denial returned a response body'

status=$(request "$temp_dir/no-content" http://127.0.0.1:10001/no-content)
check_status 204 "$status" 'rule-configured 204 denial'
[[ ! -s "$temp_dir/no-content" ]] || fail '204 denial returned a response body'
status=$(request "$temp_dir/not-modified" http://127.0.0.1:10001/not-modified)
check_status 304 "$status" 'rule-configured 304 denial'
[[ ! -s "$temp_dir/not-modified" ]] || fail '304 denial returned a response body'

before=$(backend_count /echo)
status=$(request "$temp_dir/body-deny" --request POST --header 'content-type: text/plain' \
    --data-binary 'body-attack' http://127.0.0.1:10001/echo)
check_status 429 "$status" 'phase-2 request-body rule denial'
[[ $(backend_count /echo) == "$before" ]] || fail 'phase-2 denied request reached the backend'

before=$(backend_count /echo)
status=$(request "$temp_dir/unsupported-encoding" --request POST --header 'content-type: text/plain' \
    --header 'content-encoding: gzip' --data-binary 'encoded' http://127.0.0.1:10001/echo)
check_status 415 "$status" 'unsupported request content encoding'
[[ $(backend_count /echo) == "$before" ]] || fail 'unsupported-encoding request reached the backend'

status=$(request "$temp_dir/upgrade" --header 'Connection: Upgrade' --header 'Upgrade: websocket' \
    http://127.0.0.1:10001/upgrade)
if [[ $status != 501 ]]; then
    cat "$temp_dir/upgrade" >&2
    fail "unsupported request upgrade returned HTTP $status, expected 501"
fi

python3 - "$temp_dir/upload" <<'PY'
import http.client
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
payload = bytes(range(256)) * 256
chunks = [payload[:16383], payload[16383:16384], payload[16384:32768], payload[32768:]]
connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=15)
try:
    connection.putrequest("POST", "/echo", skip_accept_encoding=True)
    connection.putheader("Content-Type", "application/octet-stream")
    connection.putheader("Transfer-Encoding", "chunked")
    connection.putheader("Connection", "close")
    connection.endheaders()
    for chunk in chunks:
        connection.send(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
    connection.send(b"0\r\n\r\n")
    response = connection.getresponse()
    body = response.read()
    if response.status != 200 or body != payload:
        raise RuntimeError(f"multi-frame upload mismatch: status={response.status} bytes={len(body)}")
    output.write_bytes(body)
finally:
    connection.close()
PY
cmp --silent <(python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256)) * 256)') "$temp_dir/upload" \
    || fail 'allowed multi-frame upload changed across 16 KiB boundaries'

python3 - "$temp_dir/trailer-body" "$temp_dir/trailer-headers" <<'PY'
import http.client
import pathlib
import sys

body_path, headers_path = map(pathlib.Path, sys.argv[1:])
connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=15)
try:
    connection.putrequest("POST", "/echo", skip_accept_encoding=True)
    connection.putheader("Content-Type", "text/plain")
    connection.putheader("Transfer-Encoding", "chunked")
    connection.putheader("Trailer", "x-client-trailer")
    connection.putheader("Connection", "close")
    connection.endheaders()
    for chunk in (b"trailer-", b"terminated"):
        connection.send(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
    connection.send(b"0\r\nx-client-trailer: preserved\r\n\r\n")
    response = connection.getresponse()
    headers = response.getheaders()
    body = response.read()
    if response.status != 200 or body != b"trailer-terminated":
        raise RuntimeError(f"trailer-terminated body mismatch: status={response.status}, body={body!r}")
    if not any(name.lower() == "x-client-trailer-seen" and value == "preserved" for name, value in headers):
        raise RuntimeError(f"backend did not receive the trailer: {headers!r}")
    body_path.write_bytes(body)
    headers_path.write_text(repr(headers))
finally:
    connection.close()
PY

"${compose[@]}" down --volumes >/dev/null

detection_policy='{"directives_map":{"main":["SecRuleEngine DetectionOnly","SecRequestBodyAccess On","SecRequestBodyLimit 16777216","SecAction \"id:1,phase:1,ctl:requestBodyProcessor=RAW,pass\"","SecRule REQUEST_URI \"@contains phase1-deny\" \"id:2,phase:1,deny,status:451\"","SecRule REQUEST_BODY \"@contains body-attack\" \"id:3,phase:2,deny,status:429\""]},"default_directives":"main"}'
write_bootstrap "$detection_policy" "$temp_dir/detection-only.yaml"
start_envoy "$temp_dir/detection-only.yaml"
status=$(request "$temp_dir/detection-phase1" http://127.0.0.1:10001/phase1-deny)
check_status 200 "$status" 'DetectionOnly phase-1 would-be denial'
status=$(request "$temp_dir/detection-phase2" --request POST --header 'content-type: text/plain' \
    --data-binary 'body-attack' http://127.0.0.1:10001/echo)
check_status 200 "$status" 'DetectionOnly phase-2 would-be denial'
[[ $(cat "$temp_dir/detection-phase2") == 'body-attack' ]] || fail 'DetectionOnly changed the request body'
"${compose[@]}" down --volumes >/dev/null

body_off_policy='{"directives_map":{"body_off":["SecRuleEngine On","SecRequestBodyAccess Off","SecRule REQUEST_BODY \"@contains body-attack\" \"id:4,phase:2,deny,status:429\""]},"default_directives":"body_off"}'
write_bootstrap "$body_off_policy" "$temp_dir/body-off.yaml"
start_envoy "$temp_dir/body-off.yaml"
status=$(request "$temp_dir/body-off" --request POST --header 'content-type: text/plain' \
    --data-binary 'body-attack' http://127.0.0.1:10001/echo)
check_status 200 "$status" 'SecRequestBodyAccess Off'
[[ $(cat "$temp_dir/body-off") == 'body-attack' ]] || fail 'body-access-off request changed the upload'
"${compose[@]}" down --volumes >/dev/null

engine_off_policy='{"directives_map":{"off":["SecRuleEngine Off","SecRule REQUEST_URI \"@contains phase1-deny\" \"id:7,phase:1,deny,status:451\""]},"default_directives":"off"}'
write_bootstrap "$engine_off_policy" "$temp_dir/engine-off.yaml"
start_envoy "$temp_dir/engine-off.yaml"
status=$(request "$temp_dir/engine-off" http://127.0.0.1:10001/phase1-deny)
check_status 200 "$status" 'SecRuleEngine Off explicit uninspected pass'
"${compose[@]}" down --volumes >/dev/null

unmatched_policy='{"directives_map":{"protected":["SecRuleEngine On","SecRule REQUEST_URI \"@contains phase1-deny\" \"id:5,phase:1,deny,status:451\""]},"per_authority_directives":{"protected.test":"protected"}}'
write_bootstrap "$unmatched_policy" "$temp_dir/unmatched.yaml"
start_envoy "$temp_dir/unmatched.yaml"
status=$(request "$temp_dir/unmatched" --header 'Host: unmatched.test' http://127.0.0.1:10001/phase1-deny)
check_status 200 "$status" 'unmatched authority bypass'
status=$(request "$temp_dir/matched-authority" --header 'Host: protected.test' http://127.0.0.1:10001/phase1-deny)
check_status 451 "$status" 'normalized authority policy selection'
"${compose[@]}" down --volumes >/dev/null

write_bootstrap '{}' "$temp_dir/empty-config.yaml"
start_envoy "$temp_dir/empty-config.yaml"
status=$(request "$temp_dir/empty-config" http://127.0.0.1:10001/phase1-deny)
check_status 200 "$status" 'empty policy configuration bypass'
"${compose[@]}" down --volumes >/dev/null

first_instance='{"directives_map":{"first":["SecRuleEngine On","SecRule REQUEST_URI \"@contains first-instance\" \"id:10,phase:1,deny,status:451\""]},"default_directives":"first"}'
second_instance='{"directives_map":{"second":["SecRuleEngine On","SecRule REQUEST_URI \"@contains second-instance\" \"id:11,phase:1,deny,status:452\""]},"default_directives":"second"}'
write_bootstrap "$first_instance" "$temp_dir/two-instances.yaml" "$second_instance"
start_envoy "$temp_dir/two-instances.yaml"
status=$(request "$temp_dir/first-instance" http://127.0.0.1:10001/first-instance)
check_status 451 "$status" 'first independent filter policy'
status=$(request "$temp_dir/second-instance" http://127.0.0.1:10001/second-instance)
check_status 452 "$status" 'second independent filter policy'
status=$(request "$temp_dir/two-instance-allow" http://127.0.0.1:10001/allowed)
check_status 200 "$status" 'independent filter pass'
"${compose[@]}" down --volumes >/dev/null

write_bootstrap '{}' "$temp_dir/empty.yaml"
unknown_config="$temp_dir/unknown-name.yaml"
write_bootstrap '{}' "$unknown_config"
sed -i '0,/filter_name: coraza/s//filter_name: unknown/' "$unknown_config"
expect_startup_rejection unknown-filter-name "$unknown_config"

invalid_json_config="$temp_dir/invalid-json.yaml"
write_bootstrap 'not-json' "$invalid_json_config"
expect_startup_rejection malformed-json "$invalid_json_config"

invalid_utf8_config="$temp_dir/invalid-utf8.yaml"
write_bootstrap '__INVALID_UTF8__' "$invalid_utf8_config"
expect_startup_rejection malformed-utf8 "$invalid_utf8_config"

cargo build --locked --release -p envoy-coraza-dynamic --features panic-probe --target-dir "$panic_target_dir"
cp "$panic_target_dir/release/libenvoy_coraza_dynamic.so" "$panic_module_file"
export ENVOY_CORAZA_DYNAMIC_MODULE="target/$panic_module_name"
"${compose[@]}" build envoy
write_bootstrap '{}' "$temp_dir/panic.yaml"
start_envoy "$temp_dir/panic.yaml"
before=$(backend_count /panic)
status=$(request "$temp_dir/panic" --header 'x-coraza-probe: panic' http://127.0.0.1:10001/panic)
check_status 500 "$status" 'feature-gated request panic fail-closed response'
[[ $(backend_count /panic) == "$before" ]] || fail 'panicking request reached the backend'
status=$(request "$temp_dir/panic-followup" http://127.0.0.1:10001/healthy)
check_status 200 "$status" 'healthy request after request panic'

printf 'Envoy 1.40 native request-enforcement checks passed\n'
