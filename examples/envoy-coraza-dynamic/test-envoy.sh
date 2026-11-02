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
crs_target_dir="$target_dir/stage-d-crs-$$_$RANDOM"
module_name="envoy-coraza-dynamic-stage-c-$$_$RANDOM.so"
panic_module_name="envoy-coraza-dynamic-stage-c-panic-$$_$RANDOM.so"
crs_module_name="envoy-coraza-dynamic-stage-d-crs-$$_$RANDOM.so"
module_file="$repo_root/target/$module_name"
panic_module_file="$repo_root/target/$panic_module_name"
crs_module_file="$repo_root/target/$crs_module_name"
temp_dir=$(mktemp -d)

cleanup() {
    local exit_code=$?
    trap - EXIT
    if (( exit_code != 0 )); then
        "${compose[@]}" logs --no-color envoy backend 2>&1 | tail --lines=80 >&2 || true
    fi
    "${compose[@]}" down --rmi local --volumes >/dev/null 2>&1 || true
    rm -f "$module_file" "$panic_module_file" "$crs_module_file"
    rm -rf "$panic_target_dir" "$crs_target_dir" "$temp_dir"
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

abort_held_http1_upload() {
    python3 - <<'PY'
import select
import socket
import struct
import time

connection = socket.create_connection(("127.0.0.1", 10001), timeout=10)
try:
    connection.sendall(
        b"POST /cancel-upload HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 8388608\r\n"
        b"Connection: close\r\n\r\n"
    )
    chunk = b"x" * (64 * 1024)
    for _ in range(32):
        connection.sendall(chunk)
        time.sleep(0.01)
    readable, _, _ = select.select([connection], [], [], 0.5)
    if readable and connection.recv(4096):
        raise RuntimeError("Envoy responded before the upload reached EOS")
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
finally:
    connection.close()
PY
}

backend_count() {
    local path=$1
    curl --silent --show-error --header 'Host: stats.local' --get --data-urlencode "path=$path" \
        http://127.0.0.1:10001/__stats
}

envoy_logs() {
    "${compose[@]}" logs --no-color --no-log-prefix envoy 2>/dev/null || true
}

require_access_log() {
    local path=$1
    local expected=$2
    for _attempt in {1..100}; do
        local latest
        latest=$(envoy_logs | grep --fixed-strings "path=$path " | tail --lines=1 || true)
        if [[ $latest == *"$expected"* ]]; then
            return
        fi
        sleep 0.1
    done
    envoy_logs >"$temp_dir/envoy.log"
    grep --fixed-strings 'path=' "$temp_dir/envoy.log" >&2 || true
    fail "Envoy access log for $path did not contain: $expected"
}

check_status() {
    local expected=$1
    local actual=$2
    local label=$3
    [[ $actual == "$expected" ]] || fail "$label returned HTTP $actual, expected $expected"
}

make_body_with_byte() {
    local destination=$1
    local size=$2
    local byte=$3
    head -c "$size" /dev/zero | tr '\000' "$byte" >"$destination"
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
    local concurrency=${2:-0}
    "${compose[@]}" down --volumes >/dev/null 2>&1 || true
    ENVOY_CORAZA_DYNAMIC_CONFIG="$config" \
        ENVOY_CORAZA_DYNAMIC_CONCURRENCY="$concurrency" "${compose[@]}" up --detach
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

phase_policy='{"directives_map":{"main":["SecRuleEngine On","SecAuditEngine RelevantOnly","SecAuditLogFormat JSON","SecRequestBodyAccess On","SecRequestBodyLimit 16777216","SecResponseBodyAccess On","SecResponseBodyLimit 1048576","SecResponseBodyMimeType text/plain","SecAction \"id:1,phase:1,ctl:requestBodyProcessor=RAW,pass\"","SecRule REQUEST_URI \"@contains phase1-deny\" \"id:2,phase:1,deny,status:451\"","SecRule REQUEST_BODY \"@contains body-attack\" \"id:3,phase:2,deny,status:429\"","SecRule REQUEST_URI \"@contains redirect-deny\" \"id:4,phase:1,redirect:https://example.test/blocked,status:307\"","SecRule REQUEST_URI \"@contains no-content\" \"id:5,phase:1,deny,status:204\"","SecRule REQUEST_URI \"@contains not-modified\" \"id:6,phase:1,deny,status:304\"","SecRule RESPONSE_BODY \"@contains secret\" \"id:8,phase:4,deny,status:451,auditlog,msg:'stage-d-response-audit'\"","SecRule RESPONSE_HEADERS:x-deny-response \"@streq yes\" \"id:9,phase:4,deny,status:452\"","SecRule RESPONSE_BODY \"@contains response-redirect\" \"id:10,phase:4,redirect:https://example.test/response-blocked,status:307\""] ,"off":["SecRuleEngine On","SecResponseBodyAccess Off","SecRule RESPONSE_HEADERS:x-deny-response \"@streq yes\" \"id:11,phase:4,deny,status:452\""],"head":["SecRuleEngine On","SecRule RESPONSE_HEADERS:x-upstream-secret \"@streq upstream-header-marker\" \"id:12,phase:3,deny,status:204\""],"not-modified":["SecRuleEngine On","SecRule RESPONSE_HEADERS:x-upstream-secret \"@streq upstream-header-marker\" \"id:13,phase:3,deny,status:304\""],"limit":["SecRuleEngine On","SecResponseBodyAccess On","SecResponseBodyLimit 5","SecResponseBodyLimitAction Reject","SecResponseBodyMimeType text/plain"],"stats":["SecRuleEngine Off"]},"default_directives":"main","per_authority_directives":{"off.local":"off","head.local":"head","not-modified.local":"not-modified","limit.local":"limit","stats.local":"stats"},"enable_filter_state_logs":true}'
write_bootstrap "$phase_policy" "$temp_dir/phase-policy.yaml"

make -C "$repo_root" crs-fetch
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

status=$(request "$temp_dir/telemetry-allow" http://127.0.0.1:10001/telemetry-allow)
check_status 200 "$status" 'healthy telemetry request'
require_access_log /telemetry-allow 'event=- rule_id=- phase=- action=- status=- reason=complete outcome=completed complete=true'

# Exercise worker-local stream state while the shared module admission remains
# process-wide: the denied and byte-exact allowed requests run concurrently.
start_envoy "$temp_dir/phase-policy.yaml" 2
make_body_with_byte "$temp_dir/multi-worker-expected" 65536 x
before=$(backend_count /phase1-deny)
request "$temp_dir/multi-worker-deny" http://127.0.0.1:10001/phase1-deny \
    >"$temp_dir/multi-worker-deny.status" &
deny_pid=$!
request "$temp_dir/multi-worker-allow" --request POST \
    --header 'content-type: application/octet-stream' \
    --data-binary "@$temp_dir/multi-worker-expected" http://127.0.0.1:10001/echo \
    >"$temp_dir/multi-worker-allow.status" &
allow_pid=$!
if ! wait "$deny_pid"; then fail 'multi-worker deny request failed'; fi
if ! wait "$allow_pid"; then fail 'multi-worker allow request failed'; fi
check_status 451 "$(cat "$temp_dir/multi-worker-deny.status")" 'multi-worker request denial'
check_status 200 "$(cat "$temp_dir/multi-worker-allow.status")" 'multi-worker allow request'
[[ $(backend_count /phase1-deny) == "$before" ]] || fail 'multi-worker denied request reached the backend'
cmp --silent "$temp_dir/multi-worker-expected" "$temp_dir/multi-worker-allow" \
    || fail 'multi-worker allowed upload changed in transit'

# Cap curl at one origin connection; stream IDs 1 and 3 prove multiplexing.
python3 - "$temp_dir/http2-expected" <<'PY'
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_bytes(bytes(range(256)) * 8)
PY
before=$(backend_count /phase1-deny)
curl --parallel --parallel-max-host 1 --http2-prior-knowledge \
    --trace-ascii "$temp_dir/http2.trace" --silent --show-error \
    --output "$temp_dir/http2-deny" --write-out 'deny %{http_version} %{http_code}\n' \
    http://127.0.0.1:10001/phase1-deny \
    --next --parallel-max-host 1 --http2-prior-knowledge --silent --show-error \
    --output "$temp_dir/http2-allow" --write-out 'allow %{http_version} %{http_code}\n' \
    --request POST --header 'content-type: application/octet-stream' \
    --data-binary "@$temp_dir/http2-expected" http://127.0.0.1:10001/echo \
    >"$temp_dir/http2.status"
grep --quiet --fixed-strings 'deny 2 451' "$temp_dir/http2.status" \
    || fail 'HTTP/2 deny stream did not receive status 451'
grep --quiet --fixed-strings 'allow 2 200' "$temp_dir/http2.status" \
    || fail 'HTTP/2 allow stream did not receive status 200'
grep --quiet --fixed-strings '[1] OPENED stream' "$temp_dir/http2.trace" \
    || fail 'HTTP/2 first stream was not observed'
grep --quiet --fixed-strings '[3] OPENED stream' "$temp_dir/http2.trace" \
    || fail 'HTTP/2 second multiplexed stream was not observed'
[[ $(backend_count /phase1-deny) == "$before" ]] || fail 'HTTP/2 denied stream reached the backend'
cmp --silent "$temp_dir/http2-expected" "$temp_dir/http2-allow" \
    || fail 'HTTP/2 allowed stream changed in transit'

before=$(backend_count /cancel-upload)
abort_held_http1_upload
[[ $(backend_count /cancel-upload) == "$before" ]] || fail 'cancelled upload reached the backend before EOS'
status=$(request "$temp_dir/cancel-followup" --max-time 10 \
    http://127.0.0.1:10001/healthy-after-cancel)
check_status 200 "$status" 'healthy request after cancelled upload'

# Four incomplete 13 MiB bodies retain 52 MiB; the fifth crosses the 64 MiB
# process-wide budget while remaining below the 16 MiB per-stream ceiling.
python3 - <<'PY'
import socket
import struct

address = ("127.0.0.1", 10001)
reserved = []
chunk = b"a" * (64 * 1024)
try:
    for index in range(5):
        connection = socket.create_connection(address, timeout=30)
        connection.settimeout(30)
        reserved.append(connection)
        connection.sendall(
            b"POST /admission HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: 15728640\r\n"
            b"Connection: close\r\n\r\n"
        )
        for _ in range(13 * 16):
            try:
                connection.sendall(chunk)
            except OSError:
                break
        if index == 4:
            response = bytearray()
            while b"\r\n" not in response:
                data = connection.recv(1024)
                if not data:
                    break
                response.extend(data)
            if b" 503 " not in response:
                raise RuntimeError(f"admission exhaustion was not denied with 503: {response!r}")
finally:
    for connection in reserved:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        connection.close()
PY
status=$(request "$temp_dir/admission-followup" --max-time 10 \
    http://127.0.0.1:10001/healthy-after-admission)
check_status 200 "$status" 'healthy request after admission reservations release'

before=$(backend_count /response-deny)
status=$(request "$temp_dir/response-body-deny" --dump-header "$temp_dir/response-body-deny.headers" \
    http://127.0.0.1:10001/response-deny)
check_status 451 "$status" 'phase-4 response-body rule denial from the encode-body callback'
[[ $(backend_count /response-deny) -eq $((before + 1)) ]] || fail 'response-body-deny request did not reach the backend exactly once'
[[ $(cat "$temp_dir/response-body-deny") == 'Upstream response blocked' ]] || fail 'response-body denial leaked or changed its replacement body'
if grep --ignore-case --quiet --extended-regexp 'x-upstream-secret|set-cookie: upstream-secret|secret upstream response' \
    "$temp_dir/response-body-deny.headers" "$temp_dir/response-body-deny"; then
    fail 'response-body denial leaked upstream content or headers'
fi
require_access_log /response-deny 'event=coraza_waf_blocked_request rule_id=8 phase=http_response_body action=deny status=451 reason=denied outcome=denied complete=true'
audit_count=$(envoy_logs | grep --count --fixed-strings 'stage-d-response-audit' || true)
[[ $audit_count == 1 ]] || fail "response transaction emitted the audit record $audit_count times instead of once"
grep --ignore-case --quiet --fixed-strings 'event=coraza_waf_blocked_request rule_id=8 phase=http_response_body action=deny status=451' \
    <(envoy_logs) || fail 'response-body interruption fields were not published before access logging'

status=$(request "$temp_dir/response-denial-followup" http://127.0.0.1:10001/healthy-after-response-deny)
check_status 200 "$status" 'healthy response after response denial'
require_access_log /healthy-after-response-deny \
    'event=- rule_id=- phase=- action=- status=- reason=complete outcome=completed complete=true'

status=$(request "$temp_dir/response-engine-limit" --header 'Host: limit.local' \
    --dump-header "$temp_dir/response-engine-limit.headers" http://127.0.0.1:10001/response-deny)
check_status 500 "$status" 'engine response-body Reject status remains distinct from host 502'
if grep --ignore-case --quiet --extended-regexp 'x-upstream-secret|set-cookie: upstream-secret|secret upstream response' \
    "$temp_dir/response-engine-limit.headers" "$temp_dir/response-engine-limit"; then
    fail 'engine response-body limit denial leaked upstream data'
fi

before=$(backend_count /phase1-deny)
status=$(request "$temp_dir/phase1" http://127.0.0.1:10001/phase1-deny)
check_status 451 "$status" 'phase-1 rule denial'
[[ $(backend_count /phase1-deny) == "$before" ]] || fail 'phase-1 denied request reached the backend'

status=$(request "$temp_dir/response-header-deny-off" --header 'Host: off.local' \
    --dump-header "$temp_dir/response-header-deny-off.headers" http://127.0.0.1:10001/large-header-deny)
check_status 452 "$status" 'phase-4 response-header rule with SecResponseBodyAccess Off'
if grep --ignore-case --quiet --extended-regexp 'x-upstream-secret|LEAK-MARKER|X-Large-Probe' \
    "$temp_dir/response-header-deny-off.headers" "$temp_dir/response-header-deny-off"; then
    fail 'body-access-off response denial leaked upstream data'
fi

status=$(request "$temp_dir/response-mime-excluded" --dump-header "$temp_dir/response-mime-excluded.headers" \
    http://127.0.0.1:10001/large-header-deny)
check_status 452 "$status" 'phase-4 response-header rule for a MIME-excluded body'
if grep --ignore-case --quiet --extended-regexp 'x-upstream-secret|LEAK-MARKER|X-Large-Probe' \
    "$temp_dir/response-mime-excluded.headers" "$temp_dir/response-mime-excluded"; then
    fail 'MIME-excluded response denial leaked upstream data'
fi

status=$(request "$temp_dir/response-redirect" --dump-header "$temp_dir/response-redirect.headers" \
    http://127.0.0.1:10001/response-redirect)
check_status 307 "$status" 'phase-4 response redirect status'
grep --ignore-case --quiet --fixed-strings 'location: https://example.test/response-blocked' "$temp_dir/response-redirect.headers" \
    || fail 'response redirect location was missing'
[[ ! -s $temp_dir/response-redirect ]] || fail 'response redirect returned a body'

for authority_status in 'head.local:204' 'not-modified.local:304'; do
    authority=${authority_status%:*}
    expected=${authority_status##*:}
    python3 - "$authority" "$expected" <<'PY'
import http.client
import sys

authority, expected = sys.argv[1:]
connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=10)
try:
    connection.request("HEAD" if expected == "204" else "GET", "/response-deny", headers={"Host": authority})
    response = connection.getresponse()
    body = response.read()
    if response.status != int(expected) or body:
        raise RuntimeError(f"response replacement mismatch: status={response.status}, body={body!r}")
    headers = {name.lower(): value for name, value in response.getheaders()}
    if "x-upstream-secret" in headers or "set-cookie" in headers:
        raise RuntimeError(f"upstream headers leaked: {headers!r}")
finally:
    connection.close()
PY
done

python3 - <<'PY'
import socket

connection = socket.create_connection(("127.0.0.1", 10001), timeout=10)
connection.sendall(b"GET /response-trailers HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
chunks = []
while True:
    data = connection.recv(4096)
    if not data:
        break
    chunks.append(data)
connection.close()
response = b"".join(chunks)
if b"HTTP/1.1 200" not in response or b"trailer response" not in response or b"x-backend-trailer: passed" not in response.lower():
    raise RuntimeError(f"allowed response body/trailer changed: {response!r}")
PY

status=$(request "$temp_dir/response-trailer-deny" --dump-header "$temp_dir/response-trailer-deny.headers" \
    http://127.0.0.1:10001/response-trailers-deny)
check_status 451 "$status" 'phase-4 response denial from the response-trailers callback'
[[ $(cat "$temp_dir/response-trailer-deny") == 'Upstream response blocked' ]] \
    || fail 'response-trailer denial returned an unexpected body'
if grep --ignore-case --quiet --extended-regexp 'x-upstream-secret|x-backend-trailer|upstream-trailer-marker|secret trailer response' \
    "$temp_dir/response-trailer-deny.headers" "$temp_dir/response-trailer-deny"; then
    fail 'response-trailer denial leaked upstream content, header, or trailer'
fi

status=$(request "$temp_dir/response-too-large" --dump-header "$temp_dir/response-too-large.headers" \
    http://127.0.0.1:10001/large-response)
check_status 502 "$status" 'native 1 MiB response host ceiling'
grep --ignore-case --quiet --fixed-strings 'x-upstream-secret' "$temp_dir/response-too-large.headers" \
    && fail 'response size failure leaked an upstream header'
grep --quiet --fixed-strings 'z' "$temp_dir/response-too-large" \
    && fail 'response size failure leaked the upstream body'

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
require_access_log /phase1-deny 'event=- rule_id=- phase=- action=- status=- reason=- outcome=- complete=-'
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

"${compose[@]}" down --volumes >/dev/null
crs_policy='{"directives_map":{"crs":["SecRuleEngine On","SecAuditEngine RelevantOnly","SecAuditLogFormat JSON","SecRequestBodyAccess On","SecRequestBodyLimit 13107200","SecResponseBodyAccess On","SecResponseBodyLimit 1048576","SecResponseBodyMimeType text/plain text/html application/json","Include crs/crs-setup.conf","Include crs/rules/*.conf","SecRule REQUEST_HEADERS:Content-Type \"@rx ^application/json(?:\\s*;.*)?$\" \"id:999100,phase:1,pass,nolog,t:none,t:lowercase,ctl:requestBodyProcessor=JSON\""]},"per_authority_directives":{"crs.local":"crs"},"enable_filter_state_logs":true}'
write_bootstrap "$crs_policy" "$temp_dir/crs-policy.yaml"
cargo build --locked --release -p envoy-coraza-dynamic --features embed-crs --target-dir "$crs_target_dir"
cp "$crs_target_dir/release/libenvoy_coraza_dynamic.so" "$crs_module_file"
export ENVOY_CORAZA_DYNAMIC_MODULE="target/$crs_module_name"
"${compose[@]}" build envoy
start_envoy "$temp_dir/crs-policy.yaml"

before=$(backend_count /crs-sqli)
status=$(request "$temp_dir/crs-sqli" --header 'Host: crs.local' \
    'http://127.0.0.1:10001/crs-sqli?q=1%27%20OR%201%3D1')
check_status 403 "$status" 'embedded CRS SQL injection denial'
[[ $(backend_count /crs-sqli) == "$before" ]] || fail 'CRS SQL injection reached the backend'
envoy_logs | grep --quiet --fixed-strings '949110' || fail 'CRS SQL injection was not denied by rule 949110'

status=$(request "$temp_dir/crs-benign" --header 'Host: crs.local' http://127.0.0.1:10001/healthy)
check_status 200 "$status" 'embedded CRS benign request'

cargo build --locked --release -p envoy-coraza-dynamic --features panic-probe --target-dir "$panic_target_dir"
cp "$panic_target_dir/release/libenvoy_coraza_dynamic.so" "$panic_module_file"
export ENVOY_CORAZA_DYNAMIC_MODULE="target/$panic_module_name"
"${compose[@]}" build envoy
panic_policy='{"directives_map":{"p":["SecRuleEngine On","SecRequestBodyAccess On","SecRequestBodyLimit 16777216","SecAction \"id:1,phase:1,ctl:requestBodyProcessor=RAW,pass\"","SecResponseBodyAccess On","SecResponseBodyLimit 1048576","SecResponseBodyMimeType text/plain"]},"default_directives":"p"}'
write_bootstrap "$panic_policy" "$temp_dir/panic.yaml"
start_envoy "$temp_dir/panic.yaml"
before=$(backend_count /panic)
status=$(request "$temp_dir/panic" --header 'x-coraza-probe: panic' http://127.0.0.1:10001/panic)
check_status 500 "$status" 'feature-gated request panic fail-closed response'
[[ $(backend_count /panic) == "$before" ]] || fail 'panicking request reached the backend'

response_panic_status=$(curl --silent --output "$temp_dir/response-panic" --write-out '%{http_code}' \
    --max-time 10 --header 'x-coraza-probe: panic-response' --request POST \
    --data-binary 'retained request body' http://127.0.0.1:10001/response-deny || true)
[[ $response_panic_status == 000 ]] || fail "response panic returned HTTP $response_panic_status instead of resetting the stream"
envoy_logs | grep --quiet --fixed-strings 'caught panic: feature-gated response panic probe' \
    || fail 'response callback panic was not caught and reset'

status=$(request "$temp_dir/panic-followup" http://127.0.0.1:10001/healthy)
check_status 200 "$status" 'healthy request after request and response panics'

printf 'Envoy 1.40 native request-enforcement checks passed\n'
