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
compose=(docker compose -f "$script_dir/compose.yaml" -p envoy-coraza-dynamic-stage-a)
target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
if [[ $target_dir != /* ]]; then
    target_dir="$repo_root/$target_dir"
fi
temp_dir=$(mktemp -d)
cleanup() {
    local exit_code=$?
    trap - EXIT
    if (( exit_code != 0 )); then
        "${compose[@]}" logs --no-color envoy backend 2>&1 | tail --lines=80 >&2 || true
    fi
    "${compose[@]}" down --rmi local --volumes >/dev/null 2>&1 || true
    rm -f "$target_dir/envoy-coraza-dynamic-probe.so"
    rm -rf "$temp_dir"
    exit "$exit_code"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'python3 is required for controlled HTTP/1.1 frames'
command -v curl >/dev/null 2>&1 || fail 'curl is required'

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

require_log() {
    local expected=$1
    for _attempt in {1..30}; do
        if envoy_logs | grep --quiet --fixed-strings "$expected"; then
            return
        fi
        sleep 0.1
    done
    envoy_logs >"$temp_dir/envoy.log"
    fail "Envoy logs did not contain: $expected"
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

write_config_variant() {
    local variant=$1
    local output=$2
    python3 - "$script_dir/envoy.yaml" "$variant" "$output" <<'PY'
import pathlib
import sys

source, variant, output = sys.argv[1:]
text = pathlib.Path(source).read_text()
if variant == "unknown-name":
    text = text.replace("filter_name: coraza\n", "filter_name: unknown\n", 1)
elif variant == "malformed-json":
    text = text.replace("value: '{\"probe\":\"stage-a\"}'", "value: 'not-json'", 1)
elif variant == "malformed-utf8":
    text = text.replace(
        'type.googleapis.com/google.protobuf.StringValue',
        'type.googleapis.com/google.protobuf.BytesValue',
        1,
    )
    text = text.replace("value: '{\"probe\":\"stage-a\"}'", 'value: "/w=="', 1)
else:
    raise ValueError(f"unknown config variant: {variant}")
pathlib.Path(output).write_text(text)
PY
}

expect_startup_rejection() {
    local label=$1
    local config=$2
    local module_dir=${3:-}
    local arguments=(run --rm --no-deps --service-ports)
    if [[ -n $module_dir ]]; then
        arguments+=(--volume "$module_dir:/opt/envoy/modules:ro")
    fi
    arguments+=(envoy)
    if env ENVOY_CORAZA_DYNAMIC_CONFIG="$config" "${compose[@]}" "${arguments[@]}" \
        >"$temp_dir/$label.log" 2>&1; then
        fail "$label unexpectedly started Envoy"
    fi
    if curl --silent --show-error --max-time 1 http://127.0.0.1:10001/should-not-be-unfiltered \
        >"$temp_dir/$label.response" 2>/dev/null; then
        fail "$label served a request after rejected startup"
    fi
    printf 'negative-control %s: startup rejected; listener did not serve traffic\n' "$label"
}

cargo build --locked --release -p envoy-coraza-dynamic
cargo build --locked --release -p envoy-coraza-dynamic --features panic-probe \
    --target-dir "$target_dir/panic-probe"
cp "$target_dir/release/libenvoy_coraza_dynamic.so" \
    "$target_dir/envoy-coraza-dynamic-probe.so"
export ENVOY_CORAZA_DYNAMIC_MODULE=target/envoy-coraza-dynamic-probe.so

"${compose[@]}" build backend envoy
"${compose[@]}" up --detach
wait_ready
status=$(request "$temp_dir/default-panic-marker" --header 'x-coraza-probe: panic' \
    http://127.0.0.1:10001/echo)
check_status 200 "$status" 'default build with the panic probe header'
if envoy_logs | grep --quiet --fixed-strings 'caught panic'; then
    fail 'default build executed a request-triggered panic'
fi
"${compose[@]}" down --volumes >/dev/null

cp "$target_dir/panic-probe/release/libenvoy_coraza_dynamic.so" \
    "$target_dir/envoy-coraza-dynamic-probe.so"
"${compose[@]}" build envoy

empty_module_dir="$temp_dir/missing-modules"
mkdir -p "$empty_module_dir"
expect_startup_rejection missing-library "$script_dir/envoy.yaml" "$empty_module_dir"

corrupt_module_dir="$temp_dir/corrupt-modules"
mkdir -p "$corrupt_module_dir"
printf 'not an ELF shared object\n' >"$corrupt_module_dir/libenvoy_coraza_dynamic.so"
expect_startup_rejection corrupt-library "$script_dir/envoy.yaml" "$corrupt_module_dir"

wrong_arch_module_dir="$temp_dir/wrong-architecture-modules"
mkdir -p "$wrong_arch_module_dir"
cp "$target_dir/envoy-coraza-dynamic-probe.so" \
    "$wrong_arch_module_dir/libenvoy_coraza_dynamic.so"
python3 - "$wrong_arch_module_dir/libenvoy_coraza_dynamic.so" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
with path.open("r+b") as library:
    library.seek(18)
    library.write((183).to_bytes(2, "little"))  # ELF EM_AARCH64 in the x86-64 artifact.
PY
expect_startup_rejection wrong-architecture "$script_dir/envoy.yaml" "$wrong_arch_module_dir"

for variant in unknown-name malformed-json malformed-utf8; do
    write_config_variant "$variant" "$temp_dir/$variant.yaml"
    expect_startup_rejection "$variant" "$temp_dir/$variant.yaml"
done

"${compose[@]}" up --detach
wait_ready

status=$(request "$temp_dir/hold" --header 'x-coraza-probe: hold' \
    http://127.0.0.1:10001/hold)
check_status 200 "$status" 'held request headers and scheduled continuation'
require_log 'callback=request_headers mode=Hold'
require_log 'callback=scheduled action=continue_decoding'

python3 - "$temp_dir/body" "$temp_dir/body.headers" <<'PY'
import http.client
import sys
import time

body_path, headers_path = sys.argv[1:]
connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=10)
try:
    connection.putrequest("POST", "/echo", skip_accept_encoding=True)
    connection.putheader("x-coraza-probe", "body")
    connection.putheader("Transfer-Encoding", "chunked")
    connection.putheader("Connection", "close")
    connection.endheaders()
    chunks = [b"frame-one-", b"frame-two-", b"frame-three"]
    for chunk in chunks:
        connection.send(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
        time.sleep(0.1)
    connection.send(b"0\r\n\r\n")
    response = connection.getresponse()
    with open(headers_path, "wb") as output:
        output.write(f"HTTP/1.1 {response.status}\r\n".encode())
        for name, value in response.getheaders():
            output.write(f"{name}: {value}\r\n".encode("iso-8859-1"))
    with open(body_path, "wb") as output:
        output.write(response.read())
    if response.status != 200:
        raise RuntimeError(f"body probe returned {response.status}")
finally:
    connection.close()
PY
if ! cmp --silent <(printf 'frame-one-frame-two-frame-three') "$temp_dir/body"; then
    python3 - "$temp_dir/body" <<'PY'
import pathlib
import sys
print(f"unexpected backend body: {pathlib.Path(sys.argv[1]).read_bytes()!r}", file=sys.stderr)
PY
    fail 'buffered multi-frame request body changed'
fi
require_log 'callback=request_body mode=Body'
require_log 'callback=request_body mode=Body eos=true'

python3 - "$temp_dir/trailer-body" "$temp_dir/trailer.headers" <<'PY'
import http.client
import sys
import time

body_path, headers_path = sys.argv[1:]
connection = http.client.HTTPConnection("127.0.0.1", 10001, timeout=10)
try:
    connection.putrequest("POST", "/echo", skip_accept_encoding=True)
    connection.putheader("x-coraza-probe", "trailer")
    connection.putheader("Transfer-Encoding", "chunked")
    connection.putheader("Trailer", "x-client-trailer")
    connection.putheader("Connection", "close")
    connection.endheaders()
    for chunk in (b"trailer-", b"terminated"):
        connection.send(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
        time.sleep(0.1)
    connection.send(b"0\r\nx-client-trailer: present\r\n\r\n")
    response = connection.getresponse()
    with open(headers_path, "wb") as output:
        output.write(f"HTTP/1.1 {response.status}\r\n".encode())
        for name, value in response.getheaders():
            output.write(f"{name}: {value}\r\n".encode("iso-8859-1"))
    with open(body_path, "wb") as output:
        output.write(response.read())
    if response.status != 200:
        raise RuntimeError(f"trailer probe returned {response.status}")
finally:
    connection.close()
PY
cmp --silent <(printf 'trailer-terminated') "$temp_dir/trailer-body" \
    || fail 'trailer-terminated request body changed'
grep --ignore-case --quiet '^x-client-trailer-seen: present' "$temp_dir/trailer.headers" \
    || fail 'request trailer did not reach the backend'
require_log 'callback=request_trailers mode=Trailer'

before=$(backend_count /denied)
status=$(request "$temp_dir/denied" --header 'x-coraza-probe: deny' \
    http://127.0.0.1:10001/denied)
check_status 403 "$status" 'held-header local reply denial'
[[ $(backend_count /denied) == "$before" ]] || fail 'denied request reached the backend'
grep --quiet --fixed-strings 'probe denied' "$temp_dir/denied" || fail 'denial body was missing'
require_log 'callback=local_reply status=403 nested_request_headers=true'
[[ $(envoy_logs | grep -c --fixed-strings 'callback=local_reply status=403' || true) == 1 ]] \
    || fail 'request denial was processed more than once'

status=$(request "$temp_dir/replacement" --dump-header "$temp_dir/replacement.headers" \
    --header 'x-coraza-probe: replace' http://127.0.0.1:10001/response-deny)
check_status 200 "$status" 'encode-path response replacement'
[[ $(cat "$temp_dir/replacement") == 'replacement response' ]] \
    || fail 'replacement response body was not delivered'
if grep --ignore-case --quiet -E '^(x-upstream-secret|set-cookie):' "$temp_dir/replacement.headers"; then
    fail 'replacement leaked upstream response headers'
fi
if grep --quiet --fixed-strings 'secret' "$temp_dir/replacement"; then
    fail 'replacement leaked upstream response body bytes'
fi
require_log 'callback=response_headers action=replace'

python3 - "$temp_dir/limit" "$temp_dir/limit.meta" <<'PY'
import select
import socket
import struct
import sys

output_path, metadata_path = sys.argv[1:]
body_size = 2 * 1024 * 1024
body = b"L" * body_size
connection = socket.create_connection(("127.0.0.1", 10001), timeout=5)
connection.settimeout(0.5)
try:
    request = (
        "POST /limit HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "x-coraza-probe: limit\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    connection.sendall(request)
    sent = 0
    while sent < body_size:
        chunk = body[sent : sent + 16384]
        try:
            connection.sendall(chunk)
            sent += len(chunk)
        except socket.timeout:
            break
    readable, _, _ = select.select([connection], [], [], 0.5)
    try:
        data = connection.recv(4096) if readable else b""
    except ConnectionResetError:
        data = b"reset"
    with open(output_path, "wb") as output:
        output.write(data)
    with open(metadata_path, "w", encoding="ascii") as output:
        output.write(f"{sent} {body_size}\n")
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
finally:
    connection.close()
PY
grep --text --quiet --fixed-strings 'HTTP/1.1 413' "$temp_dir/limit" \
    || fail 'held-header buffer-limit overflow did not produce HTTP 413'
read -r sent_body total_body <"$temp_dir/limit.meta"
(( sent_body > 0 && sent_body <= total_body )) \
    || fail "buffer-limit probe sent an invalid body length ($sent_body of $total_body)"
printf 'buffer-limit overflow: Envoy returned 413 after the client sent %s of %s bytes\n' \
    "$sent_body" "$total_body"
[[ $(backend_count /limit) == 0 ]] || fail 'held-header over-limit request reached the backend'
require_log 'requested=32 current=32 headers_held=true'
require_log 'callback=local_reply status=413'

status=$(request "$temp_dir/panic" --header 'x-coraza-probe: panic' \
    http://127.0.0.1:10001/panic)
check_status 500 "$status" 'feature-gated request panic fail-closed response'
[[ $(backend_count /panic) == 0 ]] || fail 'panicking request reached the backend'
status=$(request "$temp_dir/panic-followup" http://127.0.0.1:10001/healthy)
check_status 200 "$status" 'healthy request after request panic'

response_panic_status=$(curl --silent --show-error --max-time 5 --output "$temp_dir/response-panic" \
    --write-out '%{http_code}' --header 'x-coraza-probe: panic-response' \
    http://127.0.0.1:10001/response-deny 2>/dev/null || true)
[[ $response_panic_status == 000 ]] \
    || fail "response panic returned HTTP $response_panic_status instead of resetting the stream"
status=$(request "$temp_dir/response-panic-followup" http://127.0.0.1:10001/healthy)
check_status 200 "$status" 'healthy request after response panic reset'

envoy_logs >"$temp_dir/envoy.log"
printf 'Observed probe log excerpt:\n'
grep --fixed-strings 'coraza-dynamic-probe' "$temp_dir/envoy.log" | tail --lines=30
printf 'Envoy 1.40 dynamic-module lifecycle checks passed\n'
