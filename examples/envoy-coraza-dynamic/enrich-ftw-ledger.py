#!/usr/bin/env python3
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

"""Attach per-test evidence and conservative causes to the Stage F FTW ledger."""

import argparse
import gzip
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FTW = ROOT / "docs/performance/envoy-coraza-dynamic-stage-f/ftw"


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def outcome(manifest: dict, test_id: str) -> str:
    results = manifest.get("results", {})
    if test_id in results.get("failed", []):
        return "fail"
    if test_id in results.get("success", []):
        return "pass"
    return "not-run"


def observed_statuses(disposition: dict | None) -> list[int]:
    if disposition is None:
        return []
    return disposition.get("observed_statuses", [])


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return str(resolved)


def marker_bracketed_requests(log_path: Path, test_id: str) -> list[dict]:
    if not log_path.is_file() and log_path.with_suffix(log_path.suffix + ".gz").is_file():
        log_path = log_path.with_suffix(log_path.suffix + ".gz")
    if not log_path.is_file():
        return []
    lines = []
    if log_path.suffix == ".gz":
        with gzip.open(log_path, "rt", errors="replace") as source:
            log_lines = source.read().splitlines()
    else:
        log_lines = log_path.read_text(errors="replace").splitlines()
    for index, line in enumerate(log_lines):
        values = dict(field.split("=", 1) for field in line.split() if "=" in field)
        try:
            status = int(values["status"])
        except (KeyError, ValueError):
            continue
        if "path" in values:
            lines.append((index, status, values["path"], values.get("marker", "")))

    starts = {}
    requests = []
    marker_pattern = re.compile(r"^(\d+-\d+)-([0-9a-fA-F-]+)-([se])$")
    for line_index, status, path, marker in lines:
        match = marker_pattern.fullmatch(marker)
        if not match or match.group(1) != test_id:
            continue
        base, suffix = marker[:-2], match.group(3)
        if suffix == "s":
            starts[base] = line_index
            continue
        start = starts.pop(base, None)
        if start is None:
            continue
        requests.extend(
            {"status": request_status, "path": request_path}
            for request_index, request_status, request_path, request_marker in lines
            if start < request_index < line_index and request_marker in ("", "-")
        )
    return requests


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-current", type=Path, help="fresh ftw-runner manifest with access-log observations")
    args = parser.parse_args()

    ledger_path = FTW / "divergence-ledger.json"
    ledger = load(ledger_path)
    native = load(FTW / "native-full.json")
    wasm = load(FTW / "wasm-native-failures-except-950020-2.json")
    engine = load(FTW / "engine-standalone.json")
    current_path = args.native_current.resolve() if args.native_current else None
    current = load(current_path) if current_path else {}
    current_dispositions = current.get("results", {}).get("dispositions", {})
    current_metadata_path = current_path.parent / "run-metadata.json" if current_path else None
    current_metadata = load(current_metadata_path) if current_metadata_path and current_metadata_path.is_file() else {}

    dispositions = {}
    current_rules = current.get("results", {}).get("triggered_rules", {})
    for test_id in ledger["failure_sets"]["common_not_in_engine_baseline"]:
        current_case = current_dispositions.get(test_id)
        engine_outcome = outcome(engine, test_id)
        historical_native_outcome = outcome(native, test_id)
        native_outcome = outcome(current, test_id) if current else historical_native_outcome
        wasm_outcome = outcome(wasm, test_id)
        current_statuses = observed_statuses(current_case)
        current_paths = current_case.get("observed_paths", []) if current_case else []
        if engine_outcome == "fail":
            classification = "engine-wide"
            attribution = "decided"
            candidate = "engine-wide"
        elif native_outcome == "fail" and wasm_outcome == "fail":
            classification = "connector-or-harness"
            attribution = "undecided"
            candidate = (
                "Envoy/harness parser before routing (candidate)"
                if current_statuses
                and len(current_statuses) == len(current_paths)
                and all(status == 400 and path == "-" for status, path in zip(current_statuses, current_paths))
                else "shared-connector-or-harness"
            )
        else:
            classification = "not-supported-by-current-set-arithmetic"
            attribution = "undecided"
            candidate = "undecided"

        expected = current_case.get("expected_statuses") if current_case else None
        statuses = current_statuses
        expected_first = expected[0] if expected else None
        dispositions[test_id] = {
            "classification": classification,
            "attribution": attribution,
            "candidate_class": candidate,
            "native_outcome": native_outcome,
            "historical_native_outcome": historical_native_outcome,
            "native_current_outcome": outcome(current, test_id) if current else "not-rerun",
            "wasm_outcome": wasm_outcome,
            "engine_outcome": engine_outcome,
            "expected_status": expected_first,
            "expected_status_asserted": expected_first is not None,
            "expected_statuses": expected,
            "observed_status": statuses[0] if len(statuses) == 1 else None,
            "observed_statuses": statuses,
            "observed_paths": current_case.get("observed_paths", []) if current_case else [],
            "native_triggered_rules": current_rules.get(
                test_id, native.get("results", {}).get("triggered_rules", {}).get(test_id, [])
            ),
            "native_current_triggered_rules": current.get("results", {}).get("triggered_rules", {}).get(test_id, []),
            "wasm_triggered_rules": wasm.get("results", {}).get("triggered_rules", {}).get(test_id, []),
            "engine_triggered_rules": engine.get("results", {}).get("triggered_rules", {}).get(test_id, []),
            "evidence_gap": (
                "No per-test response status was retained in the historical manifests; rerun with "
                "test-ftw.sh to populate expected/observed status and marker-bracketed access-log paths."
                if not current_case
                else (
                    "No non-marker access-log request was found between this test's FTW markers; capture the "
                    "request/response at the filter boundary before attributing this failure."
                    if not statuses
                    else (
                        "The Envoy access log records status 400 with no parsed path; this points to a request-parser "
                        "or pre-routing harness rejection, but filter-visible bytes are needed to confirm it."
                        if candidate == "Envoy/harness parser before routing (candidate)"
                        else "Marker-bracketed status and path are recorded, but the filter-visible normalized request "
                        "and the reason a shared rule did not trigger are not; do not attribute this to connector or harness yet."
                    )
                )
            ),
            "evidence_needed_to_decide": (
                "Capture the bounded request as received at the filter boundary and its marker-bracketed Envoy "
                "status/log slice, then compare those bytes and triggered rules with the engine-standalone case."
            ),
        }

    ledger["shared_failure_classification"] = {
        "source": "native-full.json, wasm-native-failures-except-950020-2.json, engine-standalone.json",
        "native_current_manifest": display_path(current_path) if current_path else None,
        "native_current_access_log": (
            display_path(current_path.parent / "envoy-access.log.gz")
            if current_path and (current_path.parent / "envoy-access.log.gz").is_file()
            else None
        ),
        "native_outcome": "fail",
        "wasm_outcome": "fail",
        "engine_outcome": "pass",
        "classification": "connector-or-harness; exact attribution remains undecided",
        "attribution": "undecided",
        "engine_wide_failures_in_this_set": 0,
        "candidate_class_counts": dict(Counter(item["candidate_class"] for item in dispositions.values())),
        "test_dispositions": dispositions,
    }
    if current:
        recheck = ledger.setdefault("focused_rechecks", {}).setdefault("944110-18", {})
        recheck["deterministic_native_full_rerun"] = {
            "outcome": outcome(current, "944110-18"),
            "triggered_rules": current.get("results", {}).get("triggered_rules", {}).get("944110-18", []),
            "marker_wait": current_metadata.get("marker_wait"),
            "marker_max_retries": current_metadata.get("marker_max_retries"),
            "observed_requests": marker_bracketed_requests(
                args.native_current.parent / "envoy-access.log", "944110-18"
            ),
        }
    ledger_path.write_text(json.dumps(ledger, indent=2) + "\n")


if __name__ == "__main__":
    main()
