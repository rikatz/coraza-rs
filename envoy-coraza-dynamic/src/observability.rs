// Copyright Coraza Kubernetes Operator contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Bounded native Envoy filter-state and diagnostic publication.

use coraza::{
    audit_log::{AuditLog, MatchedRule},
    debug_log::{DebugEvent, DebugLevel, DebugLogger},
    transaction::{Interruption, Transaction},
    types::AuditLogFormat,
};
use envoy_coraza_common::observability::{
    bounded, category, sanitize_audit, HealthState, InterruptionPhase, MAX_AUDIT_LOG_BYTES, MAX_ERROR_LOG_BYTES,
};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilter;

/// Envoy-backed logger; it never opens a file or blocks on an external sink.
#[derive(Debug, Default)]
pub(crate) struct EnvoyDebugLogger;

impl DebugLogger for EnvoyDebugLogger {
    fn enabled(&self, _level: DebugLevel) -> bool {
        true
    }

    fn log(&self, level: DebugLevel, event: &DebugEvent<'_>) {
        let mut message = format!("[{level:?}] {} {:?}", event.message, event.fields);
        message.push('\n');
        let message = sanitize_audit(&message, MAX_ERROR_LOG_BYTES, false);
        match level {
            DebugLevel::Error => envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error!("{message}"),
            DebugLevel::Warn => envoy_proxy_dynamic_modules_rust_sdk::envoy_log_warn!("{message}"),
            DebugLevel::Info => envoy_proxy_dynamic_modules_rust_sdk::envoy_log_info!("{message}"),
            DebugLevel::Debug => envoy_proxy_dynamic_modules_rust_sdk::envoy_log_debug!("{message}"),
            DebugLevel::Trace => envoy_proxy_dynamic_modules_rust_sdk::envoy_log_trace!("{message}"),
        }
    }
}

/// Returns the legacy interruption field set, using the Wasm adapter's values.
pub(crate) fn interruption_fields(
    transaction: &Transaction,
    interruption: &Interruption,
    phase: InterruptionPhase,
) -> Vec<(String, String)> {
    let matched = transaction
        .matched_rules()
        .iter()
        .find(|matched| matched.rule_id() == interruption.rule_id);
    let mut fields = vec![
        ("event".to_owned(), "coraza_waf_blocked_request".to_owned()),
        ("rule_id".to_owned(), interruption.rule_id.to_string()),
        ("phase".to_owned(), phase.state().to_owned()),
        ("action".to_owned(), interruption.action.clone()),
        (
            "status".to_owned(),
            if interruption.status == 0 {
                403
            } else {
                interruption.status
            }
            .to_string(),
        ),
    ];
    if let Some(matched) = matched {
        if let Some(severity) = matched.severity() {
            fields.push(("severity".to_owned(), severity.as_str().to_owned()));
        }
        fields.push(("category".to_owned(), category(matched.tags())));
        if !matched.client_ip.is_empty() {
            fields.push(("client_ip".to_owned(), matched.client_ip.clone()));
        }
    }
    fields
}

/// Publishes interruption fields before a local reply or response replacement.
pub(crate) fn publish_interruption<EHF: EnvoyHttpFilter>(envoy: &mut EHF, fields: &[(String, String)]) -> bool {
    let mut failed = false;
    for (field, value) in fields {
        let key = format!("wasm.io.coraza.waf.{field}");
        failed |= !envoy.set_filter_state_bytes(key.as_bytes(), value.as_bytes());
    }
    failed
}

/// Publishes the additive Wasm-compatible health field set.
pub(crate) fn publish_health<EHF: EnvoyHttpFilter>(envoy: &mut EHF, enabled: bool, state: HealthState<'_>) -> bool {
    if !enabled {
        return state.telemetry_publish_failed;
    }
    let fields = [
        ("inspection_complete", state.inspection_complete.to_string()),
        ("inspection_reason", state.inspection_reason.to_owned()),
        ("policy_generation", state.generation.to_string()),
        ("request_body_truncated", state.request_body_truncated.to_string()),
        ("response_body_truncated", state.response_body_truncated.to_string()),
        ("terminal_outcome", state.terminal_outcome.to_owned()),
        ("telemetry_publish_failed", state.telemetry_publish_failed.to_string()),
    ];
    let mut failed = state.telemetry_publish_failed;
    for (field, value) in fields {
        let key = format!("wasm.io.coraza.waf.v1.{field}");
        failed |= !envoy.set_filter_state_bytes(key.as_bytes(), value.as_bytes());
    }
    failed
}

/// Emits one bounded rule error through Envoy's logger.
pub(crate) fn error_log(matched: &MatchedRule) {
    let message = bounded(&matched.error_log(), MAX_ERROR_LOG_BYTES);
    envoy_proxy_dynamic_modules_rust_sdk::envoy_log_warn!("{message}");
}

/// Emits one selected, bounded and sanitized audit entry through Envoy's logger.
pub(crate) fn audit_log(entry: &AuditLog, format: AuditLogFormat) {
    let (formatted, truncated) = entry.format_bounded(format, MAX_AUDIT_LOG_BYTES);
    if !formatted.is_empty() {
        let message = sanitize_audit(&formatted, MAX_AUDIT_LOG_BYTES, truncated);
        envoy_proxy_dynamic_modules_rust_sdk::envoy_log_critical!("{message}");
    }
}

/// Formats debug event fields using the engine's typed representation.
#[cfg(test)]
fn debug_message(level: DebugLevel, event: &DebugEvent<'_>) -> String {
    let mut message = format!("[{level:?}] {} {:?}", event.message, event.fields);
    message.push('\n');
    sanitize_audit(&message, MAX_ERROR_LOG_BYTES, false)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Observability tests use fixed valid transactions.")]
mod tests {
    use std::sync::Arc;

    use coraza::{
        debug_log::{DebugEvent, DebugField, DebugLevel},
        transaction::Interruption,
    };
    use envoy_coraza_common::{
        config::Config,
        observability::{Diagnostics, InterruptionPhase},
    };
    use envoy_proxy_dynamic_modules_rust_sdk::MockEnvoyHttpFilter;

    use super::{debug_message, interruption_fields};

    #[test]
    fn interruption_format_matches_legacy_phase_and_status_contract() {
        let generation = envoy_coraza_common::policy::Generation::compile(
            Config::parse(br#"{"directives_map":{"p":["SecRuleEngine On"]},"default_directives":"p"}"#).unwrap(),
            Arc::new(Diagnostics::default()),
            |_| {},
            |_, _| {},
        )
        .unwrap();
        let transaction = generation.select("example.test").unwrap().waf.new_transaction();
        let interruption = Interruption {
            rule_id: 42,
            action: "deny".to_owned(),
            status: 0,
            data: String::new(),
        };
        let fields = interruption_fields(&transaction, &interruption, InterruptionPhase::ResponseBody);
        assert_eq!(
            fields.first().map(|(key, value)| (key.as_str(), value.as_str())),
            Some(("event", "coraza_waf_blocked_request"))
        );
        assert_eq!(
            fields.get(2).map(|(key, value)| (key.as_str(), value.as_str())),
            Some(("phase", "http_response_body"))
        );
        assert_eq!(
            fields.get(4).map(|(key, value)| (key.as_str(), value.as_str())),
            Some(("status", "403"))
        );
    }

    #[test]
    fn debug_events_use_bounded_control_escaped_text() {
        let fields = [DebugField::Text("secret\u{0007}")];
        let event = DebugEvent {
            message: "inspection",
            fields: &fields,
        };
        let message = debug_message(DebugLevel::Debug, &event);
        assert!(message.len() <= super::MAX_ERROR_LOG_BYTES);
        assert!(message.contains("\\u{7}"));
    }

    #[test]
    fn health_state_publication_failure_is_non_disruptive() {
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy
            .expect_set_filter_state_bytes()
            .returning(|key, _| key != b"wasm.io.coraza.waf.v1.inspection_reason");
        let failed = super::publish_health(
            &mut envoy,
            true,
            envoy_coraza_common::observability::HealthState {
                inspection_complete: true,
                inspection_reason: "complete",
                generation: 1,
                request_body_truncated: false,
                response_body_truncated: false,
                terminal_outcome: "completed",
                telemetry_publish_failed: false,
            },
        );
        assert!(failed);
    }

    #[test]
    fn disabled_health_logging_publishes_no_filter_state() {
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy.expect_set_filter_state_bytes().times(0);
        let failed = super::publish_health(
            &mut envoy,
            false,
            envoy_coraza_common::observability::HealthState {
                inspection_complete: false,
                inspection_reason: "engine_off",
                generation: 1,
                request_body_truncated: false,
                response_body_truncated: false,
                terminal_outcome: "uninspected",
                telemetry_publish_failed: false,
            },
        );
        assert!(!failed);
    }
}
