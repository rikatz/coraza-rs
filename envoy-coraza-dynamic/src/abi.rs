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

//! Native dynamic-module ABI and HTTP filter factory.

use envoy_proxy_dynamic_modules_rust_sdk::{
    declare_init_functions, EnvoyHttpFilter, EnvoyHttpFilterConfig, HttpFilterConfig,
};

use crate::probe::{validate_config, ProbeConfig};

declare_init_functions!(init, new_http_filter_config_fn);

/// Reports successful process initialization; the probe has no process-global state.
fn init() -> bool {
    true
}

/// Accepts only the `coraza` probe name and a UTF-8 JSON object.
fn new_http_filter_config_fn<EC: EnvoyHttpFilterConfig, EHF: EnvoyHttpFilter>(
    _envoy_filter_config: &mut EC,
    filter_name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn HttpFilterConfig<EHF>>> {
    if !valid_factory_input(filter_name, config_bytes) {
        return None;
    }
    Some(Box::new(ProbeConfig))
}

/// Checks the narrow Stage A filter-name and configuration contract.
fn valid_factory_input(filter_name: &str, config_bytes: &[u8]) -> bool {
    // Stage C will replace this probe-only JSON-object check with the shared policy parser.
    filter_name == "coraza" && validate_config(config_bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use envoy_proxy_dynamic_modules_rust_sdk::{HttpFilterConfig as _, MockEnvoyHttpFilter};

    use super::valid_factory_input;
    use crate::probe::ProbeConfig;

    #[test]
    fn factory_input_rejects_unknown_names_and_invalid_bytes() {
        assert!(!valid_factory_input("unknown", b"{}"));
        assert!(!valid_factory_input("coraza", b"\xff"));
        assert!(!valid_factory_input("coraza", b"[]"));
        assert!(valid_factory_input("coraza", b"{}"));
    }

    #[test]
    fn filter_config_creates_against_the_sdk_mock_host() {
        let config = ProbeConfig;
        let mut envoy = MockEnvoyHttpFilter::default();
        let _filter = config.new_http_filter(&mut envoy);
    }
}
