/*
Copyright Coraza Kubernetes Operator contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! `cargo xtask lint-license` — enforce the Apache-2.0 copyright header on
//! every tracked `.rs` file.

use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The copyright header every `.rs` file must start with.
const LICENSE_HEADER: &str = r#"/*
Copyright Coraza Kubernetes Operator contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
"#;

/// Directory names skipped while walking the workspace for `.rs` files.
const SKIPPED_DIRS: [&str; 2] = ["target", ".git"];

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

/// CLI arguments for `cargo xtask lint-license`.
#[derive(Parser)]
pub(crate) struct Args;

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Check every `.rs` file under the workspace root for the required
/// copyright header, exiting with an error if any are missing it.
pub(crate) fn run(_args: Args) {
    let workspace_root = workspace_root();
    let files = find_rs_files(&workspace_root);

    let violations: Vec<PathBuf> = files
        .into_iter()
        .filter(|path| fs::read_to_string(path).is_ok_and(|content| !content.starts_with(LICENSE_HEADER)))
        .collect();

    if violations.is_empty() {
        println!("all .rs files carry the required copyright header");
    } else {
        eprintln!("missing or malformed copyright header:");
        for path in &violations {
            eprintln!("  {}", path.display());
        }
        std::process::exit(1);
    }
}

// -----------------------------------------------------------------------------
// Filesystem Walking
// -----------------------------------------------------------------------------

/// Recursively collect every `.rs` file under `root`, skipping
/// [`SKIPPED_DIRS`] and other hidden directories.
fn find_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    walk(root, &mut files);
    files
}

/// Walk `dir` recursively, appending `.rs` files found to `files`.
fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();

        if path.is_dir() {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if SKIPPED_DIRS.contains(&name) || name.starts_with('.') {
                continue;
            }
            walk(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

/// Locate the workspace root directory.
///
/// Uses `CARGO_MANIFEST_DIR` (set by cargo for the xtask crate) and
/// navigates one level up to reach the workspace root.
fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    Path::new(&manifest_dir)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_owned()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn file_with_header_passes() {
        let dir = tempfile_dir();
        fs::write(dir.join("good.rs"), format!("{LICENSE_HEADER}\nfn main() {{}}\n")).unwrap();
        assert!(
            find_rs_files(&dir)
                .iter()
                .all(|f| fs::read_to_string(f).unwrap().starts_with(LICENSE_HEADER))
        );
    }

    #[test]
    fn file_missing_header_fails() {
        let dir = tempfile_dir();
        fs::write(dir.join("bad.rs"), "fn main() {}\n").unwrap();
        let content = fs::read_to_string(dir.join("bad.rs")).unwrap();
        assert!(!content.starts_with(LICENSE_HEADER));
    }

    #[test]
    fn skipped_dirs_are_not_walked() {
        let dir = tempfile_dir();
        let target_dir = dir.join("target");
        fs::create_dir(&target_dir).unwrap();
        fs::write(target_dir.join("generated.rs"), "fn main() {}\n").unwrap();
        assert!(find_rs_files(&dir).is_empty());
    }

    fn tempfile_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("xtask-lint-license-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
