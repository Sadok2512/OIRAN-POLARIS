//! 2.7.17: derive the web frontend version from `apps/web/package.json` at
//! build time so the API binary cannot drift from the frontend (ANR2 refused
//! 2.7.16 because API_VERSION / PLATFORM_VERSION were hardcoded in the
//! sources; this build script closes the mirror hole on the frontend side).

use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let web_package_json = manifest_dir
        .parent()
        .expect("apps/")
        .parent()
        .expect("OIRAN/")
        .join("apps/web/package.json");
    println!("cargo:rerun-if-changed={}", web_package_json.display());
    let text = fs::read_to_string(&web_package_json).unwrap_or_else(|error| {
        panic!(
            "apps/api/build.rs: failed to read {}: {error}",
            web_package_json.display()
        )
    });
    // Minimal scan: `"version":"<value>"` in the top-level object. Avoids
    // pulling serde as a build dependency.
    let needle = "\"version\"";
    let start = text
        .find(needle)
        .unwrap_or_else(|| panic!("apps/web/package.json: no \"version\" key"));
    let after = &text[start + needle.len()..];
    let colon = after.find(':').expect("apps/web/package.json: \"version\" needs :");
    let after = &after[colon + 1..];
    let open = after.find('"').expect("apps/web/package.json: \"version\" value open");
    let after = &after[open + 1..];
    let close = after.find('"').expect("apps/web/package.json: \"version\" value close");
    let version = &after[..close];
    assert!(
        !version.is_empty() && version.chars().all(|c| c.is_ascii() && c != '\n'),
        "apps/web/package.json: version must be a non-empty ASCII string"
    );
    println!("cargo:rustc-env=OIRAN_WEB_FRONTEND_VERSION={version}");
}
