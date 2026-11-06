// BC3 audit #9 (comment 6696746387) — one test per contract drift closed
// between `lte-fixture-manifest.schema.json` (OIRAN fixture) and
// `infrastructure/lte-certification/lte-evidence-schema.json` (infra).
//
// D-2/D-3/D-4/D-5 are covered by the validator-level tests shipped inside
// `OIRAN/oiran-decode/src/lte_fixture.rs` (fail-closed on the runtime
// validator). This file covers D-1: the infra schema's `plane` enum used
// underscores (`S1_MME`, `S1_U`, `S5_C`, `S5_U`) that never match the
// hyphenated plane identifiers emitted by the OIRAN runtime. Fixed in
// `infrastructure/lte-certification/lte-evidence-schema.json` 1.1.2.

use serde_json::Value;

const INFRA_SCHEMA_PATH: &str =
    "../../infrastructure/lte-certification/lte-evidence-schema.json";
const INFRA_VERSION_PATH: &str =
    "../../infrastructure/lte-certification/VERSION";

fn load_json(relative: &str) -> Value {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(manifest_dir).join(relative);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text).expect("infra schema is valid JSON")
}

fn load_text(relative: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(manifest_dir).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// D-1 — the infra schema's `capture_refs[].plane` enum must use the same
/// hyphenated plane identifiers the OIRAN runtime emits (`S1-MME`, `S11`,
/// `S1-U`, `S5-C`, `S5-U`). An underscore variant is a silent contract
/// mismatch.
#[test]
fn d1_infra_schema_plane_enum_is_hyphenated() {
    let schema = load_json(INFRA_SCHEMA_PATH);
    let plane_enum = schema
        .pointer("/properties/capture_refs/items/properties/plane/enum")
        .and_then(Value::as_array)
        .expect("capture_refs plane enum is present");
    let values = plane_enum
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(
        values.contains(&"S1-MME") && values.contains(&"S1-U"),
        "infra schema must declare hyphenated plane identifiers; found {values:?}"
    );
    for value in &values {
        assert!(
            !value.contains('_'),
            "infra schema still carries underscore plane identifier '{value}' (D-1 reopened)"
        );
    }

    // Guard against silent downgrades: VERSION file must be at least 1.1.2.
    let version = load_text(INFRA_VERSION_PATH);
    let version = version.trim();
    assert!(
        version == "1.1.2" || version > "1.1.2",
        "infra VERSION must be >= 1.1.2 to carry the D-1 fix; found {version}"
    );
}
