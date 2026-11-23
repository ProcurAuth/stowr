//! The cases of the tests: inputs and the expected answers of a reference run, in `testdata/fixtures.json`.

use std::sync::OnceLock;

use base64::Engine as _;
use serde_json::Value;

static FIXTURES: OnceLock<Value> = OnceLock::new();

fn all() -> &'static Value {
    FIXTURES.get_or_init(|| {
        serde_json::from_str(include_str!("testdata/fixtures.json")).unwrap_or(Value::Null)
    })
}

/// The cases of one category.
pub fn cases(category: &str) -> &'static [Value] {
    all()[category].as_array().map_or(&[], Vec::as_slice)
}

/// The bytes of a base64 text of a case.
pub fn bytes(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_str().unwrap_or(""))
        .unwrap_or_default()
}

/// The name of a case.
pub fn name(case: &Value) -> &str {
    case["name"].as_str().unwrap_or("")
}
