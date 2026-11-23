// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the HTML text reader.

use super::fixtures::cases;
use super::html::{to_plain_text, unescape};

#[test]
fn html_text_and_references_match_the_expected_answers_in_each_case() {
    let mut failures = Vec::new();
    for case in cases("html") {
        let input = case["input"].as_str().unwrap_or("");
        let want_text = case["text"].as_str().unwrap_or("");
        let want_unescape = case["unescape"].as_str().unwrap_or("");
        let text = to_plain_text(input);
        if text != want_text {
            failures.push(format!("text of {input:?}: got {text:?}, want {want_text:?}"));
        }
        let unescaped = unescape(input);
        if unescaped != want_unescape {
            failures.push(format!(
                "references of {input:?}: got {unescaped:?}, want {want_unescape:?}"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
