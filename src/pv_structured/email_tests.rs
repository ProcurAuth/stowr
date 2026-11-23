//! The tests of the e-mail reader.

use serde_json::{Value, json};

use super::email::{
    MAX_MIME_DEPTH, MAX_MIME_PARTS, display_headers_for_tests, email_properties, parse_email_headers,
    parse_email_preview,
};
use super::fixtures::{bytes, cases, name};

fn expected_headers(value: &Value) -> Value {
    if value.is_null() { json!({}) } else { value.clone() }
}

#[test]
fn e_mail_previews_match_the_expected_answers_in_each_case() {
    let mut failures = Vec::new();
    for case in cases("emails") {
        let data = bytes(&case["input"]);
        let preview = serde_json::to_value(parse_email_preview(&data)).unwrap_or(Value::Null);
        if preview != case["preview"] {
            failures.push(format!(
                "{} (preview): got {preview}, want {}",
                name(case),
                case["preview"]
            ));
        }
        let headers = parse_email_headers(&data);
        let complete = headers.is_some();
        if complete != case["complete"].as_bool().unwrap_or(false) {
            failures.push(format!("{} (complete): got {complete}", name(case)));
        }
        let map = headers.unwrap_or_default();
        let props = serde_json::to_value(email_properties(&map)).unwrap_or(Value::Null);
        if props != expected_headers(&case["properties"]) {
            failures.push(format!(
                "{} (properties): got {props}, want {}",
                name(case),
                case["properties"]
            ));
        }
        let display = serde_json::to_value(display_headers_for_tests(&map)).unwrap_or(Value::Null);
        if display != expected_headers(&case["headers"]) {
            failures.push(format!(
                "{} (display): got {display}, want {}",
                name(case),
                case["headers"]
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

fn nested_multipart_message(depth: usize, leaf: &str) -> Vec<u8> {
    let mut text =
        String::from("From: a@example.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b0\r\n\r\n");
    for level in 0..depth {
        text.push_str(&format!(
            "--b{level}\r\nContent-Type: multipart/mixed; boundary=b{}\r\n\r\n",
            level + 1
        ));
    }
    text.push_str(&format!(
        "--b{depth}\r\nContent-Type: text/plain\r\n\r\n{leaf}\r\n--b{depth}--\r\n"
    ));
    for level in (0..depth).rev() {
        text.push_str(&format!("--b{level}--\r\n"));
    }
    text.into_bytes()
}

#[test]
fn the_e_mail_preview_bounds_the_multipart_depth_and_the_part_count() {
    assert_eq!(
        parse_email_preview(&nested_multipart_message(3, "shallow")).body_text,
        "shallow"
    );
    assert_eq!(
        parse_email_preview(&nested_multipart_message(MAX_MIME_DEPTH + 12, "too deep")).body_text,
        ""
    );
    let mut text =
        String::from("From: a@example.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n");
    for _ in 0..MAX_MIME_PARTS + 500 {
        text.push_str("--b\r\nContent-Type: text/plain; name=f.txt\r\n\r\nx\r\n");
    }
    text.push_str("--b--\r\n");
    assert_eq!(parse_email_preview(text.as_bytes()).attachments.len(), MAX_MIME_PARTS);
}
