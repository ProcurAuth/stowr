// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the certificate, request and key details.

use std::collections::BTreeMap;

use serde_json::Value;

use super::certificate::{
    certificate_container_label, is_mostly_text, parse_all_certificate_properties, parse_certificate_properties,
};
use super::der::{BigInt, Der, read_time};
use super::fixtures::{bytes, cases, name};
use super::x509::ip_text;

fn expected_map(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(key, value)| (key.clone(), value.as_str().unwrap_or("").to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn certificate_details_match_the_expected_text_in_each_case() {
    let mut failures = Vec::new();
    for case in cases("certificates") {
        let data = bytes(&case["input"]);
        let extension = case["extension"].as_str().unwrap_or("");
        let expected = expected_map(&case["properties"]);
        let got = parse_certificate_properties(&data, extension);
        if got != expected {
            failures.push(format!("{}: got {got:?}, want {expected:?}", name(case)));
        }
        let expected_all: Vec<BTreeMap<String, String>> = case["all"]
            .as_array()
            .map(|list| list.iter().map(expected_map).collect())
            .unwrap_or_default();
        let got_all = parse_all_certificate_properties(&data, extension);
        if got_all != expected_all {
            failures.push(format!(
                "{} (all blocks): got {got_all:?}, want {expected_all:?}",
                name(case)
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

#[test]
fn the_test_cases_are_present() {
    assert!(cases("certificates").len() > 80);
}

#[test]
fn container_labels_follow_the_extension() {
    assert_eq!(certificate_container_label("csr"), "Certificate signing request");
    assert_eq!(certificate_container_label("req"), "Certificate signing request");
    assert_eq!(certificate_container_label("p7b"), "PKCS#7 certificate bundle");
    assert_eq!(certificate_container_label("pfx"), "PKCS#12 bundle");
    assert_eq!(certificate_container_label("key"), "PEM private key");
    assert_eq!(certificate_container_label("pub"), "Public key");
    assert_eq!(certificate_container_label("der"), "DER certificate");
    assert_eq!(certificate_container_label("pem"), "PEM certificate");
}

#[test]
fn a_private_key_block_with_bad_data_shows_only_its_type() {
    let data = b"-----BEGIN PRIVATE KEY-----\nAQIDBA==\n-----END PRIVATE KEY-----\n";
    let props = parse_certificate_properties(data, "key");
    assert_eq!(props.get("PEM blocks").map(String::as_str), Some("1"));
    assert_eq!(props.get("First block").map(String::as_str), Some("PRIVATE KEY"));
    assert_eq!(props.len(), 2);
}

#[test]
fn text_is_recognized_by_the_share_of_printable_bytes() {
    assert!(is_mostly_text(b""));
    assert!(is_mostly_text(
        b"-----BEGIN PRIVATE KEY-----\nAQIDBA==\n-----END PRIVATE KEY-----\n"
    ));
    assert!(!is_mostly_text(&[0x30, 0x82, 0x00, 0x01]));
    assert!(!is_mostly_text(b"abc\0def"));
    let mut data = vec![b'a'; 89];
    data.extend_from_slice(&[0x01; 11]);
    assert!(!is_mostly_text(&data));
    let mut data = vec![b'a'; 90];
    data.extend_from_slice(&[0x01; 10]);
    assert!(is_mostly_text(&data));
}

#[test]
fn big_integers_have_a_decimal_text() {
    let cases: [(&[u8], &str); 6] = [
        (&[0x00], "0"),
        (&[0x7f], "127"),
        (&[0x00, 0x80], "128"),
        (&[0xff], "-1"),
        (&[0x80], "-128"),
        (
            &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "18446744073709551616",
        ),
    ];
    for (content, expected) in cases {
        let value = BigInt::from_der_content(content).unwrap_or_else(|| BigInt {
            negative: false,
            magnitude: Vec::new(),
        });
        assert_eq!(value.to_decimal(), expected, "{content:?}");
    }
    assert!(BigInt::from_der_content(&[0x00, 0x01]).is_none());
    assert!(BigInt::from_der_content(&[0xff, 0xff]).is_none());
    assert!(BigInt::from_der_content(&[]).is_none());
}

#[test]
fn ip_addresses_have_the_compact_text() {
    assert_eq!(ip_text(&[192, 0, 2, 7]), "192.0.2.7");
    let mut ip = [0u8; 16];
    ip[15] = 1;
    assert_eq!(ip_text(&ip), "::1");
    assert_eq!(ip_text(&[0; 16]), "::");
    let mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4];
    assert_eq!(ip_text(&mapped), "1.2.3.4");
    let address = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(ip_text(&address), "2001:db8::1");
    let split = [0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
    assert_eq!(ip_text(&split), "1:0:2::3:0:0");
}

#[test]
fn times_in_a_certificate_follow_the_two_forms() {
    let read = |tag: u8, text: &str| {
        let mut data = vec![tag, text.len() as u8];
        data.extend_from_slice(text.as_bytes());
        read_time(&mut Der(&data)).map(|time| time.rfc3339())
    };
    assert_eq!(read(0x17, "260102030405Z").as_deref(), Some("2026-01-02T03:04:05Z"));
    assert_eq!(read(0x17, "500101000000Z").as_deref(), Some("1950-01-01T00:00:00Z"));
    assert_eq!(read(0x17, "491231235959Z").as_deref(), Some("2049-12-31T23:59:59Z"));
    assert_eq!(read(0x17, "2601020304Z").as_deref(), Some("2026-01-02T03:04:00Z"));
    assert_eq!(read(0x17, "260102030405+0100").as_deref(), Some("2026-01-02T02:04:05Z"));
    assert_eq!(read(0x17, "260102030405-0130").as_deref(), Some("2026-01-02T04:34:05Z"));
    assert_eq!(read(0x17, "260102030405+0000"), None);
    assert_eq!(read(0x17, "261302030405Z"), None);
    assert_eq!(read(0x17, "260230030405Z"), None);
    assert_eq!(read(0x17, "260102240000Z"), None);
    assert_eq!(read(0x17, "260102030460Z"), None);
    assert_eq!(read(0x17, "26010203040"), None);
    assert_eq!(read(0x18, "20500101000000Z").as_deref(), Some("2050-01-01T00:00:00Z"));
    assert_eq!(read(0x18, "99991231235959Z").as_deref(), Some("9999-12-31T23:59:59Z"));
    assert_eq!(read(0x18, "20240229120000Z").as_deref(), Some("2024-02-29T12:00:00Z"));
    assert_eq!(read(0x18, "20230229120000Z"), None);
    assert_eq!(read(0x18, "20260102030405.5Z"), None);
    assert_eq!(read(0x18, "2026010203Z"), None);
}

#[test]
fn big_unsigned_integers_multiply_and_reduce() {
    use super::bignum::{Uint, point_on_curve};
    let a = Uint::from_hex("ffffffffffffffffffffffffffffffff");
    let b = Uint::from_hex("123456789abcdef0123456789abcdef");
    let product = a.mul(&b);
    assert_eq!(product.rem(&a), Uint::default());
    assert_eq!(product.rem(&b), Uint::default());
    assert_eq!(product.add(&Uint::from_u64(7)).rem(&a), Uint::from_u64(7));
    assert_eq!(Uint::from_u64(100).rem(&Uint::from_u64(7)), Uint::from_u64(2));
    assert_eq!(Uint::from_u64(5).sub(&Uint::from_u64(9)), Uint::default());
    assert_eq!(Uint::from_hex("0100").bit_length(), 9);
    // The base point of the curve P-256 is on the curve; a changed coordinate is not.
    let x_bytes = hex_bytes("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    let y_bytes = hex_bytes("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    assert!(point_on_curve("P-256", &x_bytes, &y_bytes));
    let mut changed = y_bytes.clone();
    changed[31] ^= 1;
    assert!(!point_on_curve("P-256", &x_bytes, &changed));
    assert!(!point_on_curve("P-256", &[0xff; 32], &y_bytes));
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap_or(0))
        .collect()
}
