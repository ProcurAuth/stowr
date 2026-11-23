//! The tests of the reader of the public keys of the issuer.

use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
use aws_lc_rs::signature::KeyPair as _;
use base64::engine::general_purpose::STANDARD;

use super::*;

/// The Ed25519 key of RFC 8037, appendix A.3, and its thumbprint.
const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
/// The P-256 key of RFC 7515, appendix A.3.
const RFC7515_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const RFC7515_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

fn ed_jwk(extra: &str) -> String {
    format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{RFC8037_X}"{extra}}}"#)
}

fn ec_jwk(extra: &str) -> String {
    format!(r#"{{"kty":"EC","crv":"P-256","x":"{RFC7515_X}","y":"{RFC7515_Y}"{extra}}}"#)
}

fn key_set(keys: &[String]) -> String {
    format!(r#"{{"keys":[{}]}}"#, keys.join(","))
}

/// One PEM block of DER bytes.
fn pem_of(der: &[u8]) -> String {
    let text = STANDARD.encode(der);
    let lines: Vec<&str> = text
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        lines.join("\n")
    )
}

fn rfc8037_pem() -> String {
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend(URL_SAFE_NO_PAD.decode(RFC8037_X).unwrap());
    pem_of(&der)
}

fn rfc7515_point() -> (Vec<u8>, Vec<u8>) {
    (
        URL_SAFE_NO_PAD.decode(RFC7515_X).unwrap(),
        URL_SAFE_NO_PAD.decode(RFC7515_Y).unwrap(),
    )
}

fn rfc7515_pem() -> String {
    let (x, y) = rfc7515_point();
    let mut der = P256_SPKI_PREFIX.to_vec();
    der.extend(x);
    der.extend(y);
    pem_of(&der)
}

fn random_ed25519_pem() -> String {
    let mut key = [0u8; 32];
    crate::common::misc::random_bytes(&mut key).unwrap();
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend(key);
    pem_of(&der)
}

#[test]
fn ed25519_and_p256_keys_are_accepted() {
    let keys = parse(&key_set(&[
        ed_jwk(r#","kid":"ed-1","alg":"Ed25519","use":"sig","key_ops":["verify"],"x5t":"ignored""#),
        ec_jwk(r#","kid":"ec-1","alg":"ES256""#),
    ]))
    .unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!((keys[0].alg, keys[0].kid.as_str()), (Algorithm::Ed25519, "ed-1"));
    assert!(keys[0].y.is_none());
    assert_eq!((keys[1].alg, keys[1].kid.as_str()), (Algorithm::Es256, "ec-1"));
    assert!(keys[1].y.is_some());
    assert_eq!(keys[0].display(), "Ed25519 kid=ed-1");
    assert_eq!(keys[1].display(), "P-256 kid=ec-1");
}

#[test]
fn the_thumbprint_is_the_default_kid() {
    let keys = parse(&key_set(&[ed_jwk(""), ec_jwk("")])).unwrap();
    assert_eq!(keys[0].kid, RFC8037_THUMBPRINT);
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{RFC7515_X}","y":"{RFC7515_Y}"}}"#);
    let want = URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        canonical.as_bytes(),
    ));
    assert_eq!(keys[1].kid, want);
}

#[test]
fn sixteen_keys_and_the_unknown_members_of_the_set_are_accepted() {
    let items: Vec<String> = (0..16).map(|i| ed_jwk(&format!(r#","kid":"k{i}""#))).collect();
    let keys = parse(&format!(r#"{{"extra":{{"a":1}},"keys":[{}]}}"#, items.join(","))).unwrap();
    assert_eq!(keys.len(), 16);
}

#[test]
fn the_refusals_of_a_jwk_set_name_the_problem() {
    let seventeen: Vec<String> = (0..17).map(|i| ed_jwk(&format!(r#","kid":"k{i}""#))).collect();
    let off_curve_y = format!("y{}", &RFC7515_Y[1..]);
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "not JSON, so not PEM",
            "not json".into(),
            "line 1 is not -----BEGIN PUBLIC KEY-----",
        ),
        ("empty text", String::new(), "no key"),
        (
            "array at the top",
            "[]".into(),
            "line 1 is not -----BEGIN PUBLIC KEY-----",
        ),
        ("JSON that is not valid", r#"{"keys":"#.into(), "not valid JSON"),
        ("no keys member", "{}".into(), r#"must have the member "keys""#),
        (
            "keys is not an array",
            r#"{"keys":{}}"#.into(),
            r#""keys" must be an array"#,
        ),
        ("no keys", r#"{"keys":[]}"#.into(), "has no key"),
        (
            "17 keys",
            format!(r#"{{"keys":[{}]}}"#, seventeen.join(",")),
            "has 17 keys",
        ),
        (
            "key is not an object",
            r#"{"keys":["x"]}"#.into(),
            "key 1: must be a JSON object",
        ),
        (
            "duplicate kid",
            key_set(&[ed_jwk(r#","kid":"same""#), ec_jwk(r#","kid":"same""#)]),
            r#"key 2: the kid "same" is also the kid of key 1"#,
        ),
        (
            "duplicate member of key",
            key_set(&[ed_jwk(r#","kid":"a","kid":"b""#)]),
            r#"the member "kid" is two times"#,
        ),
        (
            "duplicate member of set",
            format!(r#"{{"keys":[{}],"keys":[]}}"#, ed_jwk("")),
            r#"the member "keys" is two times in the JWK Set"#,
        ),
        (
            "duplicate with escape",
            key_set(&[ed_jwk(",\"kid\":\"a\",\"\\u006bid\":\"b\"")]),
            r#"the member "kid" is two times"#,
        ),
        (
            "trailing data",
            format!("{} {{}}", key_set(&[ed_jwk("")])),
            "data after the JSON value",
        ),
        (
            "private member d",
            key_set(&[ed_jwk(&format!(r#","d":"{RFC8037_X}""#))]),
            r#"private member "d""#,
        ),
        (
            "private member k",
            key_set(&[ed_jwk(r#","k":"AAAA""#)]),
            r#"private member "k""#,
        ),
        (
            "private member oth",
            key_set(&[ec_jwk(r#","oth":[]"#)]),
            r#"private member "oth""#,
        ),
        (
            "alg EdDSA for EC",
            key_set(&[ec_jwk(r#","alg":"EdDSA""#)]),
            r#"alg must be "ES256""#,
        ),
        (
            "alg mismatch",
            key_set(&[ed_jwk(r#","alg":"ES256""#)]),
            r#"alg must be "Ed25519""#,
        ),
        (
            "alg mismatch for EC",
            key_set(&[ec_jwk(r#","alg":"Ed25519""#)]),
            r#"alg must be "ES256""#,
        ),
        (
            "alg is not a string",
            key_set(&[ed_jwk(r#","alg":5"#)]),
            r#""alg" must be a string"#,
        ),
        (
            "empty kid",
            key_set(&[ed_jwk(r#","kid":"""#)]),
            "kid must have 1 to 256 bytes",
        ),
        (
            "long kid",
            key_set(&[ed_jwk(&format!(r#","kid":"{}""#, "k".repeat(257)))]),
            "kid must have 1 to 256 bytes",
        ),
        (
            "kid with a control",
            key_set(&[ed_jwk(r#","kid":"a\u0001b""#)]),
            "kid must have 1 to 256 bytes",
        ),
        (
            "kty RSA",
            key_set(&[r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#.into()]),
            r#"kty "RSA""#,
        ),
        (
            "EC with crv P-384",
            key_set(&[r#"{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}"#.into()]),
            r#"crv "P-384""#,
        ),
        (
            "OKP with crv Ed448",
            key_set(&[r#"{"kty":"OKP","crv":"Ed448","x":"AA"}"#.into()]),
            r#"crv "Ed448""#,
        ),
        (
            "no kty",
            key_set(&[format!(r#"{{"crv":"Ed25519","x":"{RFC8037_X}"}}"#)]),
            "is not supported",
        ),
        (
            "no x",
            key_set(&[r#"{"kty":"OKP","crv":"Ed25519"}"#.into()]),
            r#"the member "x" is required"#,
        ),
        (
            "no y",
            key_set(&[format!(r#"{{"kty":"EC","crv":"P-256","x":"{RFC7515_X}"}}"#)]),
            r#"the member "y" is required"#,
        ),
        (
            "x too short",
            key_set(&[format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#, "A".repeat(42))]),
            r#""x" must hold 32 bytes, got 31"#,
        ),
        (
            "x too long",
            key_set(&[format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#, "A".repeat(46))]),
            r#""x" must hold 32 bytes, got 34"#,
        ),
        (
            "x with padding",
            key_set(&[format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{RFC8037_X}="}}"#)]),
            r#""x" must be base64url without padding"#,
        ),
        (
            "x in standard base64",
            key_set(&[format!(
                r#"{{"kty":"OKP","crv":"Ed25519","x":"{}"}}"#,
                RFC8037_X.replace('_', "/")
            )]),
            r#""x" must be base64url without padding"#,
        ),
        (
            "x is not a string",
            key_set(&[r#"{"kty":"OKP","crv":"Ed25519","x":1}"#.into()]),
            r#""x" must be a string"#,
        ),
        (
            "y too short",
            key_set(&[format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{RFC7515_X}","y":"{}"}}"#,
                "A".repeat(42)
            )]),
            r#""y" must hold 32 bytes, got 31"#,
        ),
        (
            "point not on the curve",
            key_set(&[format!(
                r#"{{"kty":"EC","crv":"P-256","x":"{RFC7515_X}","y":"{off_curve_y}"}}"#
            )]),
            "not a point of the curve P-256",
        ),
        (
            "kty is not a string",
            key_set(&[r#"{"kty":1}"#.into()]),
            r#""kty" must be a string"#,
        ),
    ];
    for (name, text, want) in cases {
        match parse(&text) {
            Ok(keys) => panic!("{name}: the text is accepted ({} keys)", keys.len()),
            Err(error) => assert!(
                error.contains(want),
                "{name}: error {error:?} does not contain {want:?}"
            ),
        }
    }
}

#[test]
fn the_error_names_the_position_of_the_key() {
    let error = parse(&key_set(&[
        ed_jwk(r#","kid":"a""#),
        ec_jwk(r#","kid":"b""#),
        ed_jwk(r#","kid":"c","alg":"ES256""#),
    ]))
    .unwrap_err();
    assert!(error.starts_with("key 3: "), "{error}");
}

#[test]
fn some_jwk_members_have_no_effect() {
    // The alg EdDSA of an OKP key is accepted, and the members use and key_ops have no effect.
    let keys = parse(&key_set(&[
        ed_jwk(r#","kid":"a","alg":"EdDSA""#),
        ed_jwk(r#","kid":"b","use":"enc""#),
        ed_jwk(r#","kid":"c","key_ops":["sign"]"#),
        ed_jwk(r#","kid":"d","key_ops":"verify""#),
        ed_jwk(r#","kid":"e\u0085""#),
    ]))
    .unwrap();
    assert!(keys.iter().all(|key| key.alg == Algorithm::Ed25519));
    assert_eq!(keys[4].kid, "e\u{85}");
}

#[test]
fn a_pem_key_gets_its_thumbprint_as_kid() {
    let keys = parse(&rfc8037_pem()).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        (keys[0].alg, keys[0].kid.as_str()),
        (Algorithm::Ed25519, RFC8037_THUMBPRINT)
    );
    assert_eq!(keys[0].display(), format!("Ed25519 kid={RFC8037_THUMBPRINT}"));
    let keys = parse(&rfc7515_pem()).unwrap();
    let from_jwk = parse(&key_set(&[ec_jwk("")])).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].alg, Algorithm::Es256);
    assert_eq!(keys[0].kid, from_jwk[0].kid);
    assert_eq!(keys[0].display(), format!("P-256 kid={}", from_jwk[0].kid));
    assert_eq!(keys[0], from_jwk[0]);
}

#[test]
fn the_forms_of_pem_text() {
    let two = format!("\n  {}\n\n{}\n", rfc8037_pem(), rfc7515_pem());
    let keys = parse(&two).unwrap();
    assert_eq!(
        keys.iter().map(|key| key.alg).collect::<Vec<_>>(),
        vec![Algorithm::Ed25519, Algorithm::Es256]
    );
    assert_eq!(parse(&rfc8037_pem().replace('\n', "\r\n")).unwrap().len(), 1);
    // Two identical blocks give one kid two times: only a JWK Set refuses a repeated kid.
    assert_eq!(parse(&format!("{}{}", rfc8037_pem(), rfc8037_pem())).unwrap().len(), 2);
    let sixteen: String = (0..16).map(|_| random_ed25519_pem()).collect();
    assert_eq!(parse(&sixteen).unwrap().len(), 16);
    let error = parse(&format!("{sixteen}{}", random_ed25519_pem())).unwrap_err();
    assert!(error.contains("more than 16 keys"), "{error}");
}

#[test]
fn the_refusals_of_pem_text_name_the_problem() {
    let ed = rfc8037_pem();
    let body = ed
        .trim_start_matches("-----BEGIN PUBLIC KEY-----\n")
        .trim_end_matches("-----END PUBLIC KEY-----\n")
        .to_owned();
    let rsa = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let rsa_der: PublicKeyX509Der<'static> = rsa.public_key().as_der().unwrap();
    let p384 =
        aws_lc_rs::signature::EcdsaKeyPair::generate(&aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING).unwrap();
    let p384_der: PublicKeyX509Der<'static> = p384.public_key().as_der().unwrap();
    // A compressed P-256 point: the prefix of a SubjectPublicKeyInfo with a point of 33 bytes.
    let mut compressed = vec![
        0x30, 0x39, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x22, 0x00, 0x02,
    ];
    compressed.extend([0u8; 32]);
    // A P-256 point that is not on the curve: the y of RFC 7515 with its first byte changed.
    let (x, mut y) = rfc7515_point();
    y[0] ^= 0xff;
    let mut off_curve = P256_SPKI_PREFIX.to_vec();
    off_curve.extend(x);
    off_curve.extend(y);
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "text before the block",
            format!("keys:\n{ed}"),
            "line 1 is not -----BEGIN PUBLIC KEY-----",
        ),
        (
            "text after the block",
            format!("{ed}end\n"),
            "line 4 is not -----BEGIN PUBLIC KEY-----",
        ),
        (
            "private key",
            format!("-----BEGIN PRIVATE KEY-----\n{body}-----END PRIVATE KEY-----\n"),
            "line 1 is not -----BEGIN PUBLIC KEY-----",
        ),
        (
            "PEM header",
            format!("-----BEGIN PUBLIC KEY-----\nProc-Type: 4,ENCRYPTED\n{body}-----END PUBLIC KEY-----\n"),
            "key 1 is not valid base64",
        ),
        (
            "no end line",
            ed.trim_end_matches("-----END PUBLIC KEY-----\n").to_owned(),
            "-----END PUBLIC KEY----- is missing",
        ),
        (
            "bad base64",
            "-----BEGIN PUBLIC KEY-----\n%%%%\n-----END PUBLIC KEY-----\n".into(),
            "key 1 is not valid base64",
        ),
        (
            "base64 without padding",
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                body.trim().trim_end_matches('=')
            ),
            "key 1 is not valid base64",
        ),
        (
            "empty block",
            "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n".into(),
            "key 1 is not an Ed25519 public key",
        ),
        (
            "RSA key",
            pem_of(rsa_der.as_ref()),
            "key 1 is not an Ed25519 public key or a P-256 public key",
        ),
        (
            "P-384 key",
            pem_of(p384_der.as_ref()),
            "key 1 is not an Ed25519 public key or a P-256 public key",
        ),
        (
            "compressed P-256 point",
            pem_of(&compressed),
            "key 1 is not an Ed25519 public key or a P-256 public key with an uncompressed point",
        ),
        (
            "point not on the curve",
            pem_of(&off_curve),
            "key 1 is not a point of the curve P-256",
        ),
        (
            "second block is bad",
            format!("{ed}-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"),
            "key 2 is not an Ed25519 public key",
        ),
        (
            "block too long",
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                "A".repeat(4097)
            ),
            "key 1 is too long",
        ),
        ("only spaces", " \n\t\n".into(), "no key"),
        (
            "a JWK Set and PEM",
            format!("{}\n{ed}", key_set(&[ed_jwk("")])),
            "data after the JSON value",
        ),
        (
            "PEM then a JWK Set",
            format!("{ed}{}", key_set(&[ed_jwk("")])),
            "line 4 is not -----BEGIN PUBLIC KEY-----",
        ),
    ];
    for (name, text, want) in cases {
        match parse(&text) {
            Ok(keys) => panic!("{name}: the text is accepted ({} keys)", keys.len()),
            Err(error) => assert!(
                error.contains(want),
                "{name}: error {error:?} does not contain {want:?}"
            ),
        }
    }
}

#[test]
fn a_key_gives_its_jwk_with_its_kid() {
    let keys = parse(&key_set(&[ed_jwk(r#","kid":"ed-1""#), ec_jwk("")])).unwrap();
    assert_eq!(
        keys[0].to_jwk(),
        serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X, "kid": "ed-1"})
    );
    assert_eq!(
        keys[1].to_jwk(),
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": RFC7515_X, "y": RFC7515_Y, "kid": keys[1].kid})
    );
    // The JWK of a key reads back to the same key.
    let again = parse(&key_set(&[keys[1].to_jwk().to_string()])).unwrap();
    assert_eq!(again[0], keys[1]);
}
