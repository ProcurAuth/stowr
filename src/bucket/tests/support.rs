//! The tests of the helpers: the MD5 digest, the XML tree, the quoting, the URL of an admin API and the signature.

use crate::bucket::sign::{SigningInput, amz_date, authorization, canonical_query, sha256_hex};
use crate::bucket::support::{
    aws_uri_encode, copy_source_header, embedded_error, md5, parse_xml, printable_ascii, quote,
};
use crate::bucket::usage_admin::{AdminUrl, join_host_port, split_host_port};
use crate::common::misc::hex;
use crate::common::time::Timestamp;

#[test]
fn the_md5_digest_gives_the_values_of_the_standard() {
    let cases = [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];
    for (text, want) in cases {
        assert_eq!(hex(&md5(text.as_bytes())), want, "{text:?}");
    }
    // A block boundary: 55, 56, 63, 64 and 65 bytes.
    let long = "x".repeat(65);
    assert_eq!(hex(&md5(long.as_bytes())).len(), 32);
    assert_ne!(md5("x".repeat(55).as_bytes()), md5("x".repeat(56).as_bytes()));
}

#[test]
fn a_document_is_read_into_a_tree_with_the_text_of_each_element() {
    let document = "<?xml version=\"1.0\"?><Result xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><A>a &amp; b</A><B><C> 5 </C></B><B><C>6</C></B><D/><E><![CDATA[<x>]]></E></Result>";
    let root = parse_xml(document.as_bytes()).ok().flatten().unwrap();
    assert_eq!(root.name, "Result");
    assert_eq!(root.text_at(&["A"]), "a & b");
    assert_eq!(root.text_at(&["B", "C"]), " 5 ");
    assert_eq!(root.children_named("B").count(), 2);
    assert!(root.child("D").is_some());
    assert_eq!(root.text_at(&["E"]), "<x>");
    assert_eq!(root.text_at(&["Missing"]), "");
    assert!(matches!(parse_xml(b""), Ok(None)));
    assert!(matches!(parse_xml(b"  \n"), Ok(None)));
    assert!(parse_xml(b"<a><b></a>").is_err());
    assert!(parse_xml(b"<a>").is_err());
    assert!(parse_xml(&[0xff, 0xfe]).is_err());
    assert!(parse_xml(b"<a>&unknown;</a>").is_err());
    let numeric = parse_xml(b"<a>&#65;&#x42;</a>").ok().flatten().unwrap();
    assert_eq!(numeric.text, "AB");
}

#[test]
fn an_embedded_error_is_found_in_a_successful_answer() {
    let error = embedded_error(b"<Error><Code>InternalError</Code><Message>no</Message></Error>");
    let upstream = error.and_then(|error| error.as_upstream());
    assert_eq!(
        upstream.as_ref().map(|value| value.code.as_str()),
        Some("InternalError")
    );
    assert_eq!(upstream.map(|value| value.status), Some(502));
    assert!(embedded_error(b"<CopyObjectResult/>").is_none());
    assert!(embedded_error(b"").is_none());
    assert!(embedded_error(b"not xml <").is_none());
}

#[test]
fn a_text_is_quoted_with_the_escapes_of_a_quoted_text() {
    assert_eq!(quote("doc.txt"), "\"doc.txt\"");
    assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
    assert_eq!(quote("x\ny\t\u{1}"), "\"x\\ny\\t\\x01\"");
    assert_eq!(quote("é"), "\"é\"");
}

#[test]
fn printable_ascii_refuses_a_space_at_the_ends_and_any_other_character() {
    assert!(printable_ascii("a b-1"));
    assert!(!printable_ascii(" a"));
    assert!(!printable_ascii("a "));
    assert!(!printable_ascii("a\tb"));
    assert!(!printable_ascii("é"));
    assert!(printable_ascii(""));
}

#[test]
fn the_copy_source_has_the_escaped_bucket_key_and_version() {
    assert_eq!(
        copy_source_header("bucket", "dir/a file.json", "v 1"),
        "/bucket/dir/a%20file.json?versionId=v+1"
    );
    assert_eq!(
        copy_source_header("bucket", "tenant/doc.txt", ""),
        "/bucket/tenant/doc.txt"
    );
    assert_eq!(aws_uri_encode("a/b c~", true), "a%2Fb%20c~");
    assert_eq!(aws_uri_encode("a/b c~", false), "a/b%20c~");
}

#[test]
fn an_endpoint_of_an_admin_api_is_checked_and_joined() {
    let url = AdminUrl::parse("usage", "http://g:3903").unwrap();
    assert_eq!(url.authority, "g:3903");
    assert_eq!(url.join(&["v2", "GetBucketInfo"]), "http://g:3903/v2/GetBucketInfo");
    assert_eq!(url.hostname(), "g");
    let based = AdminUrl::parse("usage", "https://h.example/base/").unwrap();
    assert_eq!(based.join(&["buckets", "a b"]), "https://h.example/base/buckets/a%20b");
    let cases = [
        ("ftp://f", "scheme must be http or https"),
        ("localhost:9000", "scheme must be http or https"),
        ("http://", "must include a host"),
        ("http://user@h", "must not contain user information"),
        ("http://h?x=1", "must not contain a query string or fragment"),
        ("http://h/#top", "must not contain a query string or fragment"),
    ];
    for (raw, want) in cases {
        let error = AdminUrl::parse("usage", raw)
            .err()
            .map(|error| error.to_string())
            .unwrap();
        assert!(
            error.contains(want) && error.starts_with("usage endpoint"),
            "{raw}: {error}"
        );
    }
    assert_eq!(split_host_port("[::1]:8080"), Some(("::1", "8080")));
    assert_eq!(split_host_port("host:80"), Some(("host", "80")));
    assert_eq!(split_host_port("a:b:c"), None);
    assert_eq!(split_host_port("host"), None);
    assert_eq!(join_host_port("::1", "80"), "[::1]:80");
    assert_eq!(join_host_port("h", "80"), "h:80");
    let ipv6 = AdminUrl::parse("usage", "http://[::1]:9333").unwrap();
    assert_eq!(ipv6.hostname(), "::1");
}

#[test]
fn the_signature_gives_the_reference_value_of_the_documentation() {
    // The example "GET Object" of the documentation of the signature version 4.
    let payload = sha256_hex(b"");
    assert_eq!(
        payload,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    let headers = [
        ("host".to_owned(), "examplebucket.s3.amazonaws.com".to_owned()),
        ("range".to_owned(), "bytes=0-9".to_owned()),
        ("x-amz-content-sha256".to_owned(), payload.clone()),
        ("x-amz-date".to_owned(), "20130524T000000Z".to_owned()),
    ];
    let time = Timestamp::from_unix(1_369_353_600, 0);
    assert_eq!(amz_date(time), "20130524T000000Z");
    let value = authorization(&SigningInput {
        method: "GET",
        canonical_uri: "/test.txt",
        query: &[],
        headers: &headers,
        payload_hash: &payload,
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region: "us-east-1",
        service: "s3",
        time,
    });
    assert_eq!(
        value,
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
}

#[test]
fn the_canonical_query_is_encoded_and_sorted() {
    let query = [("b".to_owned(), "x y".to_owned()), ("a".to_owned(), String::new())];
    assert_eq!(canonical_query(&query), "a=&b=x%20y");
    assert_eq!(canonical_query(&[]), "");
}
