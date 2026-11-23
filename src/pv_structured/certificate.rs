// SPDX-License-Identifier: MIT OR Apache-2.0
//! The details of certificates, certificate requests and keys: the PEM blocks and the DER structures.

use std::collections::BTreeMap;

use super::pem::{PemBlock, decode_all};
use super::x509;

/// The label of the container of a certificate file.
pub fn certificate_container_label(extension: &str) -> &'static str {
    match extension {
        "csr" | "req" => "Certificate signing request",
        "p7b" | "p7c" | "spc" => "PKCS#7 certificate bundle",
        "pfx" | "p12" => "PKCS#12 bundle",
        "key" => "PEM private key",
        "pub" => "Public key",
        "der" => "DER certificate",
        _ => "PEM certificate",
    }
}

/// Add the details of one block: the type of the block and what the DER bytes tell.
pub fn merge_block_properties(props: &mut BTreeMap<String, String>, kind: &str, der: &[u8]) {
    let kind = kind.trim().to_uppercase();
    if !kind.is_empty() {
        props.insert("First block".to_owned(), kind.clone());
    }
    match kind.as_str() {
        "CERTIFICATE" => {
            let Some(certificate) = x509::parse_certificate(der) else {
                return;
            };
            props.insert("Subject".to_owned(), certificate.subject.to_text());
            props.insert("Issuer".to_owned(), certificate.issuer.to_text());
            props.insert("Serial number".to_owned(), certificate.serial.clone());
            props.insert("Not before".to_owned(), certificate.not_before.rfc3339());
            props.insert("Not after".to_owned(), certificate.not_after.rfc3339());
            props.insert(
                "Signature algorithm".to_owned(),
                certificate.signature_algorithm.clone(),
            );
            props.insert(
                "Public key algorithm".to_owned(),
                certificate.public_key_algorithm.clone(),
            );
            if !certificate.dns_names.is_empty() {
                props.insert("DNS names".to_owned(), certificate.dns_names.join(", "));
            }
            if !certificate.email_addresses.is_empty() {
                props.insert("Email addresses".to_owned(), certificate.email_addresses.join(", "));
            }
            if !certificate.ip_addresses.is_empty() {
                props.insert("IP addresses".to_owned(), certificate.ip_addresses.join(", "));
            }
            if certificate.is_ca {
                props.insert("Certificate authority".to_owned(), "Yes".to_owned());
            }
        }
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => {
            let Some(request) = x509::parse_certificate_request(der) else {
                return;
            };
            props.insert("Subject".to_owned(), request.subject.to_text());
            props.insert("Signature algorithm".to_owned(), request.signature_algorithm.clone());
            props.insert("Public key algorithm".to_owned(), request.public_key_label.clone());
            if !request.dns_names.is_empty() {
                props.insert("DNS names".to_owned(), request.dns_names.join(", "));
            }
        }
        "RSA PRIVATE KEY" => {
            if let Some(bits) = x509::parse_pkcs1_private_key(der) {
                props.insert("Key algorithm".to_owned(), "RSA".to_owned());
                props.insert("Key bits".to_owned(), bits.to_string());
            }
        }
        "PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" => {
            if let Some(key) = x509::parse_pkcs8_private_key(der) {
                props.insert("Key algorithm".to_owned(), key.label());
            }
        }
        "PUBLIC KEY" => {
            if let Some(key) = x509::parse_pkix_public_key(der) {
                props.insert("Public key algorithm".to_owned(), key.label());
            }
        }
        "EC PRIVATE KEY" => {
            if let Some(curve) = x509::parse_ec_private_key_curve(der) {
                props.insert("Key algorithm".to_owned(), "ECDSA".to_owned());
                props.insert("Curve".to_owned(), curve.to_owned());
            }
        }
        _ => {
            if x509::is_asn1_element(der) {
                props.insert("ASN.1 DER".to_owned(), "Yes".to_owned());
            }
        }
    }
}

/// The details of a certificate file: the count of the PEM blocks and the details of the first block that has a
/// type. A file without a PEM block is read as a DER certificate, or as a DER request for the extensions `csr`
/// and `req`.
pub fn parse_certificate_properties(data: &[u8], extension: &str) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();
    let blocks = decode_all(data);
    if !blocks.is_empty() {
        props.insert("PEM blocks".to_owned(), blocks.len().to_string());
        for block in &blocks {
            merge_block_properties(&mut props, &block.kind, &block.bytes);
            if props.len() > 1 {
                return props;
            }
        }
        return props;
    }
    if extension == "csr" || extension == "req" {
        merge_block_properties(&mut props, "CERTIFICATE REQUEST", data);
    } else {
        merge_block_properties(&mut props, "CERTIFICATE", data);
    }
    props
}

/// The details of each block of a certificate file.
pub fn parse_all_certificate_properties(data: &[u8], extension: &str) -> Vec<BTreeMap<String, String>> {
    let blocks: Vec<PemBlock> = decode_all(data);
    let mut result = Vec::new();
    if blocks.is_empty() {
        let mut props = BTreeMap::new();
        if extension == "csr" || extension == "req" {
            merge_block_properties(&mut props, "CERTIFICATE REQUEST", data);
        } else {
            merge_block_properties(&mut props, "CERTIFICATE", data);
        }
        if !props.is_empty() {
            result.push(props);
        }
        return result;
    }
    for block in blocks {
        let mut props = BTreeMap::new();
        merge_block_properties(&mut props, &block.kind, &block.bytes);
        if props.is_empty() {
            props.insert("Block".to_owned(), block.kind.clone());
        }
        result.push(props);
    }
    result
}

/// True when the data is mostly text: no NUL byte and at least 90 percent printable bytes.
pub fn is_mostly_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let mut printable = 0usize;
    for value in data {
        if *value == 0 {
            return false;
        }
        if matches!(*value, b'\n' | b'\r' | b'\t') || (0x20..0x7f).contains(value) || *value >= 0xc2 {
            printable += 1;
        }
    }
    printable * 100 / data.len() >= 90
}
