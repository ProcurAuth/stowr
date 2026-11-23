//! A reader of X.509 certificates, certificate requests and keys. It gives the facts that the previews show.
//! These are the names in the text form of RFC 2253, the serial number, the dates, the algorithms, the
//! alternative names and the size of a key. The reader refuses a structure that a strict parser refuses.

use std::fmt::Write as _;

use super::bignum::Uint;
use super::der::{
    BOOLEAN, BitString, DateTime, Der, INTEGER, OBJECT_IDENTIFIER, OCTET_STRING, Oid, SEQUENCE, SET, context,
    context_constructed, read_time,
};

/// One attribute of a name: the type and the text of the value.
#[derive(Clone, Debug)]
struct Attribute {
    oid: Oid,
    value: String,
    /// True when the value is not valid UTF-8: each invalid byte shows as U+FFFD.
    invalid: bool,
}

impl Attribute {
    /// The last arc of a standard attribute type `2.5.4.x`, when the identifier is one of those that the name
    /// keeps in a named field.
    fn named_field(&self) -> Option<u64> {
        match self.oid.0.as_slice() {
            [2, 5, 4, last] if matches!(last, 3 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 17) => Some(*last),
            _ => None,
        }
    }
}

/// A distinguished name.
#[derive(Clone, Debug, Default)]
pub struct Name {
    names: Vec<Attribute>,
    country: Vec<String>,
    organization: Vec<String>,
    organizational_unit: Vec<String>,
    locality: Vec<String>,
    province: Vec<String>,
    street_address: Vec<String>,
    postal_code: Vec<String>,
    serial_number: String,
    common_name: String,
}

fn is_printable(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || (b'\''..=b')').contains(&byte)
        || (b'+'..=b'/').contains(&byte)
        || matches!(byte, b' ' | b':' | b'=' | b'?' | b'*' | b'&')
}

/// The text of an ASN.1 string type, or `None` when the bytes are not valid for the type.
fn parse_string(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        super::der::T61_STRING => Some(super::text::lossy(value)),
        super::der::PRINTABLE_STRING => {
            if value.iter().all(|byte| is_printable(*byte)) {
                Some(String::from_utf8_lossy(value).into_owned())
            } else {
                None
            }
        }
        super::der::UTF8_STRING => std::str::from_utf8(value).ok().map(str::to_owned),
        super::der::BMP_STRING => {
            if !value.len().is_multiple_of(2) {
                return None;
            }
            let mut value = value;
            if value.len() >= 2 && value[value.len() - 1] == 0 && value[value.len() - 2] == 0 {
                value = &value[..value.len() - 2];
            }
            let mut units = Vec::with_capacity(value.len() / 2);
            for pair in value.chunks(2) {
                let point = u16::from(pair[0]) << 8 | u16::from(pair[1]);
                if point == 0xfffe
                    || point == 0xffff
                    || (0xfdd0..=0xfdef).contains(&point)
                    || (0xd800..=0xdfff).contains(&point)
                {
                    return None;
                }
                units.push(point);
            }
            String::from_utf16(&units).ok()
        }
        super::der::IA5_STRING => {
            if value.iter().all(u8::is_ascii) {
                Some(String::from_utf8_lossy(value).into_owned())
            } else {
                None
            }
        }
        super::der::NUMERIC_STRING => {
            if value.iter().all(|byte| byte.is_ascii_digit() || *byte == b' ') {
                Some(String::from_utf8_lossy(value).into_owned())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Read the value of an attribute: a string type. Any other type makes the name not valid.
fn read_value(der: &mut Der<'_>) -> Option<(String, bool)> {
    let (tag, content) = der.read_any()?;
    let text = parse_string(tag, content)?;
    let invalid = tag == super::der::T61_STRING && std::str::from_utf8(content).is_err();
    Some((text, invalid))
}

impl Name {
    /// Read a name from a whole SEQUENCE element.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let mut outer = Der(raw);
        let content = outer.read(SEQUENCE)?;
        let mut sequence = Der(content);
        let mut name = Name::default();
        while !sequence.is_empty() {
            let set = sequence.read(SET)?;
            let mut set = Der(set);
            while !set.is_empty() {
                let attribute = set.read(SEQUENCE)?;
                let mut attribute = Der(attribute);
                let oid = attribute.read_oid()?;
                let (value, invalid) = read_value(&mut attribute)?;
                name.add(Attribute { oid, value, invalid });
            }
        }
        Some(name)
    }

    fn add(&mut self, attribute: Attribute) {
        if let Some(last) = attribute.named_field() {
            let value = attribute.value.clone();
            match last {
                3 => self.common_name = value,
                5 => self.serial_number = value,
                6 => self.country.push(value),
                7 => self.locality.push(value),
                8 => self.province.push(value),
                9 => self.street_address.push(value),
                10 => self.organization.push(value),
                11 => self.organizational_unit.push(value),
                17 => self.postal_code.push(value),
                _ => {}
            }
        }
        self.names.push(attribute);
    }

    /// The text form of the name, in the order of RFC 2253: the last relative name first. An attribute that the
    /// reader does not know stays at the end; the standard attributes come in a fixed order.
    pub fn to_text(&self) -> String {
        let mut rdns: Vec<Vec<Rendered>> = Vec::new();
        for attribute in &self.names {
            if attribute.named_field().is_some() {
                continue;
            }
            rdns.push(vec![describe_other(attribute)]);
        }
        let groups: [(&[String], &str); 7] = [
            (&self.country, "C"),
            (&self.province, "ST"),
            (&self.locality, "L"),
            (&self.street_address, "STREET"),
            (&self.postal_code, "POSTALCODE"),
            (&self.organization, "O"),
            (&self.organizational_unit, "OU"),
        ];
        for (values, name) in groups {
            if !values.is_empty() {
                rdns.push(values.iter().map(|value| Rendered::text(name, value)).collect());
            }
        }
        if !self.common_name.is_empty() {
            rdns.push(vec![Rendered::text("CN", &self.common_name)]);
        }
        if !self.serial_number.is_empty() {
            rdns.push(vec![Rendered::text("SERIALNUMBER", &self.serial_number)]);
        }
        let mut out = String::new();
        for (index, rdn) in rdns.iter().rev().enumerate() {
            if index > 0 {
                out.push(',');
            }
            for (position, item) in rdn.iter().enumerate() {
                if position > 0 {
                    out.push('+');
                }
                out.push_str(&item.name);
                out.push('=');
                if item.hex {
                    out.push('#');
                }
                out.push_str(&item.value);
            }
        }
        out
    }
}

/// One attribute of a name as text.
struct Rendered {
    name: String,
    value: String,
    hex: bool,
}

impl Rendered {
    fn text(name: &str, value: &str) -> Self {
        Self {
            name: name.to_owned(),
            value: escape_value(value),
            hex: false,
        }
    }
}

/// Escape a value as RFC 2253 asks.
fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let last = value.len().saturating_sub(1);
    for (index, character) in value.char_indices() {
        let escape = match character {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => true,
            ' ' => index == 0 || index == last,
            '#' => index == 0,
            _ => false,
        };
        if escape {
            out.push('\\');
        }
        out.push(character);
    }
    out
}

/// The type name and the value of an attribute of a type that has no short name.
/// The type name is the identifier. The value is the hexadecimal form of its DER bytes.
/// The DER value is a PrintableString when its characters allow it, else a UTF8String.
fn describe_other(attribute: &Attribute) -> Rendered {
    if attribute.invalid {
        // The bytes are not UTF-8: no DER form exists for the text, so the text stays.
        return Rendered::text(&attribute.oid.dotted(), &attribute.value);
    }
    let printable = attribute.value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b' ' | b':' | b'=' | b'?'
            )
    });
    let tag = if printable { 0x13 } else { 0x0c };
    let content = attribute.value.as_bytes();
    let mut der: Vec<u8> = vec![tag];
    if content.len() < 128 {
        der.push(content.len() as u8);
    } else {
        let length = content.len().to_be_bytes();
        let start = length.iter().position(|byte| *byte != 0).unwrap_or(length.len() - 1);
        der.push(0x80 | (length.len() - start) as u8);
        der.extend_from_slice(&length[start..]);
    }
    der.extend_from_slice(content);
    let mut hex = String::with_capacity(der.len() * 2);
    for byte in &der {
        let _ = write!(hex, "{byte:02x}");
    }
    Rendered {
        name: attribute.oid.dotted(),
        value: hex,
        hex: true,
    }
}

/// The algorithm identifier: the identifier and the whole parameters element (empty when absent).
#[derive(Clone, Debug)]
struct AlgorithmIdentifier {
    oid: Oid,
    parameters: Vec<u8>,
}

fn read_algorithm_identifier(content: &[u8]) -> Option<AlgorithmIdentifier> {
    let mut der = Der(content);
    let oid = der.read_oid()?;
    if der.is_empty() {
        return Some(AlgorithmIdentifier {
            oid,
            parameters: Vec::new(),
        });
    }
    let (_, full, _) = der.read_any_element()?;
    Some(AlgorithmIdentifier {
        oid,
        parameters: full.to_vec(),
    })
}

/// The signature algorithm names.
fn signature_algorithm_name(identifier: &AlgorithmIdentifier) -> String {
    const ED25519: &[u64] = &[1, 3, 101, 112];
    const RSA_PSS: &[u64] = &[1, 2, 840, 113_549, 1, 1, 10];
    let table: [(&[u64], &str); 13] = [
        (&[1, 2, 840, 113_549, 1, 1, 4], "MD5-RSA"),
        (&[1, 2, 840, 113_549, 1, 1, 5], "SHA1-RSA"),
        (&[1, 3, 14, 3, 2, 29], "SHA1-RSA"),
        (&[1, 2, 840, 113_549, 1, 1, 11], "SHA256-RSA"),
        (&[1, 2, 840, 113_549, 1, 1, 12], "SHA384-RSA"),
        (&[1, 2, 840, 113_549, 1, 1, 13], "SHA512-RSA"),
        (&[1, 2, 840, 10_040, 4, 3], "DSA-SHA1"),
        (&[2, 16, 840, 1, 101, 3, 4, 3, 2], "DSA-SHA256"),
        (&[1, 2, 840, 10_045, 4, 1], "ECDSA-SHA1"),
        (&[1, 2, 840, 10_045, 4, 3, 2], "ECDSA-SHA256"),
        (&[1, 2, 840, 10_045, 4, 3, 3], "ECDSA-SHA384"),
        (&[1, 2, 840, 10_045, 4, 3, 4], "ECDSA-SHA512"),
        (ED25519, "Ed25519"),
    ];
    if identifier.oid.is(ED25519) && !identifier.parameters.is_empty() {
        return "0".to_owned();
    }
    if !identifier.oid.is(RSA_PSS) {
        return table
            .iter()
            .find(|(arcs, _)| identifier.oid.is(arcs))
            .map_or_else(|| "0".to_owned(), |(_, name)| (*name).to_owned());
    }
    pss_algorithm_name(&identifier.parameters).unwrap_or("0").to_owned()
}

/// The name of an RSA PSS algorithm from its parameters, when they are one of the three usual forms.
fn pss_algorithm_name(parameters: &[u8]) -> Option<&'static str> {
    let mut outer = Der(parameters);
    let content = outer.read(SEQUENCE)?;
    let mut der = Der(content);
    let hash = read_algorithm_identifier(single_sequence(der.read(context_constructed(0))?)?)?;
    let mask = read_algorithm_identifier(single_sequence(der.read(context_constructed(1))?)?)?;
    let salt = {
        let inner = der.read(context_constructed(2))?;
        let mut inner = Der(inner);
        inner.read_i32()?
    };
    let trailer = match der.read_optional(context_constructed(3))? {
        Some(inner) => {
            let mut inner = Der(inner);
            inner.read_i32()?
        }
        None => 1,
    };
    let mut mask_parameters = Der(&mask.parameters);
    let mask_content = mask_parameters.read(SEQUENCE)?;
    let mask_hash = read_algorithm_identifier(mask_content)?;
    let null: &[u8] = &[5, 0];
    if (!hash.parameters.is_empty() && hash.parameters != null)
        || !mask.oid.is(&[1, 2, 840, 113_549, 1, 1, 8])
        || mask_hash.oid != hash.oid
        || (!mask_hash.parameters.is_empty() && mask_hash.parameters != null)
        || trailer != 1
    {
        return None;
    }
    if hash.oid.is(&[2, 16, 840, 1, 101, 3, 4, 2, 1]) && salt == 32 {
        Some("SHA256-RSAPSS")
    } else if hash.oid.is(&[2, 16, 840, 1, 101, 3, 4, 2, 2]) && salt == 48 {
        Some("SHA384-RSAPSS")
    } else if hash.oid.is(&[2, 16, 840, 1, 101, 3, 4, 2, 3]) && salt == 64 {
        Some("SHA512-RSAPSS")
    } else {
        None
    }
}

/// The content of the first SEQUENCE of the bytes.
fn single_sequence(bytes: &[u8]) -> Option<&[u8]> {
    let mut der = Der(bytes);
    der.read(SEQUENCE)
}

/// The key of a certificate or of a key file, as far as the previews need it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// An RSA key with the size of its modulus in bits.
    Rsa(usize),
    /// An ECDSA key with the name of its curve.
    Ecdsa(&'static str),
    /// An Ed25519 key.
    Ed25519,
    /// A DSA key.
    Dsa,
    /// An X25519 key.
    X25519,
}

impl PublicKey {
    /// The label of the preview: `RSA (2048 bits)`, `ECDSA P-256`, `Ed25519`. A key of another type shows the
    /// name of its algorithm.
    pub fn label(&self) -> String {
        match self {
            Self::Rsa(bits) => format!("RSA ({bits} bits)"),
            Self::Ecdsa(curve) => format!("ECDSA {curve}"),
            Self::Ed25519 => "Ed25519".to_owned(),
            Self::Dsa => "DSA".to_owned(),
            Self::X25519 => "X25519".to_owned(),
        }
    }
}

/// The curve and the byte length of its field for the identifier of a named curve.
fn named_curve(oid: &Oid) -> Option<&'static str> {
    if oid.is(&[1, 3, 132, 0, 33]) {
        Some("P-224")
    } else if oid.is(&[1, 2, 840, 10_045, 3, 1, 7]) {
        Some("P-256")
    } else if oid.is(&[1, 3, 132, 0, 34]) {
        Some("P-384")
    } else if oid.is(&[1, 3, 132, 0, 35]) {
        Some("P-521")
    } else {
        None
    }
}

/// The length in bytes of a coordinate of a curve.
fn coordinate_length(curve: &str) -> usize {
    match curve {
        "P-224" => 28,
        "P-256" => 32,
        "P-384" => 48,
        _ => 66,
    }
}

/// The order of the group of a curve, big-endian.
fn curve_order(curve: &str) -> &'static [u8] {
    match curve {
        "P-224" => &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x16, 0xa2, 0xe0, 0xb8,
            0xf0, 0x3e, 0x13, 0xdd, 0x29, 0x45, 0x5c, 0x5c, 0x2a, 0x3d,
        ],
        "P-256" => &[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6,
            0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ],
        "P-384" => &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
            0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
        ],
        _ => &[
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83,
            0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
            0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
        ],
    }
}

/// The key of a SubjectPublicKeyInfo: the algorithm, the whole parameters element and the key bits.
fn parse_public_key(oid: &Oid, parameters: &[u8], data: &[u8]) -> Option<PublicKey> {
    if oid.is(&[1, 2, 840, 113_549, 1, 1, 1]) {
        if parameters != [5, 0] {
            return None;
        }
        let mut der = Der(data);
        let content = der.read(SEQUENCE)?;
        let mut der = Der(content);
        let modulus = der.read_integer()?;
        let exponent = der.read_i64()?;
        if modulus.sign() <= 0 || exponent <= 0 {
            return None;
        }
        Some(PublicKey::Rsa(modulus.bit_length()))
    } else if oid.is(&[1, 2, 840, 10_045, 2, 1]) {
        let mut der = Der(parameters);
        let curve_oid = der.read_oid()?;
        let curve = named_curve(&curve_oid)?;
        let length = coordinate_length(curve);
        if data.len() != 1 + 2 * length || data[0] != 4 {
            return None;
        }
        if !super::bignum::point_on_curve(curve, &data[1..=length], &data[1 + length..]) {
            return None;
        }
        Some(PublicKey::Ecdsa(curve))
    } else if oid.is(&[1, 3, 101, 112]) {
        if !parameters.is_empty() || data.len() != 32 {
            return None;
        }
        Some(PublicKey::Ed25519)
    } else if oid.is(&[1, 3, 101, 110]) {
        if !parameters.is_empty() || data.len() != 32 {
            return None;
        }
        Some(PublicKey::X25519)
    } else if oid.is(&[1, 2, 840, 10_040, 4, 1]) {
        let mut der = Der(data);
        let y = der.read_integer()?;
        let mut parameters = Der(parameters);
        let content = parameters.read(SEQUENCE)?;
        let mut content = Der(content);
        let p = content.read_integer()?;
        let q = content.read_integer()?;
        let g = content.read_integer()?;
        if y.sign() <= 0 || p.sign() <= 0 || q.sign() <= 0 || g.sign() <= 0 {
            return None;
        }
        Some(PublicKey::Dsa)
    } else {
        None
    }
}

/// True for the public key algorithms that a certificate parser reads: RSA, DSA, ECDSA and Ed25519.
fn certificate_key_algorithm(oid: &Oid) -> Option<&'static str> {
    if oid.is(&[1, 2, 840, 113_549, 1, 1, 1]) {
        Some("RSA")
    } else if oid.is(&[1, 2, 840, 10_040, 4, 1]) {
        Some("DSA")
    } else if oid.is(&[1, 2, 840, 10_045, 2, 1]) {
        Some("ECDSA")
    } else if oid.is(&[1, 3, 101, 112]) {
        Some("Ed25519")
    } else {
        None
    }
}

/// The facts of a certificate.
#[derive(Clone, Debug)]
pub struct Certificate {
    /// The subject.
    pub subject: Name,
    /// The issuer.
    pub issuer: Name,
    /// The serial number in decimal.
    pub serial: String,
    /// The start of the validity.
    pub not_before: DateTime,
    /// The end of the validity.
    pub not_after: DateTime,
    /// The name of the signature algorithm.
    pub signature_algorithm: String,
    /// The name of the public key algorithm: `RSA`, `DSA`, `ECDSA`, `Ed25519`, or `0`.
    pub public_key_algorithm: String,
    /// The DNS names of the alternative names.
    pub dns_names: Vec<String>,
    /// The email addresses of the alternative names.
    pub email_addresses: Vec<String>,
    /// The IP addresses of the alternative names, in text form.
    pub ip_addresses: Vec<String>,
    /// True when the basic constraints say that the certificate is a certificate authority.
    pub is_ca: bool,
}

/// Read a certificate from DER bytes: one certificate and nothing after it.
pub fn parse_certificate(der: &[u8]) -> Option<Certificate> {
    let mut input = Der(der);
    let certificate = input.read_element(SEQUENCE)?;
    if !input.is_empty() {
        return None;
    }
    let mut input = Der(certificate);
    let content = input.read(SEQUENCE)?;
    let mut input = Der(content);
    let tbs_element = input.read_element(SEQUENCE)?;
    let mut tbs = Der(tbs_element);
    let tbs_content = tbs.read(SEQUENCE)?;
    let mut tbs = Der(tbs_content);

    let version = match tbs.read_optional(context_constructed(0))? {
        Some(inner) => {
            let mut inner = Der(inner);
            let value = inner.read_i64()?;
            if !inner.is_empty() {
                return None;
            }
            value
        }
        None => 0,
    };
    if version < 0 {
        return None;
    }
    let version = version + 1;
    if version > 3 {
        return None;
    }
    let serial = tbs.read_integer()?;

    let signature_inner = tbs.read_element(SEQUENCE)?;
    let signature_content = Der(signature_inner).read(SEQUENCE)?;
    let outer_signature = input.read(SEQUENCE)?;
    if outer_signature != signature_content {
        return None;
    }
    let signature_identifier = read_algorithm_identifier(signature_content)?;
    let signature_algorithm = signature_algorithm_name(&signature_identifier);

    let issuer_element = tbs.read_element(SEQUENCE)?;
    let issuer = Name::parse(issuer_element)?;
    let validity = tbs.read(SEQUENCE)?;
    let mut validity = Der(validity);
    let not_before = read_time(&mut validity)?;
    let not_after = read_time(&mut validity)?;
    let subject_element = tbs.read_element(SEQUENCE)?;
    let subject = Name::parse(subject_element)?;

    let spki_element = tbs.read_element(SEQUENCE)?;
    let spki_content = Der(spki_element).read(SEQUENCE)?;
    let mut spki = Der(spki_content);
    let key_identifier = spki.read(SEQUENCE)?;
    let key_identifier = read_algorithm_identifier(key_identifier)?;
    let key_algorithm = certificate_key_algorithm(&key_identifier.oid);
    let key_bits: BitString<'_> = spki.read_bit_string()?;
    if key_algorithm.is_some() {
        parse_public_key(&key_identifier.oid, &key_identifier.parameters, key_bits.bytes)?;
    }

    let mut certificate_facts = Certificate {
        subject,
        issuer,
        serial: serial.to_decimal(),
        not_before,
        not_after,
        signature_algorithm,
        public_key_algorithm: key_algorithm.unwrap_or("0").to_owned(),
        dns_names: Vec::new(),
        email_addresses: Vec::new(),
        ip_addresses: Vec::new(),
        is_ca: false,
    };

    if version > 1 {
        if !tbs.skip_optional(context(1)) {
            return None;
        }
        if !tbs.skip_optional(context(2)) {
            return None;
        }
        if version == 3
            && let Some(extensions) = tbs.read_optional(context_constructed(3))?
        {
            read_extensions(extensions, &mut certificate_facts)?;
        }
    }
    let mut signature_input = input;
    signature_input.read_bit_string()?;
    Some(certificate_facts)
}

/// One extension: the identifier, the critical flag and the value.
struct Extension<'a> {
    oid: Oid,
    critical: bool,
    value: &'a [u8],
}

fn read_extension(content: &[u8]) -> Option<Extension<'_>> {
    let mut der = Der(content);
    let oid = der.read_oid()?;
    let mut critical = false;
    if der.peek_tag(BOOLEAN) {
        critical = der.read_boolean()?;
    }
    let value = der.read(OCTET_STRING)?;
    Some(Extension { oid, critical, value })
}

fn read_extensions(extensions: &[u8], facts: &mut Certificate) -> Option<()> {
    let mut der = Der(extensions);
    let content = der.read(SEQUENCE)?;
    let mut list = Der(content);
    let mut seen: Vec<String> = Vec::new();
    let mut parsed: Vec<Extension<'_>> = Vec::new();
    while !list.is_empty() {
        let element = list.read(SEQUENCE)?;
        let extension = read_extension(element)?;
        let key = extension.oid.dotted();
        if seen.contains(&key) {
            return None;
        }
        seen.push(key);
        parsed.push(extension);
    }
    for extension in &parsed {
        process_extension(extension, facts)?;
    }
    Some(())
}

fn process_extension(extension: &Extension<'_>, facts: &mut Certificate) -> Option<()> {
    let id = extension.oid.0.as_slice();
    if let [2, 5, 29, last] = id {
        match last {
            15 => {
                // The key usage.
                let mut der = Der(extension.value);
                der.read_bit_string()?;
            }
            19 => {
                let mut der = Der(extension.value);
                let content = der.read(SEQUENCE)?;
                let mut der = Der(content);
                let mut is_ca = false;
                if der.peek_tag(BOOLEAN) {
                    is_ca = der.read_boolean()?;
                }
                if der.peek_tag(INTEGER) {
                    let value = der.read_i64()?;
                    if value < 0 {
                        return None;
                    }
                }
                facts.is_ca = is_ca;
            }
            17 => read_alternative_names(extension.value, facts)?,
            30 => read_name_constraints(extension.value)?,
            31 => read_crl_distribution_points(extension.value)?,
            35 => {
                if extension.critical {
                    return None;
                }
                let mut der = Der(extension.value);
                let content = der.read(SEQUENCE)?;
                let mut der = Der(content);
                if der.peek_tag(context(0)) {
                    der.read(context(0))?;
                }
            }
            36 => {
                let mut der = Der(extension.value);
                let content = der.read(SEQUENCE)?;
                let mut der = Der(content);
                if der.peek_tag(context(0)) {
                    read_tagged_i64(&mut der, context(0))?;
                }
                if der.peek_tag(context(1)) {
                    read_tagged_i64(&mut der, context(1))?;
                }
            }
            37 => {
                let mut der = Der(extension.value);
                let content = der.read(SEQUENCE)?;
                let mut der = Der(content);
                while !der.is_empty() {
                    der.read_oid()?;
                }
            }
            14 => {
                if extension.critical {
                    return None;
                }
                let mut der = Der(extension.value);
                der.read(OCTET_STRING)?;
            }
            32 => read_certificate_policies(extension.value)?,
            33 => {
                let mut der = Der(extension.value);
                let content = der.read(SEQUENCE)?;
                let mut der = Der(content);
                while !der.is_empty() {
                    let mapping = der.read(SEQUENCE)?;
                    let mut mapping = Der(mapping);
                    mapping.read(OBJECT_IDENTIFIER)?;
                    mapping.read(OBJECT_IDENTIFIER)?;
                }
            }
            54 => {
                let mut der = Der(extension.value);
                der.read_integer()?;
            }
            _ => {}
        }
    } else if extension.oid.is(&[1, 3, 6, 1, 5, 5, 7, 1, 1]) {
        if extension.critical {
            return None;
        }
        let mut der = Der(extension.value);
        let content = der.read(SEQUENCE)?;
        let mut der = Der(content);
        while !der.is_empty() {
            let access = der.read(SEQUENCE)?;
            let mut access = Der(access);
            access.read_oid()?;
            if !access.peek_tag(context(6)) {
                continue;
            }
            access.read(context(6))?;
        }
    }
    Some(())
}

/// Read an element with an implicit tag that holds an integer.
fn read_tagged_i64(der: &mut Der<'_>, tag: u8) -> Option<i64> {
    let content = der.read(tag)?;
    let mut bytes = Vec::with_capacity(content.len() + 2);
    bytes.push(INTEGER);
    bytes.push(u8::try_from(content.len()).ok()?);
    bytes.extend_from_slice(content);
    Der(&bytes).read_i64()
}

fn read_certificate_policies(value: &[u8]) -> Option<()> {
    let mut der = Der(value);
    let content = der.read(SEQUENCE)?;
    let mut der = Der(content);
    let mut seen: Vec<&[u8]> = Vec::new();
    while !der.is_empty() {
        let policy = der.read(SEQUENCE)?;
        let mut policy = Der(policy);
        let oid = policy.read(OBJECT_IDENTIFIER)?;
        if seen.contains(&oid) {
            return None;
        }
        seen.push(oid);
        Oid::from_der_content(oid)?;
    }
    Some(())
}

fn read_crl_distribution_points(value: &[u8]) -> Option<()> {
    let mut der = Der(value);
    let content = der.read(SEQUENCE)?;
    let mut list = Der(content);
    while !list.is_empty() {
        let point = list.read(SEQUENCE)?;
        let mut point = Der(point);
        let Some(name) = point.read_optional(context_constructed(0))? else {
            continue;
        };
        let mut name = Der(name);
        let inner = name.read(context_constructed(0))?;
        let mut inner = Der(inner);
        while !inner.is_empty() {
            if !inner.peek_tag(context(6)) {
                break;
            }
            inner.read(context(6))?;
        }
    }
    Some(())
}

fn read_name_constraints(value: &[u8]) -> Option<()> {
    let mut outer = Der(value);
    let toplevel = outer.read(SEQUENCE)?;
    if !outer.is_empty() {
        return None;
    }
    let mut toplevel = Der(toplevel);
    let permitted = toplevel.read_optional(context_constructed(0))?;
    let excluded = toplevel.read_optional(context_constructed(1))?;
    if !toplevel.is_empty() {
        return None;
    }
    let permitted_empty = permitted.is_none_or(<[u8]>::is_empty);
    let excluded_empty = excluded.is_none_or(<[u8]>::is_empty);
    if (permitted.is_none() && excluded.is_none()) || (permitted_empty && excluded_empty) {
        return None;
    }
    for subtrees in [permitted, excluded].into_iter().flatten() {
        let mut subtrees = Der(subtrees);
        while !subtrees.is_empty() {
            let sequence = subtrees.read(SEQUENCE)?;
            let mut sequence = Der(sequence);
            sequence.read_any()?;
        }
    }
    Some(())
}

fn read_alternative_names(value: &[u8], facts: &mut Certificate) -> Option<()> {
    let mut der = Der(value);
    let content = der.read(SEQUENCE)?;
    let mut der = Der(content);
    let mut dns = Vec::new();
    let mut emails = Vec::new();
    let mut ips = Vec::new();
    while !der.is_empty() {
        let (tag, data) = der.read_any()?;
        match tag ^ 0x80 {
            1 => {
                if !data.is_ascii() {
                    return None;
                }
                emails.push(String::from_utf8_lossy(data).into_owned());
            }
            2 => {
                if !data.is_ascii() {
                    return None;
                }
                dns.push(String::from_utf8_lossy(data).into_owned());
            }
            6 => {
                if !data.is_ascii() {
                    return None;
                }
            }
            7 => match data.len() {
                4 | 16 => ips.push(ip_text(data)),
                _ => return None,
            },
            _ => {}
        }
    }
    facts.dns_names = dns;
    facts.email_addresses = emails;
    facts.ip_addresses = ips;
    Some(())
}

/// The text of an IP address of 4 or 16 bytes. An IPv4 address and an IPv4-mapped address have the dotted
/// decimal form. Any other address has the compact form of RFC 5952.
pub fn ip_text(bytes: &[u8]) -> String {
    if bytes.len() == 4 {
        return format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
    }
    let mapped = bytes[..10].iter().all(|byte| *byte == 0) && bytes[10] == 0xff && bytes[11] == 0xff;
    if mapped {
        return format!("{}.{}.{}.{}", bytes[12], bytes[13], bytes[14], bytes[15]);
    }
    let mut groups = [0u16; 8];
    for (index, group) in groups.iter_mut().enumerate() {
        *group = u16::from(bytes[index * 2]) << 8 | u16::from(bytes[index * 2 + 1]);
    }
    // The longest run of zero groups, at least two long; the first one on a tie.
    let mut best_start = 0;
    let mut best_length = 0;
    let mut index = 0;
    while index < 8 {
        if groups[index] == 0 {
            let start = index;
            while index < 8 && groups[index] == 0 {
                index += 1;
            }
            if index - start > best_length {
                best_start = start;
                best_length = index - start;
            }
        } else {
            index += 1;
        }
    }
    if best_length < 2 {
        best_length = 0;
    }
    let mut out = String::new();
    let mut index = 0;
    while index < 8 {
        if best_length > 0 && index == best_start {
            out.push_str("::");
            index += best_length;
            continue;
        }
        if index > 0 && !(best_length > 0 && index == best_start + best_length) {
            out.push(':');
        }
        let _ = write!(out, "{:x}", groups[index]);
        index += 1;
    }
    out
}

/// The facts of a certificate request.
#[derive(Clone, Debug)]
pub struct CertificateRequest {
    /// The subject.
    pub subject: Name,
    /// The name of the signature algorithm.
    pub signature_algorithm: String,
    /// The label of the public key: the key of a known algorithm, else the name of the algorithm.
    pub public_key_label: String,
    /// The DNS names of the requested extensions.
    pub dns_names: Vec<String>,
}

/// Read a certificate request from DER bytes: one request and nothing after it.
pub fn parse_certificate_request(der: &[u8]) -> Option<CertificateRequest> {
    let mut input = Der(der);
    let content = input.read(SEQUENCE)?;
    if !input.is_empty() {
        return None;
    }
    let mut request = Der(content);
    let tbs = request.read(SEQUENCE)?;
    let signature = request.read(SEQUENCE)?;
    request.read_bit_string()?;
    let signature_identifier = {
        let mut inner = Der(signature);
        let oid = inner.read_oid()?;
        let parameters = if inner.is_empty() {
            Vec::new()
        } else {
            inner.read_any_element()?.1.to_vec()
        };
        AlgorithmIdentifier { oid, parameters }
    };
    let mut tbs = Der(tbs);
    let version = tbs.read_i32()?;
    let _ = version;
    let subject_element = tbs.read_any_element()?.1;
    let info = tbs.read(SEQUENCE)?;
    let mut info = Der(info);
    let identifier = info.read(SEQUENCE)?;
    let key_bits = info.read_bit_string()?;
    let identifier = {
        let mut inner = Der(identifier);
        let oid = inner.read_oid()?;
        let parameters = if inner.is_empty() {
            Vec::new()
        } else {
            inner.read_any_element()?.1.to_vec()
        };
        AlgorithmIdentifier { oid, parameters }
    };
    let attributes = tbs.read(context_constructed(0))?;
    let public_key_label = if certificate_key_algorithm(&identifier.oid).is_some() {
        parse_public_key(&identifier.oid, &identifier.parameters, key_bits.bytes)?.label()
    } else {
        algorithm_name(&identifier.oid)
    };
    let subject = Name::parse(subject_element)?;
    let mut dns_names = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut attributes = Der(attributes);
    while !attributes.is_empty() {
        let (attribute_tag, attribute_content) = attributes.read_any()?;
        if attribute_tag != SEQUENCE {
            continue;
        }
        let mut attribute = Der(attribute_content);
        let Some(oid) = attribute.read_oid() else { continue };
        let Some(values) = attribute.read(SET) else { continue };
        let mut values = Der(values);
        let Some((_, first, _)) = values.read_any_element() else {
            continue;
        };
        if !oid.is(&[1, 2, 840, 113_549, 1, 9, 14]) {
            continue;
        }
        let mut list = Der(first);
        let sequence = list.read(SEQUENCE)?;
        let mut sequence = Der(sequence);
        while !sequence.is_empty() {
            let element = sequence.read(SEQUENCE)?;
            let extension = read_extension(element)?;
            let key = extension.oid.dotted();
            if seen.contains(&key) {
                return None;
            }
            seen.push(key);
            if extension.oid.is(&[2, 5, 29, 17]) {
                let mut facts = Certificate {
                    subject: Name::default(),
                    issuer: Name::default(),
                    serial: String::new(),
                    not_before: DateTime {
                        year: 0,
                        month: 1,
                        day: 1,
                        hour: 0,
                        minute: 0,
                        second: 0,
                    },
                    not_after: DateTime {
                        year: 0,
                        month: 1,
                        day: 1,
                        hour: 0,
                        minute: 0,
                        second: 0,
                    },
                    signature_algorithm: String::new(),
                    public_key_algorithm: String::new(),
                    dns_names: Vec::new(),
                    email_addresses: Vec::new(),
                    ip_addresses: Vec::new(),
                    is_ca: false,
                };
                read_alternative_names(extension.value, &mut facts)?;
                dns_names = facts.dns_names;
            }
        }
    }
    Some(CertificateRequest {
        subject,
        signature_algorithm: signature_algorithm_name(&signature_identifier),
        public_key_label,
        dns_names,
    })
}

/// The bits of the modulus of an RSA private key (PKCS #1). The key must be consistent: the primes multiply to the
/// modulus and the exponents agree with each prime.
pub fn parse_pkcs1_private_key(der: &[u8]) -> Option<usize> {
    let mut input = Der(der);
    let content = input.read(SEQUENCE)?;
    if !input.is_empty() {
        return None;
    }
    let mut der = Der(content);
    let version = der.read_i32()?;
    let modulus = der.read_integer()?;
    let exponent = der.read_i32()?;
    let d = der.read_integer()?;
    let p = der.read_integer()?;
    let q = der.read_integer()?;
    let mut optional = Vec::new();
    for _ in 0..3 {
        if der.peek_tag(INTEGER) {
            optional.push(der.read_integer()?);
        }
    }
    let mut primes = vec![p, q];
    if der.peek_tag(SEQUENCE) {
        let content = der.read(SEQUENCE)?;
        let mut list = Der(content);
        while !list.is_empty() {
            let prime = list.read(SEQUENCE)?;
            let mut prime = Der(prime);
            let first = prime.read_integer()?;
            prime.read_integer()?;
            prime.read_integer()?;
            if first.sign() <= 0 {
                return None;
            }
            primes.push(first);
        }
    }
    if version > 1 {
        return None;
    }
    if modulus.sign() <= 0
        || d.sign() <= 0
        || primes[0].sign() <= 0
        || primes[1].sign() <= 0
        || optional.iter().any(|value| value.sign() <= 0)
    {
        return None;
    }
    if exponent < 2 {
        return None;
    }
    let one = Uint::from_u64(1);
    let mut product = one.clone();
    let primes: Vec<Uint> = primes
        .iter()
        .map(|prime| Uint::from_be_bytes(&prime.magnitude))
        .collect();
    for prime in &primes {
        if *prime <= one {
            return None;
        }
        product = product.mul(prime);
    }
    if product != Uint::from_be_bytes(&modulus.magnitude) {
        return None;
    }
    let exponent_times_d = Uint::from_u64(exponent as u64).mul(&Uint::from_be_bytes(&d.magnitude));
    for prime in &primes {
        if exponent_times_d.rem(&prime.sub(&one)) != one {
            return None;
        }
    }
    Some(modulus.bit_length())
}

/// The private key of an EC private key structure (SEC 1): the curve. `curve` is the curve that a wrapper gave.
fn parse_ec_private_key(der: &[u8], wrapped_curve: Option<&'static str>) -> Option<&'static str> {
    let mut input = Der(der);
    let content = input.read(SEQUENCE)?;
    let mut der = Der(content);
    let version = der.read_i32()?;
    let scalar = der.read(OCTET_STRING)?;
    let curve_oid = match der.read_optional(context_constructed(0))? {
        Some(inner) => Some(Der(inner).read_oid()?),
        None => None,
    };
    if let Some(inner) = der.read_optional(context_constructed(1))? {
        Der(inner).read_bit_string()?;
    }
    if version != 1 {
        return None;
    }
    let curve = match wrapped_curve {
        Some(curve) => curve,
        None => named_curve(&curve_oid?)?,
    };
    let order = curve_order(curve);
    let size = order.len();
    let mut scalar = scalar;
    while scalar.len() > size {
        if scalar[0] != 0 {
            return None;
        }
        scalar = &scalar[1..];
    }
    let mut padded = vec![0u8; size - scalar.len()];
    padded.extend_from_slice(scalar);
    if padded.as_slice() >= order {
        return None;
    }
    Some(curve)
}

/// Read a private key of the form `EC PRIVATE KEY`: the curve.
pub fn parse_ec_private_key_curve(der: &[u8]) -> Option<&'static str> {
    parse_ec_private_key(der, None)
}

/// Read a private key of the wrapped form (PKCS #8).
pub fn parse_pkcs8_private_key(der: &[u8]) -> Option<PublicKey> {
    let mut input = Der(der);
    let content = input.read(SEQUENCE)?;
    let mut der = Der(content);
    der.read_i32()?;
    let identifier = der.read(SEQUENCE)?;
    let identifier = read_algorithm_identifier(identifier)?;
    let private_key = der.read(OCTET_STRING)?;
    let oid = &identifier.oid;
    if oid.is(&[1, 2, 840, 113_549, 1, 1, 1]) {
        parse_pkcs1_private_key(private_key).map(PublicKey::Rsa)
    } else if oid.is(&[1, 2, 840, 10_045, 2, 1]) {
        let wrapped = Der(&identifier.parameters).read_oid().and_then(|oid| named_curve(&oid));
        parse_ec_private_key(private_key, wrapped).map(PublicKey::Ecdsa)
    } else if oid.is(&[1, 3, 101, 112]) {
        if !identifier.parameters.is_empty() {
            return None;
        }
        let seed = Der(private_key).read(OCTET_STRING)?;
        (seed.len() == 32).then_some(PublicKey::Ed25519)
    } else if oid.is(&[1, 3, 101, 110]) {
        if !identifier.parameters.is_empty() {
            return None;
        }
        let key = Der(private_key).read(OCTET_STRING)?;
        (key.len() == 32).then_some(PublicKey::X25519)
    } else {
        None
    }
}

/// Read a public key of the form `PUBLIC KEY` (SubjectPublicKeyInfo).
pub fn parse_pkix_public_key(der: &[u8]) -> Option<PublicKey> {
    let mut input = Der(der);
    let content = input.read(SEQUENCE)?;
    if !input.is_empty() {
        return None;
    }
    let mut der = Der(content);
    let identifier = der.read(SEQUENCE)?;
    let identifier = read_algorithm_identifier(identifier)?;
    let key = der.read_bit_string()?;
    parse_public_key(&identifier.oid, &identifier.parameters, key.bytes)
}

/// The name of a public key algorithm that the reader does not parse: its usual name, else the dotted identifier.
fn algorithm_name(oid: &Oid) -> String {
    let known: [(&[u64], &str); 8] = [
        (&[1, 3, 101, 110], "X25519"),
        (&[1, 3, 101, 111], "X448"),
        (&[1, 3, 101, 113], "Ed448"),
        (&[1, 2, 840, 113_549, 1, 3, 1], "DH"),
        (&[2, 16, 840, 1, 101, 3, 4, 3, 17], "ML-DSA-44"),
        (&[2, 16, 840, 1, 101, 3, 4, 3, 18], "ML-DSA-65"),
        (&[2, 16, 840, 1, 101, 3, 4, 3, 19], "ML-DSA-87"),
        (&[1, 2, 840, 113_549, 1, 1, 10], "RSA-PSS"),
    ];
    known
        .iter()
        .find(|(arcs, _)| oid.is(arcs))
        .map_or_else(|| oid.dotted(), |(_, name)| (*name).to_owned())
}

/// True when the bytes start with one element whose tag and length are valid and whose data fits in the bytes.
/// The rule is the one of a reader that takes any element: a tag with a high number is valid.
pub fn is_asn1_element(data: &[u8]) -> bool {
    let mut offset = 0;
    let Some(&first) = data.first() else {
        return false;
    };
    offset += 1;
    if first & 0x1f == 0x1f {
        let mut number: u64 = 0;
        let mut count = 0;
        loop {
            let Some(&byte) = data.get(offset) else {
                return false;
            };
            offset += 1;
            count += 1;
            if count > 4 {
                return false;
            }
            if count == 1 && byte == 0x80 {
                return false;
            }
            number = (number << 7) | u64::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                break;
            }
        }
        if number < 0x1f {
            return false;
        }
    }
    let Some(&length_byte) = data.get(offset) else {
        return false;
    };
    offset += 1;
    let length: usize = if length_byte & 0x80 == 0 {
        usize::from(length_byte & 0x7f)
    } else {
        let count = usize::from(length_byte & 0x7f);
        if count == 0 {
            return false;
        }
        let mut length: usize = 0;
        for _ in 0..count {
            let Some(&byte) = data.get(offset) else {
                return false;
            };
            offset += 1;
            if length >= 1 << 23 {
                return false;
            }
            length = (length << 8) | usize::from(byte);
            if length == 0 {
                return false;
            }
        }
        if length < 0x80 {
            return false;
        }
        length
    };
    offset + length <= data.len()
}
