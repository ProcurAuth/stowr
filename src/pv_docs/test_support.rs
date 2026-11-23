//! The helpers of the tests of this folder: an application over the memory back end and a call of a route.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use bytes::Bytes;
use http::{HeaderMap, Method};

use crate::access::AccessLayer;
use crate::common::app::App;
use crate::common::config::Config;
use crate::common::ctx::OpCtx;
use crate::common::http::{Req, Response, empty, read_limited};
use crate::common::query::Query;
use crate::instance::Instance;
use crate::testkit::{MemoryBackend, read_write_backend, read_write_instance};

/// An application over instances, in the mode `open`.
pub fn application(instances: Vec<Arc<Instance>>) -> Arc<App> {
    let config = Config::default();
    let access = AccessLayer::new(&config).unwrap();
    Arc::new(App {
        config: Arc::new(config),
        instances,
        auths: BTreeMap::new(),
        jobs: crate::jobs::JobManager::new(Weak::new(), 10),
        uploads: crate::uploads::UploadManager::new(),
        sqlite: crate::pv_data::SqliteSessions::new(),
        access,
        resume_token_key: [0; 32],
    })
}

/// The test application: the instance `rw` (root prefix `tenant/`) over a memory back end.
pub fn setup() -> (Arc<App>, Arc<MemoryBackend>) {
    let backend = read_write_backend();
    let instance = read_write_instance(backend.clone());
    (application(vec![instance]), backend)
}

/// Put an object of the instance `rw`.
pub fn put(backend: &MemoryBackend, key: &str, data: impl Into<Bytes>, content_type: &str) {
    backend.insert(&format!("tenant/{key}"), data, content_type);
}

/// The answer of a call: the status and the body.
pub struct Called {
    /// The status.
    pub status: u16,
    /// The body.
    pub bytes: Bytes,
    /// The headers.
    pub headers: HeaderMap,
}

impl Called {
    /// The body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// The body as JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.bytes).unwrap_or(serde_json::Value::Null)
    }

    /// The body as a value of a type. The status must be 200.
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> T {
        assert_eq!(self.status, 200, "unexpected status: {}", self.text());
        serde_json::from_slice(&self.bytes).unwrap()
    }

    /// The code of the error object, or an empty text.
    pub fn code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap_or("").to_owned()
    }

    /// The message of the error object, or an empty text.
    pub fn message(&self) -> String {
        self.json()["error"]["message"].as_str().unwrap_or("").to_owned()
    }
}

/// Call a route of this folder with a method and a target (`/api/json/raw?instance=rw&key=a.json`).
pub async fn call_with(app: &Arc<App>, method: &str, target: &str) -> Called {
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let request = Req {
        method: Method::from_bytes(method.as_bytes()).unwrap(),
        path: path.to_owned(),
        raw_query: raw_query.to_owned(),
        query: Query::parse(raw_query),
        headers: HeaderMap::new(),
        body: empty(),
        ctx: OpCtx::default(),
        host: "localhost".to_owned(),
    };
    let route = super::routes()
        .into_iter()
        .find(|route| route.pattern == path)
        .unwrap_or_else(|| panic!("no route {path}"));
    let response: Response = (route.handler)(Arc::clone(app), request).await;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let (bytes, _) = read_limited(response.into_body(), usize::MAX).await.unwrap();
    Called { status, bytes, headers }
}

/// Call a route with `GET`.
pub async fn get(app: &Arc<App>, target: &str) -> Called {
    call_with(app, "GET", target).await
}

/// Check that each range is a closed range: `bytes=<start>-<end>`.
pub fn require_exact_byte_ranges(ranges: &[String]) {
    assert!(!ranges.is_empty(), "expected at least one byte-range request");
    for value in ranges {
        let rest = value
            .strip_prefix("bytes=")
            .unwrap_or_else(|| panic!("range {value:?} is not an exact byte range"));
        let (start, end) = rest
            .split_once('-')
            .unwrap_or_else(|| panic!("range {value:?} is open-ended or malformed"));
        let start: i64 = start.parse().unwrap_or_else(|_| panic!("range {value:?} is invalid"));
        let end: i64 = end.parse().unwrap_or_else(|_| panic!("range {value:?} is invalid"));
        assert!(start >= 0 && end >= start, "range {value:?} is invalid");
    }
}

/// The start of an exact range.
pub fn exact_range_start(value: &str) -> i64 {
    require_exact_byte_ranges(&[value.to_owned()]);
    value
        .strip_prefix("bytes=")
        .unwrap()
        .split_once('-')
        .unwrap()
        .0
        .parse()
        .unwrap()
}

/// The last character of the token with a change: the token is not valid any more.
pub fn mutate_cursor(value: &str) -> String {
    let Some(last) = value.chars().last() else {
        return "x".to_owned();
    };
    let replacement = if last == 'A' { 'B' } else { 'A' };
    format!("{}{replacement}", &value[..value.len() - last.len_utf8()])
}

/// The text of a value as a component of a query.
pub fn escape(value: &str) -> String {
    crate::common::query::query_escape(value)
}

/// A ZIP archive in memory. Each entry is stored, or deflated when `deflate` is true.
pub fn zip_bytes(entries: &[(&str, &str)], deflate: bool) -> Vec<u8> {
    use std::io::Write;

    fn put_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }
    fn put_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    for (name, data) in entries {
        let bytes = data.as_bytes();
        let mut crc = flate2::Crc::new();
        crc.update(bytes);
        let (method, body): (u16, Vec<u8>) = if deflate {
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(bytes).unwrap();
            (8, encoder.finish().unwrap())
        } else {
            (0, bytes.to_vec())
        };
        let offset = u32::try_from(out.len()).unwrap();
        put_u32(&mut out, 0x0403_4b50);
        put_u16(&mut out, 20);
        put_u16(&mut out, 0);
        put_u16(&mut out, method);
        put_u16(&mut out, 0);
        put_u16(&mut out, 0x21);
        put_u32(&mut out, crc.sum());
        put_u32(&mut out, u32::try_from(body.len()).unwrap());
        put_u32(&mut out, u32::try_from(bytes.len()).unwrap());
        put_u16(&mut out, u16::try_from(name.len()).unwrap());
        put_u16(&mut out, 0);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&body);
        put_u32(&mut central, 0x0201_4b50);
        put_u16(&mut central, 20);
        put_u16(&mut central, 20);
        put_u16(&mut central, 0);
        put_u16(&mut central, method);
        put_u16(&mut central, 0);
        put_u16(&mut central, 0x21);
        put_u32(&mut central, crc.sum());
        put_u32(&mut central, u32::try_from(body.len()).unwrap());
        put_u32(&mut central, u32::try_from(bytes.len()).unwrap());
        put_u16(&mut central, u16::try_from(name.len()).unwrap());
        put_u16(&mut central, 0);
        put_u16(&mut central, 0);
        put_u16(&mut central, 0);
        put_u16(&mut central, 0);
        put_u32(&mut central, 0);
        put_u32(&mut central, offset);
        central.extend_from_slice(name.as_bytes());
    }
    let central_offset = u32::try_from(out.len()).unwrap();
    let count = u16::try_from(entries.len()).unwrap();
    out.extend_from_slice(&central);
    put_u32(&mut out, 0x0605_4b50);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    put_u16(&mut out, count);
    put_u16(&mut out, count);
    put_u32(&mut out, u32::try_from(central.len()).unwrap());
    put_u32(&mut out, central_offset);
    put_u16(&mut out, 0);
    out
}

/// The workbook of the tests: the sheets `Data` and `Archive` (hidden).
pub fn test_workbook() -> Vec<u8> {
    zip_bytes(
        &[
            (
                "[Content_Types].xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
</Types>"#,
            ),
            (
                "xl/workbook.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Data" sheetId="1" r:id="rId1"/>
    <sheet name="Archive" sheetId="2" state="hidden" r:id="rId2"/>
  </sheets>
</workbook>"#,
            ),
            (
                "xl/_rels/workbook.xml.rels",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
</Relationships>"#,
            ),
            (
                "xl/sharedStrings.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="4" uniqueCount="4">
  <si><t>alpha</t></si><si><t>beta</t></si><si><t>gamma</t></si><si><t>archived</t></si>
</sst>"#,
            ),
            (
                "xl/styles.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cellXfs count="1"><xf numFmtId="0"/></cellXfs></styleSheet>"#,
            ),
            (
                "xl/worksheets/sheet1.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
  <row r="2"><c r="A2" t="s"><v>0</v></c><c r="B2"><v>10</v></c></row>
  <row r="3"><c r="A3" t="inlineStr"><is><t></t></is></c></row>
  <row r="4"><c r="A4" t="s"><v>1</v></c><c r="B4"><v>20</v></c></row>
  <row r="5"><c r="A5" t="s"><v>2</v></c><c r="B5"><v>3</v></c><c r="D5"></c></row>
</sheetData></worksheet>"#,
            ),
            (
                "xl/worksheets/sheet2.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
  <row r="1"><c r="A1" t="s"><v>3</v></c></row>
</sheetData></worksheet>"#,
            ),
        ],
        true,
    )
}
