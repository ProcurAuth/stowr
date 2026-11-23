// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Parquet preview (`/api/parquet`) and the Parquet summary of the details: the footer (`PAR1` and the length of
//! the metadata), then the `FileMetaData` in the Thrift compact protocol. The preview gives the version, the rows,
//! the schema (at most 20,000 fields), the row groups (at most 10,000) and the creator; it decodes no data page
//! (docs/PREVIEWS.md, "Parquet").

use std::sync::Arc;

use bytes::Bytes;
use serde::Serialize;

use super::thrift::{BINARY, CompactReader, LIST, STOP, STRUCT, ThriftError, ThriftResult};
use crate::common::app::App;
use crate::common::config::PERMISSION_READ;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{self, Req, Response};
use crate::instance::Instance;
use crate::instance::range::RangeSource;
use crate::pv_docs::util::lossy_bytes;

/// The largest metadata of a footer: 128 MiB.
pub(crate) const MAX_METADATA_BYTES: i64 = 128 << 20;
/// The number of schema fields of a preview.
pub(crate) const MAX_SCHEMA_FIELDS: usize = 20_000;
/// The number of row groups of a preview.
pub(crate) const MAX_ROW_GROUPS: usize = 10_000;

/// One field of the schema, with its dotted path.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct SchemaField {
    /// The dotted path.
    pub(crate) path: String,
    /// The name.
    pub(crate) name: String,
    /// The physical type, or `GROUP`.
    #[serde(rename = "physicalType", skip_serializing_if = "String::is_empty")]
    pub(crate) physical_type: String,
    /// The converted type.
    #[serde(rename = "logicalType", skip_serializing_if = "String::is_empty")]
    pub(crate) logical_type: String,
    /// The repetition.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) repetition: String,
    /// The number of children.
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub(crate) children: usize,
    /// The length of a fixed-length type.
    #[serde(rename = "typeLength", skip_serializing_if = "is_zero")]
    pub(crate) type_length: i64,
    /// The precision of a decimal.
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) precision: i64,
    /// The scale of a decimal.
    #[serde(skip_serializing_if = "is_zero")]
    pub(crate) scale: i64,
}

/// One row group.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct RowGroupInfo {
    /// The index in the footer.
    pub(crate) index: usize,
    /// The rows.
    pub(crate) rows: i64,
    /// The column chunks.
    pub(crate) columns: usize,
    /// The uncompressed bytes.
    #[serde(rename = "uncompressedBytes", skip_serializing_if = "is_zero")]
    pub(crate) uncompressed_bytes: i64,
    /// The compressed bytes.
    #[serde(rename = "compressedBytes", skip_serializing_if = "is_zero")]
    pub(crate) compressed_bytes: i64,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}

/// The answer of `/api/parquet`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct PreviewAnswer {
    /// The id of the instance.
    pub(crate) instance: String,
    /// The key.
    pub(crate) key: String,
    /// The version of the format.
    pub(crate) version: i64,
    /// The rows of the file.
    pub(crate) rows: i64,
    /// The top-level columns.
    pub(crate) columns: usize,
    /// The creator.
    #[serde(rename = "createdBy", skip_serializing_if = "String::is_empty")]
    pub(crate) created_by: String,
    /// The fields of the schema, or `null` for an empty schema.
    pub(crate) schema: Option<Vec<SchemaField>>,
    /// The row groups, or `null` when there is none.
    #[serde(rename = "rowGroups")]
    pub(crate) row_groups: Option<Vec<RowGroupInfo>>,
    /// The number of row groups in the footer.
    #[serde(rename = "rowGroupCount")]
    pub(crate) row_group_count: usize,
    /// True when the schema has more fields than the preview shows.
    #[serde(rename = "schemaTruncated", skip_serializing_if = "std::ops::Not::not")]
    pub(crate) schema_truncated: bool,
    /// True when the footer has more row groups than the preview shows.
    #[serde(rename = "rowGroupsTruncated", skip_serializing_if = "std::ops::Not::not")]
    pub(crate) row_groups_truncated: bool,
    /// The bytes of the metadata.
    #[serde(rename = "metadataBytes")]
    pub(crate) metadata_bytes: i64,
    /// The bytes read from the storage.
    #[serde(rename = "storageBytes")]
    pub(crate) storage_bytes: i64,
    /// The requests to the storage.
    #[serde(rename = "storageRequests")]
    pub(crate) storage_requests: u64,
    /// Always false: the preview decodes no data page.
    #[serde(rename = "dataRowsDecoded")]
    pub(crate) data_rows_decoded: bool,
}

/// One element of the schema as the footer gives it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SchemaElement {
    pub(crate) name: String,
    pub(crate) physical_type: Option<i64>,
    pub(crate) type_length: i64,
    pub(crate) repetition: Option<i64>,
    pub(crate) children: usize,
    pub(crate) converted_type: Option<i64>,
    pub(crate) scale: i64,
    pub(crate) precision: i64,
}

/// The values of a `FileMetaData` that the previews use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct MetadataDetail {
    pub(crate) version: i64,
    pub(crate) rows: i64,
    pub(crate) created_by: String,
    pub(crate) schema: Vec<SchemaElement>,
    pub(crate) row_groups: Vec<RowGroupInfo>,
    pub(crate) group_count: usize,
}

/// The rows and the top-level columns of a file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Summary {
    pub(crate) rows: i64,
    pub(crate) columns: usize,
}

/// Read a `FileMetaData`. The error text is the message of the answer.
pub(crate) fn parse_metadata_detail(data: &[u8]) -> ThriftResult<MetadataDetail> {
    let mut reader = CompactReader::new(data);
    let mut detail = MetadataDetail::default();
    let mut last = 0;
    loop {
        let (field_id, field_type, next_last) = reader.field_header(last)?;
        if field_type == STOP {
            break;
        }
        last = next_last;
        match field_id {
            1 => detail.version = reader.read_integer(field_type)?,
            2 => {
                if field_type != LIST {
                    return Err(ThriftError::new("unexpected Parquet schema field type"));
                }
                let (size, element_type) = reader.collection_header()?;
                if element_type != STRUCT {
                    return Err(ThriftError::new("unexpected Parquet schema element type"));
                }
                if size > MAX_SCHEMA_FIELDS * 2 {
                    return Err(ThriftError::new("Parquet schema contains too many fields"));
                }
                detail.schema = Vec::with_capacity(size.min(MAX_SCHEMA_FIELDS + 1));
                for _ in 0..size {
                    let element = read_schema_element(&mut reader)?;
                    if detail.schema.len() < MAX_SCHEMA_FIELDS + 1 {
                        detail.schema.push(element);
                    }
                }
            }
            3 => detail.rows = reader.read_integer(field_type)?,
            4 => {
                if field_type != LIST {
                    return Err(ThriftError::new("unexpected Parquet row-group field type"));
                }
                let (size, element_type) = reader.collection_header()?;
                detail.group_count = size;
                if size > reader.remaining() {
                    return Err(ThriftError::unexpected_end());
                }
                for index in 0..size {
                    if element_type != STRUCT {
                        reader.skip_value(element_type, true)?;
                        continue;
                    }
                    let group = read_row_group(&mut reader, index)?;
                    if detail.row_groups.len() < MAX_ROW_GROUPS {
                        detail.row_groups.push(group);
                    }
                }
            }
            6 => {
                if field_type != BINARY {
                    reader.skip(field_type)?;
                    continue;
                }
                detail.created_by = lossy_bytes(reader.read_binary(4096)?);
            }
            _ => reader.skip(field_type)?,
        }
    }
    if detail.rows < 0 {
        return Err(ThriftError::new("Parquet metadata contains an invalid row count"));
    }
    Ok(detail)
}

fn read_schema_element(reader: &mut CompactReader<'_>) -> ThriftResult<SchemaElement> {
    let mut element = SchemaElement::default();
    let mut last = 0;
    loop {
        let (field_id, field_type, next_last) = reader.field_header(last)?;
        if field_type == STOP {
            return Ok(element);
        }
        last = next_last;
        match field_id {
            1 => element.physical_type = Some(reader.read_integer(field_type)?),
            2 => element.type_length = reader.read_integer(field_type)?,
            3 => element.repetition = Some(reader.read_integer(field_type)?),
            4 => {
                if field_type != BINARY {
                    return Err(ThriftError::new("unexpected Parquet schema name type"));
                }
                element.name = lossy_bytes(reader.read_binary(16 << 10)?);
            }
            5 => {
                let value = reader.read_integer(field_type)?;
                if value < 0 || value > MAX_SCHEMA_FIELDS as i64 {
                    return Err(ThriftError::new("Parquet schema contains an invalid child count"));
                }
                element.children = value as usize;
            }
            6 => element.converted_type = Some(reader.read_integer(field_type)?),
            7 => element.scale = reader.read_integer(field_type)?,
            8 => element.precision = reader.read_integer(field_type)?,
            _ => reader.skip(field_type)?,
        }
    }
}

fn read_row_group(reader: &mut CompactReader<'_>, index: usize) -> ThriftResult<RowGroupInfo> {
    let mut group = RowGroupInfo {
        index,
        ..RowGroupInfo::default()
    };
    let mut last = 0;
    loop {
        let (field_id, field_type, next_last) = reader.field_header(last)?;
        if field_type == STOP {
            return Ok(group);
        }
        last = next_last;
        match field_id {
            1 => {
                if field_type != LIST {
                    return Err(ThriftError::new("unexpected Parquet column-chunk list type"));
                }
                let (size, element_type) = reader.collection_header()?;
                group.columns = size;
                if size > reader.remaining() {
                    return Err(ThriftError::unexpected_end());
                }
                for _ in 0..size {
                    reader.skip_value(element_type, true)?;
                }
            }
            2 => group.uncompressed_bytes = reader.read_integer(field_type)?,
            3 => group.rows = reader.read_integer(field_type)?,
            6 => group.compressed_bytes = reader.read_integer(field_type)?,
            _ => reader.skip(field_type)?,
        }
    }
}

/// The name of a physical type: `GROUP` without a type, `TYPE_n` for an unknown type.
fn physical_type_name(element: &SchemaElement) -> String {
    const NAMES: [&str; 8] = [
        "BOOLEAN",
        "INT32",
        "INT64",
        "INT96",
        "FLOAT",
        "DOUBLE",
        "BYTE_ARRAY",
        "FIXED_LEN_BYTE_ARRAY",
    ];
    match element.physical_type {
        None => "GROUP".to_owned(),
        Some(value) => usize::try_from(value)
            .ok()
            .and_then(|index| NAMES.get(index))
            .map_or_else(|| format!("TYPE_{value}"), |name| (*name).to_owned()),
    }
}

/// The name of a repetition, or an empty text without one.
fn repetition_name(element: &SchemaElement) -> String {
    match element.repetition {
        None => String::new(),
        Some(0) => "REQUIRED".to_owned(),
        Some(1) => "OPTIONAL".to_owned(),
        Some(2) => "REPEATED".to_owned(),
        Some(other) => format!("REPETITION_{other}"),
    }
}

/// The name of a converted type, or an empty text without one.
fn converted_type_name(element: &SchemaElement) -> String {
    const NAMES: [&str; 22] = [
        "UTF8",
        "MAP",
        "MAP_KEY_VALUE",
        "LIST",
        "ENUM",
        "DECIMAL",
        "DATE",
        "TIME_MILLIS",
        "TIME_MICROS",
        "TIMESTAMP_MILLIS",
        "TIMESTAMP_MICROS",
        "UINT_8",
        "UINT_16",
        "UINT_32",
        "UINT_64",
        "INT_8",
        "INT_16",
        "INT_32",
        "INT_64",
        "JSON",
        "BSON",
        "INTERVAL",
    ];
    match element.converted_type {
        None => String::new(),
        Some(value) => usize::try_from(value)
            .ok()
            .and_then(|index| NAMES.get(index))
            .map_or_else(|| format!("LOGICAL_{value}"), |name| (*name).to_owned()),
    }
}

/// The fields of the schema in depth-first order, without the root, with their dotted paths. The flag is true when
/// the preview does not show each field: the list stops at 20,000 fields, or the children do not match the elements.
pub(crate) fn flatten_schema(elements: &[SchemaElement]) -> (Option<Vec<SchemaField>>, bool) {
    let Some(root) = elements.first() else {
        return (None, false);
    };
    let mut fields = Vec::with_capacity((elements.len() - 1).min(MAX_SCHEMA_FIELDS));
    let mut index = 1;
    let mut stack: Vec<(String, usize)> = vec![(String::new(), root.children)];
    let mut complete = true;
    while let Some((parent, remaining)) = stack.last_mut() {
        if *remaining == 0 {
            stack.pop();
            continue;
        }
        *remaining -= 1;
        let Some(element) = elements.get(index) else {
            complete = false;
            break;
        };
        index += 1;
        let name = element.name.trim();
        let path = if parent.is_empty() {
            name.to_owned()
        } else if name.is_empty() {
            parent.clone()
        } else {
            format!("{parent}.{name}")
        };
        if fields.len() < MAX_SCHEMA_FIELDS {
            fields.push(SchemaField {
                path: path.clone(),
                name: name.to_owned(),
                physical_type: physical_type_name(element),
                logical_type: converted_type_name(element),
                repetition: repetition_name(element),
                children: element.children,
                type_length: element.type_length,
                precision: element.precision,
                scale: element.scale,
            });
        }
        stack.push((path, element.children));
    }
    let truncated = !complete || index < elements.len() || elements.len() - 1 > MAX_SCHEMA_FIELDS;
    (Some(fields), truncated)
}

/// The number of top-level columns: the children of the root.
pub(crate) fn top_level_columns(elements: &[SchemaElement]) -> usize {
    elements.first().map_or(0, |root| root.children)
}

/// The rows and the top-level columns of a `FileMetaData`.
pub(crate) fn parse_file_metadata(data: &[u8]) -> ThriftResult<Summary> {
    let detail = parse_metadata_detail(data)?;
    Ok(Summary {
        rows: detail.rows,
        columns: top_level_columns(&detail.schema),
    })
}

/// Read a `FileMetaData` on a thread for blocking work: a footer can have 128 MiB. A failed read gives
/// `422 invalid_parquet_metadata` with the message of the reader.
async fn parse_blocking<T: Send + 'static>(metadata: Bytes, parse: fn(&[u8]) -> ThriftResult<T>) -> Result<T> {
    tokio::task::spawn_blocking(move || parse(&metadata))
        .await
        .map_err(|error| Error::internal(format!("read of the Parquet metadata: {error}")))?
        .map_err(|error| Error::api(422, "invalid_parquet_metadata", error.to_string()))
}

/// Read the footer of a file: the length of the metadata after the check of `PAR1`. `limit_message` is the message
/// of a length that is not valid.
async fn read_footer(source: &RangeSource, limit_message: &str) -> Result<(i64, Bytes)> {
    let footer = source.read_suffix(8).await?;
    if footer.len() != 8 || &footer[4..] != b"PAR1" {
        return Err(Error::api(
            422,
            "invalid_parquet",
            "the object is not a valid Parquet file",
        ));
    }
    let metadata_length = i64::from(u32::from_le_bytes([footer[0], footer[1], footer[2], footer[3]]));
    let size = source.size_or_zero();
    if metadata_length <= 0 || metadata_length > MAX_METADATA_BYTES || size < metadata_length + 8 {
        return Err(Error::api(422, "invalid_parquet_metadata", limit_message));
    }
    let metadata = read_exact_range(source, size - 8 - metadata_length, metadata_length).await?;
    Ok((metadata_length, metadata))
}

/// Read a range that must be complete: fewer bytes than the range is an error of the read.
pub(crate) async fn read_exact_range(source: &RangeSource, start: i64, length: i64) -> Result<Bytes> {
    let known = source.size_or_zero();
    let data = source.read_range(start, length).await?;
    let expected = if known > 0 { length.min(known - start) } else { length };
    if (known > 0 && start >= known) || (data.len() as i64) < expected {
        return Err(super::sqlite::unexpected_end());
    }
    Ok(data)
}

/// Read the preview of a Parquet file.
pub(crate) async fn read_preview(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    known_size: i64,
    expected_etag: &str,
) -> Result<PreviewAnswer> {
    let mut answer = PreviewAnswer {
        instance: instance.cfg.id.clone(),
        key: key.to_owned(),
        ..PreviewAnswer::default()
    };
    let mut source = RangeSource::open(ctx, instance, key).await?;
    source.set_known_size(known_size);
    source.set_expected_etag(expected_etag);
    let (metadata_length, metadata) = read_footer(
        &source,
        "the Parquet footer metadata length is invalid or exceeds the preview limit",
    )
    .await?;
    let detail = parse_blocking(metadata, parse_metadata_detail).await?;
    let (schema, truncated) = flatten_schema(&detail.schema);
    answer.version = detail.version;
    answer.rows = detail.rows;
    answer.columns = top_level_columns(&detail.schema);
    answer.schema = schema;
    answer.created_by = detail.created_by;
    answer.row_groups_truncated = detail.group_count > detail.row_groups.len();
    answer.row_groups = (!detail.row_groups.is_empty()).then_some(detail.row_groups);
    answer.row_group_count = detail.group_count;
    answer.schema_truncated = truncated;
    answer.metadata_bytes = metadata_length;
    let (requests, bytes) = source.counters();
    answer.storage_bytes = bytes;
    answer.storage_requests = requests;
    Ok(answer)
}

/// The rows and the columns of a file for the details, with the headers and the size of the object.
pub(crate) async fn inspect_summary(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    known_size: i64,
) -> Result<(Summary, ::http::HeaderMap, i64)> {
    let mut source = RangeSource::open(ctx, instance, key).await?;
    source.set_known_size(known_size);
    let (_, metadata) = read_footer(&source, "the Parquet footer metadata length is invalid").await?;
    let summary = parse_blocking(metadata, parse_file_metadata).await?;
    Ok((summary, source.headers(), source.size_or_zero()))
}

/// Read the size of the query: an empty text gives 0, another text must be an integer from 0.
pub(crate) fn parse_optional_size(raw: &str) -> Result<i64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(0);
    }
    match crate::pv_docs::util::parse_integer(raw) {
        (value, true) if value >= 0 => Ok(value),
        _ => Err(Error::api(400, "invalid_size", "size must be a non-negative integer")),
    }
}

/// The route `/api/parquet`.
async fn parquet_route(app: Arc<App>, req: Req) -> Response {
    if req.method != ::http::Method::GET {
        return http::method_not_allowed(&["GET"]);
    }
    let instance = match app.instance_of("", req.query.get("instance")) {
        Ok(instance) => instance.clone(),
        Err(error) => return http::api_error(&error),
    };
    if let Err(error) = instance.require_permission(PERMISSION_READ) {
        return http::api_error(&error);
    }
    let key = req.query.get("key").trim_start_matches('/').to_owned();
    if key.is_empty() {
        return http::api_error(&Error::api(400, "missing_key", "key is required"));
    }
    if let Err(error) = crate::access::authorize_read(&app, &req.ctx, &instance, &key).await {
        return http::api_error(&error);
    }
    let known_size = match parse_optional_size(req.query.get("size")) {
        Ok(size) => size,
        Err(error) => return http::api_error(&error),
    };
    match read_preview(&req.ctx, &instance, &key, known_size, req.query.get("etag")).await {
        Ok(answer) => http::json(200, &answer),
        Err(error) => http::api_error(&error),
    }
}

/// The handler of `/api/parquet`.
pub fn handle_parquet(app: Arc<App>, req: Req) -> crate::common::BoxFuture<'static, Response> {
    Box::pin(parquet_route(app, req))
}
