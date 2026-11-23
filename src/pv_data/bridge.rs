//! The calls of the details to the readers of the other parts of the program: the package properties of the Office
//! Open XML files (`crate::pv_docs`) and the structured metadata (`crate::pv_structured`).
//!
//! Each call gives the container, the properties, the headers of the first answer of the storage and the size of the
//! object. When a reader gives fewer values, the details use the size of the listing and no header.

use std::collections::BTreeMap;
use std::sync::Arc;

use http::HeaderMap;

use super::text::upper;
use crate::common::ctx::OpCtx;
use crate::common::error::{CODE_NOT_SERVED, Result};
use crate::instance::Instance;
use crate::pv_media::MediaSourceMetadata;

/// The family of an Office Open XML package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OfficeFamily {
    /// Word.
    Word,
    /// Excel.
    Spreadsheet,
    /// PowerPoint.
    Presentation,
    /// Visio.
    Visio,
}

/// What another reader gives to the details.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReaderDetails {
    /// The container label.
    pub(crate) container: String,
    /// The properties by label.
    pub(crate) properties: BTreeMap<String, String>,
    /// The headers of the first answer of the storage.
    pub(crate) headers: HeaderMap,
    /// The size of the object, or 0 or less when it is not known.
    pub(crate) size: i64,
}

/// The container label of an Office Open XML extension; another extension gives its upper-case form.
pub(crate) fn office_container_label(extension: &str) -> String {
    let label = match extension.trim().to_ascii_lowercase().as_str() {
        "docx" => "Microsoft Word Open XML",
        "docm" => "Microsoft Word macro-enabled document",
        "dotx" => "Microsoft Word template",
        "dotm" => "Microsoft Word macro-enabled template",
        "xlsx" => "Microsoft Excel workbook",
        "xlsm" => "Microsoft Excel macro-enabled workbook",
        "xltx" => "Microsoft Excel template",
        "xltm" => "Microsoft Excel macro-enabled template",
        "xlam" => "Microsoft Excel add-in",
        "pptx" => "Microsoft PowerPoint presentation",
        "pptm" => "Microsoft PowerPoint macro-enabled presentation",
        "potx" => "Microsoft PowerPoint template",
        "potm" => "Microsoft PowerPoint macro-enabled template",
        "ppsx" => "Microsoft PowerPoint slide show",
        "ppsm" => "Microsoft PowerPoint macro-enabled slide show",
        "ppam" => "Microsoft PowerPoint add-in",
        "sldx" => "Microsoft PowerPoint slide",
        "sldm" => "Microsoft PowerPoint macro-enabled slide",
        "vsdx" => "Microsoft Visio drawing",
        "vsdm" => "Microsoft Visio macro-enabled drawing",
        "vssx" => "Microsoft Visio stencil",
        "vssm" => "Microsoft Visio macro-enabled stencil",
        "vstx" => "Microsoft Visio template",
        "vstm" => "Microsoft Visio macro-enabled template",
        _ => return upper(extension.trim()),
    };
    label.to_owned()
}

/// The package properties of an Office Open XML file: the central directory and the small property parts only.
pub(crate) async fn office_details(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    listed: &MediaSourceMetadata,
    family: OfficeFamily,
) -> Result<ReaderDetails> {
    let _ = family;
    let properties = crate::pv_docs::office_properties(ctx, instance, key, extension).await?;
    Ok(ReaderDetails {
        container: office_container_label(extension),
        properties,
        headers: HeaderMap::new(),
        size: listed.size,
    })
}

/// The structured metadata of an object (PDF, ZIP-compatible packages, contacts, calendars, email, certificates),
/// or `None` when the structured reader does not handle the format.
pub(crate) async fn structured_details(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    content_type: &str,
    listed: &MediaSourceMetadata,
) -> Result<Option<ReaderDetails>> {
    match crate::pv_structured::inspect_structured_metadata(ctx, instance, key, extension, content_type, listed).await {
        Ok((container, properties)) if !container.is_empty() => Ok(Some(ReaderDetails {
            container,
            properties,
            headers: HeaderMap::new(),
            size: listed.size,
        })),
        Ok(_) => Ok(None),
        Err(error) if error.has_code(CODE_NOT_SERVED) => Ok(None),
        Err(error) => Err(error),
    }
}
