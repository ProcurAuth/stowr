//! The previews of structured text and of packages (docs/PREVIEWS.md, "Structured text" and
//! "ZIP-compatible packages").
//!
//! The text formats are vCard, iCalendar and email (EML, MIME, MHTML). The key formats are certificates, certificate
//! requests and keys: a small DER reader gives their details. The reader also gives the details of PDF files.
//! The ZIP-compatible packages (ZIP, JAR, APK, XPI, CRX, VSIX, EPUB) use the reader of `crate::archive::zip`.

mod bignum;
mod certificate;
mod der;
mod email;
mod entities;
mod html;
mod metadata;
mod mime;
mod package;
mod pdf;
mod pem;
mod routes;
mod text;
mod x509;
mod xml;

#[cfg(test)]
mod certificate_tests;
#[cfg(test)]
mod email_tests;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod html_tests;
#[cfg(test)]
mod metadata_tests;
#[cfg(test)]
mod package_tests;
#[cfg(test)]
mod pdf_tests;
#[cfg(test)]
mod routes_tests;
#[cfg(test)]
mod testzip;
#[cfg(test)]
mod text_tests;

use crate::common::http::{Route, RouteAccess, route};

pub use metadata::{StructuredMetadata, inspect_structured_metadata};
pub use routes::{handle_archive_preview, handle_structured_preview};

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route(
            "/api/structured-preview",
            RouteAccess::HandlerAsks,
            handle_structured_preview,
        ),
        route("/api/archive-preview", RouteAccess::HandlerAsks, handle_archive_preview),
    ]
}
