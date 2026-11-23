# Previews

This document gives the rules of the previews and of the metadata that Stowr shows.

## General rules

A preview reads only deterministic, bounded structures of a format by default. An exact value that needs a complete scan
does not appear until the person starts an explicit operation. A partial inventory never shows as a complete one.

A preview never fetches a URL that it finds inside a document. Stowr sanitizes HTML-like content and blocks active SVG
content. It shows external EPUB and email resources as text only.

You can select an immutable version of an object. Then Preview, Details, Open original, Inspect and Verify integrity all use that exact version or generation of the provider.

## PDF

The PDF preview uses the local PDF.js module and its worker, a canvas that the application controls, a custom
`PDFDataRangeTransport`, and strict same-origin Range requests.

- It has no iframe, no embed, no object element and no fallback to the viewer of the browser.
- It turns off the stream and the automatic fetch of the whole file.
- The page count comes from the parsed PDF structure.
- It keeps only the current page and a small cache of the next pages.
- The controls of the page and of the zoom act on the PDF.js document.
- The viewer fits the viewport, after the application header and the PDF controls.

The binary embeds these files. Stowr never gets them at run time.

```text
src/public/assets/vendor/pdfjs/4.10.38/pdf.min.mjs
src/public/assets/vendor/pdfjs/4.10.38/pdf.worker.min.mjs
```

## Office Open XML

The metadata of Word, Excel, PowerPoint and Visio files comes from the ZIP central directory. It also comes from a few small package members: `docProps/core.xml`, `docProps/app.xml` and `docProps/custom.xml`.

The Word preview shows paragraphs, headings, lists, links and tables. The Excel preview uses the shared data grid. It loads the
workbook structures and the selected worksheet data with range-backed ZIP access. The PowerPoint and Visio previews show
deterministic metadata. They do not draw the pages.

The row and column totals of a worksheet need a full scan of the active sheet. They appear only after the person runs the scan.

## Tabular data

Delimited text, Excel worksheets, SQLite, JSON lines (JSONL and NDJSON) and Parquet use one shared grid. The grid has these
rules:

- The filters, the sort, the pages, and the states for load, empty and error are the same for each format.
- A number is right-aligned.
- The size of a page is bounded.
- The grid uses the full available width.
- The initial display never loads a whole data set.

A SQLite preview reads the pages of the remote database with exact ranges. Stowr never shows an unknown row total as zero.

## JSON

The raw, beautified, summary and tree views are separate modes. An exact total of lines or pages appears only after the person
runs a complete count. The tree mode has no count action. After a count, the page shows the exact totals and no other status
label.

## Structured text

The structured viewer covers these formats: vCard (VCF), iCalendar (ICS and IFB), email (EML, MIME and MHTML), certificates, certificate requests, public keys and private keys. It also shows the related deterministic metadata.

A certificate or key preview gives structured fields and a Raw tab. It shows binary content as Base64. The raw content of a
private key is visible on purpose. It never goes to a third party.

Stowr does not inject the HTML of an email as active content. It lists the attachments. It does not decode them and it does
not fetch external resources automatically.

## Images, audio and video

The image preview uses the local image viewer for the formats that the browser supports. Stowr serves an SVG with strict
security headers. Audio and video use the same-origin object gateway and `preload="metadata"`. The codecs that play depend on
the browser.

## ZIP-compatible packages

ZIP, JAR, WAR, EAR, APK, AAR, XPI, CRX, VSIX and EPUB files use the exact central directory. The preview shows the
deterministic package or publication information and the complete Contents table.

The Contents table scrolls vertically with the page. It scrolls horizontally only when it needs to. You can open, download,
verify or select each entry for extraction. Stowr follows no URL that an archive or an EPUB holds.

Stowr makes no partial inventory of a format that has no deterministic central directory, such as TAR, RAR or 7z.

## Integrity of one object

Verify integrity streams a complete object when the person clicks the button. It reports the SHA-256 and the hashes of the
provider for comparison. It keeps no object bytes. When the provider gives a composite value, Stowr shows it but does not
compare it with a whole-object digest. The action is in the Advanced tab of Details. It starts only after an explicit click,
and it shows its result in that tab.

Stowr has no global checksum export and no global duplicate scan.

## Technical inspection

Inspect is in the Advanced tab of Details. It starts only after an explicit click, and it shows its result in that tab. It reads
the deterministic metadata of the object, the first 64 KiB and, when useful, the last 64 KiB. It reports these things:

- the declared and the detected MIME type;
- the safe headers and the checksums of the provider;
- the structural markers that it recognizes;
- bounded hexadecimal and ASCII probes;
- the exact count of provider requests and of bytes that it used.

Stowr removes the headers that carry credentials before the answer reaches the interface.
