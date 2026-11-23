//! The details of a PDF file from its first bytes and its last bytes. They are the version, the page count,
//! the information dictionary and a few flags. The readers look for text patterns and parse no object tree.

use std::collections::BTreeMap;

use super::text::lossy;

/// The most `/Type /Pages` markers that the page count reads. Each marker costs a search in a bounded window.
const MAX_PAGES_MARKERS: usize = 4096;

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let Some((&first, rest)) = needle.split_first() else {
        return Some(0);
    };
    let mut from = 0;
    while from < haystack.len() {
        let offset = haystack[from..].iter().position(|byte| *byte == first)?;
        let start = from + offset;
        if haystack[start + 1..].starts_with(rest) {
            return Some(start);
        }
        from = start + 1;
    }
    None
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_spaces(data: &[u8], mut index: usize) -> usize {
    while index < data.len() && is_space(data[index]) {
        index += 1;
    }
    index
}

fn skip_digits(data: &[u8], mut index: usize) -> usize {
    while index < data.len() && data[index].is_ascii_digit() {
        index += 1;
    }
    index
}

/// The version of the header `%PDF-<digits>.<digits>`.
fn header_version(prefix: &[u8]) -> Option<String> {
    let marker = b"%PDF-";
    let mut from = 0;
    while let Some(offset) = find(&prefix[from..], marker) {
        let start = from + offset + marker.len();
        let major_end = skip_digits(prefix, start);
        if major_end > start && prefix.get(major_end) == Some(&b'.') {
            let minor_end = skip_digits(prefix, major_end + 1);
            if minor_end > major_end + 1 {
                return Some(String::from_utf8_lossy(&prefix[start..minor_end]).into_owned());
            }
        }
        from += offset + 1;
    }
    None
}

/// The `/Type /Pages` markers: the start and the end of each, without overlap, at most `limit`.
fn pages_markers(data: &[u8], limit: usize) -> Vec<(usize, usize)> {
    let mut markers = Vec::new();
    let mut from = 0;
    let first = b"/Type";
    while markers.len() < limit {
        let Some(offset) = find(&data[from..], first) else {
            break;
        };
        let start = from + offset;
        let after = skip_spaces(data, start + first.len());
        let pages = b"/Pages";
        if data[after..].starts_with(pages) {
            let end = after + pages.len();
            if data.get(end).is_none_or(|byte| !is_word(*byte)) {
                markers.push((start, end));
                from = end;
                continue;
            }
        }
        from = start + 1;
    }
    markers
}

/// The start of each copy of a needle in the data, in order. Two copies can overlap.
fn positions(data: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = find(&data[from..], needle) {
        found.push(from + offset);
        from += offset + 1;
    }
    found
}

/// The numbers of the matches `/Count <digits>` in `data[start..end]`, from the positions of `/Count` in the data.
/// A match does not overlap the match before it, and its digits stop at `end`.
fn counts_in(data: &[u8], count_positions: &[usize], start: usize, end: usize) -> Vec<i64> {
    let marker_length = b"/Count".len();
    let mut counts = Vec::new();
    let mut from = start;
    let first = count_positions.partition_point(|position| *position < start);
    for &position in &count_positions[first..] {
        if position + marker_length > end {
            break;
        }
        if position < from {
            continue;
        }
        let after = position + marker_length;
        let mut digits_start = after;
        while digits_start < end && is_space(data[digits_start]) {
            digits_start += 1;
        }
        if digits_start > after {
            let mut digits_end = digits_start;
            while digits_end < end && data[digits_end].is_ascii_digit() {
                digits_end += 1;
            }
            if digits_end > digits_start {
                if let Ok(value) = String::from_utf8_lossy(&data[digits_start..digits_end]).parse::<i64>() {
                    counts.push(value);
                }
                from = digits_end;
                continue;
            }
        }
        from = position + 1;
    }
    counts
}

/// The page count that the page tree markers give. Zero when no marker gives a count.
pub fn page_count(data: &[u8]) -> i64 {
    let mut counts: Vec<i64> = Vec::new();
    let markers = pages_markers(data, MAX_PAGES_MARKERS);
    if markers.is_empty() {
        return 0;
    }
    // One pass over the data finds each word that a marker needs. Each marker then reads only its own window.
    let objects = positions(data, b"obj");
    let ends = positions(data, b"endobj");
    let count_positions = positions(data, b"/Count");
    for (marker_start, marker_end) in markers {
        let mut start = marker_start;
        // Only the 4096 bytes before the marker can hold the start of its object.
        let window_start = marker_start.saturating_sub(4096);
        let before = objects.partition_point(|position| position + 3 <= marker_start);
        match before.checked_sub(1).map(|index| objects[index]) {
            Some(position) if position >= window_start => start = position,
            _ if start > 512 => start -= 512,
            _ => start = 0,
        }
        let mut end = marker_end + 4096;
        let limit = data.len().min(marker_end + 4096);
        let next = ends.partition_point(|position| *position < marker_end);
        if let Some(&position) = ends.get(next)
            && position + 6 <= limit
        {
            end = position;
        }
        let end = end.min(data.len());
        counts.extend(
            counts_in(data, &count_positions, start, end)
                .into_iter()
                .filter(|value| *value > 0),
        );
    }
    if counts.is_empty() {
        return 0;
    }
    counts.sort_unstable();
    let total: i64 = counts.iter().sum();
    let largest = counts[counts.len() - 1];
    let rest = total - largest;
    if rest == 0 || rest == largest {
        return largest;
    }
    if rest > 0 && rest < largest {
        return total;
    }
    largest
}

/// The object and the generation number of the entry `/Info <n> <g> R`.
fn info_reference(data: &[u8]) -> Option<(String, String)> {
    let marker = b"/Info";
    let mut from = 0;
    while let Some(offset) = find(&data[from..], marker) {
        let start = from + offset;
        let mut index = start + marker.len();
        let after = skip_spaces(data, index);
        if after > index {
            index = after;
            let first_end = skip_digits(data, index);
            if first_end > index {
                let second_start = skip_spaces(data, first_end);
                if second_start > first_end {
                    let second_end = skip_digits(data, second_start);
                    if second_end > second_start {
                        let r_start = skip_spaces(data, second_end);
                        if r_start > second_end && data.get(r_start) == Some(&b'R') {
                            return Some((
                                String::from_utf8_lossy(&data[index..first_end]).into_owned(),
                                String::from_utf8_lossy(&data[second_start..second_end]).into_owned(),
                            ));
                        }
                    }
                }
            }
        }
        from = start + 1;
    }
    None
}

/// One object of the form `<n> <g> obj << ... >>`: the number, the generation and the content of the dictionary.
struct DictionaryObject<'a> {
    number: &'a [u8],
    generation: &'a [u8],
    dictionary: &'a [u8],
    end: usize,
}

/// The next object after `from`. The match starts at the start of a run of digits.
fn next_object(data: &[u8], from: usize) -> Option<DictionaryObject<'_>> {
    let mut index = from;
    while index < data.len() {
        if !data[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let number_end = skip_digits(data, index);
        let candidate = (|| {
            let second_start = skip_spaces(data, number_end);
            if second_start == number_end {
                return None;
            }
            let second_end = skip_digits(data, second_start);
            if second_end == second_start {
                return None;
            }
            let obj_start = skip_spaces(data, second_end);
            if obj_start == second_end || !data[obj_start..].starts_with(b"obj") {
                return None;
            }
            let open = skip_spaces(data, obj_start + 3);
            if !data[open..].starts_with(b"<<") {
                return None;
            }
            Some((second_start, second_end, open + 2))
        })();
        match candidate {
            Some((second_start, second_end, content_start)) => {
                let relative = find(&data[content_start..], b">>")?;
                return Some(DictionaryObject {
                    number: &data[index..number_end],
                    generation: &data[second_start..second_end],
                    dictionary: &data[content_start..content_start + relative],
                    end: content_start + relative + 2,
                });
            }
            None => index = number_end,
        }
    }
    None
}

/// The string `(...)` after a name in a dictionary, with the escapes `\n`, `\r`, `\t`, `\b` and `\f`.
fn literal_field(dictionary: &[u8], name: &str) -> String {
    let marker = format!("/{name}");
    let Some(index) = find(dictionary, marker.as_bytes()) else {
        return String::new();
    };
    let mut cursor = index + marker.len();
    while cursor < dictionary.len() && matches!(dictionary[cursor], b' ' | b'\t' | b'\r' | b'\n') {
        cursor += 1;
    }
    if cursor >= dictionary.len() || dictionary[cursor] != b'(' {
        return String::new();
    }
    cursor += 1;
    let mut out: Vec<u8> = Vec::new();
    let mut escaped = false;
    while cursor < dictionary.len() {
        let byte = dictionary[cursor];
        cursor += 1;
        if escaped {
            out.push(match byte {
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'b' => 0x08,
                b'f' => 0x0c,
                other => other,
            });
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            continue;
        }
        if byte == b')' {
            break;
        }
        out.push(byte);
    }
    lossy(&out).trim().to_owned()
}

/// The entries of the information dictionary that the details show.
fn info_dictionary(data: &[u8]) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let Some((number, generation)) = info_reference(data) else {
        return result;
    };
    let mut from = 0;
    while let Some(object) = next_object(data, from) {
        from = object.end;
        if object.number != number.as_bytes() || object.generation != generation.as_bytes() {
            continue;
        }
        let fields = [
            ("Title", "Title"),
            ("Author", "Author"),
            ("Subject", "Subject"),
            ("Keywords", "Keywords"),
            ("Creator", "Creator"),
            ("Producer", "Producer"),
            ("CreationDate", "Created"),
            ("ModDate", "Modified"),
        ];
        for (raw, label) in fields {
            let value = literal_field(object.dictionary, raw);
            if !value.is_empty() {
                result.insert(label.to_owned(), value);
            }
        }
        return result;
    }
    result
}

/// The details of a PDF file from its first bytes, its last bytes and its size (0 when the size is not known).
pub fn parse_pdf_metadata(prefix: &[u8], suffix: &[u8], size: i64) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();
    if let Some(version) = header_version(prefix) {
        props.insert("PDF version".to_owned(), version);
    }
    if contains(prefix, b"/Linearized") {
        props.insert("Linearized".to_owned(), "Yes".to_owned());
    }
    let mut combined = Vec::with_capacity(prefix.len() + suffix.len());
    combined.extend_from_slice(prefix);
    combined.extend_from_slice(suffix);
    let pages = page_count(&combined);
    if pages > 0 {
        props.insert("Pages".to_owned(), pages.to_string());
    }
    if size > 0 {
        props.insert("Object size".to_owned(), size.to_string());
    }
    for (key, value) in info_dictionary(&combined) {
        if !props.contains_key(&key) && !value.is_empty() {
            props.insert(key, value);
        }
    }
    if contains(&combined, b"/Encrypt") {
        props.insert("Encrypted".to_owned(), "Yes".to_owned());
    }
    if contains(&combined, b"/AcroForm") {
        props.insert("Forms".to_owned(), "AcroForm".to_owned());
    }
    if contains(&combined, b"/MarkInfo") {
        props.insert("Tagged".to_owned(), "Yes".to_owned());
    }
    props
}
