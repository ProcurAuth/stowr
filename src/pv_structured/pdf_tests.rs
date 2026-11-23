//! The tests of the PDF details.

use std::collections::BTreeMap;

use super::fixtures::{bytes, cases, name};
use super::pdf::{page_count, parse_pdf_metadata};

#[test]
fn pdf_details_match_the_expected_answers_in_each_case() {
    let mut failures = Vec::new();
    for case in cases("pdfs") {
        let prefix = bytes(&case["prefix"]);
        let suffix = bytes(&case["suffix"]);
        let size = case["size"].as_i64().unwrap_or(0);
        let expected: BTreeMap<String, String> = case["properties"]
            .as_object()
            .map(|map| {
                map.iter()
                    .map(|(key, value)| (key.clone(), value.as_str().unwrap_or("").to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let got = parse_pdf_metadata(&prefix, &suffix, size);
        if got != expected {
            failures.push(format!("{}: got {got:?}, want {expected:?}", name(case)));
        }
        let mut combined = prefix.clone();
        combined.extend_from_slice(&suffix);
        let pages = page_count(&combined);
        let want_pages = case["pages"].as_i64().unwrap_or(0);
        if pages != want_pages {
            failures.push(format!("{} (pages): got {pages}, want {want_pages}", name(case)));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn pdf_details_use_the_bounded_page_tree_counts() {
    let prefix = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n";
    let suffix = b"2 0 obj << /Type /Pages /Kids [3 0 R 4 0 R] /Count 6 >> endobj\n4 0 obj << /Type /Pages /Count 1229 >> endobj\ntrailer << /Root 1 0 R >>";
    let props = parse_pdf_metadata(prefix, suffix, (prefix.len() + suffix.len()) as i64);
    assert_eq!(props.get("Pages").map(String::as_str), Some("1235"));
    assert_eq!(props.get("PDF version").map(String::as_str), Some("1.7"));
}

#[test]
fn the_page_count_scan_is_bounded() {
    // Without any "obj" text an unbounded backward search scans everything before each marker.
    let data = b"/Type/Pages".repeat(20_000);
    let started = std::time::Instant::now();
    page_count(&data);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "the scan took {:?}",
        started.elapsed()
    );
    let legit = b"%PDF-1.7\n2 0 obj << /Type /Pages /Count 7 /Kids [3 0 R] >> endobj\n";
    assert_eq!(page_count(legit), 7);
}

/// The page count with a direct search in the window of each marker: the indexed count must give the same value.
fn direct_page_count(data: &[u8]) -> i64 {
    let find = |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).position(|window| window == needle);
    let space = |byte: u8| matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' ');
    let mut markers = Vec::new();
    let mut from = 0;
    while markers.len() < 4096 {
        let Some(offset) = find(&data[from..], b"/Type") else {
            break;
        };
        let start = from + offset;
        let mut after = start + 5;
        while after < data.len() && space(data[after]) {
            after += 1;
        }
        let end = after + 6;
        if data[after..].starts_with(b"/Pages")
            && data.get(end).is_none_or(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
        {
            markers.push((start, end));
            from = end;
            continue;
        }
        from = start + 1;
    }
    let mut counts = Vec::new();
    for (marker_start, marker_end) in markers {
        let window_start = marker_start.saturating_sub(4096);
        let window = &data[window_start..marker_start];
        let last = window.windows(3).rposition(|part| part == b"obj");
        let start = match last {
            Some(index) => window_start + index,
            None if marker_start > 512 => marker_start - 512,
            None => 0,
        };
        let limit = data.len().min(marker_end + 4096);
        let end = match find(&data[marker_end..limit], b"endobj") {
            Some(relative) => marker_end + relative,
            None => marker_end + 4096,
        }
        .min(data.len());
        let part = &data[start..end];
        let mut from = 0;
        while let Some(offset) = find(&part[from..], b"/Count") {
            let at = from + offset;
            let mut digits_start = at + 6;
            while digits_start < part.len() && space(part[digits_start]) {
                digits_start += 1;
            }
            let mut digits_end = digits_start;
            while digits_end < part.len() && part[digits_end].is_ascii_digit() {
                digits_end += 1;
            }
            if digits_start > at + 6 && digits_end > digits_start {
                if let Ok(value) = std::str::from_utf8(&part[digits_start..digits_end]).unwrap().parse::<i64>()
                    && value > 0
                {
                    counts.push(value);
                }
                from = digits_end;
            } else {
                from = at + 1;
            }
        }
    }
    if counts.is_empty() {
        return 0;
    }
    counts.sort_unstable();
    let total: i64 = counts.iter().sum();
    let largest = counts[counts.len() - 1];
    let rest = total - largest;
    if rest == 0 || rest == largest {
        largest
    } else if rest > 0 && rest < largest {
        total
    } else {
        largest
    }
}

#[test]
fn the_page_count_of_the_index_is_the_count_of_a_direct_search() {
    let mut cases: Vec<Vec<u8>> = vec![
        b"1 0 obj << /Type /Pages /Count 3 >> endobj 2 0 obj << /Type/Pages /Count 2 >> endobj".to_vec(),
        b"/Type /Pages /Count 12".to_vec(),
        b"obj /Count 4 /Type /Pages /Count  5 endobj /Count 6".to_vec(),
        b"/Type /PagesX /Count 9 /Type\n/Pages\t/Count\r7".to_vec(),
    ];
    // Windows at their limits: a count after 4096 bytes, an object start before 4096 bytes, digits cut by `endobj`.
    let mut far = b"9 0 obj /Count 40 ".to_vec();
    far.extend(std::iter::repeat_n(b' ', 4100));
    far.extend_from_slice(b"/Type /Pages /Count 3");
    far.extend(std::iter::repeat_n(b'x', 4090));
    far.extend_from_slice(b"/Count 77 endobj /Count 8");
    cases.push(far);
    let mut seed = 7u64;
    for _ in 0..200 {
        let mut data = Vec::new();
        for _ in 0..40 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            let part: &[u8] = match (seed >> 33) % 9 {
                0 => b"/Type /Pages ",
                1 => b"/Count ",
                2 => b"12 ",
                3 => b"obj ",
                4 => b"endobj ",
                5 => b"/Count 3 ",
                6 => b"/Type/Pages/Count 1 ",
                7 => b"\n",
                _ => b"filler text ",
            };
            data.extend_from_slice(part);
            if (seed >> 40) % 5 == 0 {
                data.extend(std::iter::repeat_n(b'.', ((seed >> 20) % 3000) as usize));
            }
        }
        cases.push(data);
    }
    for data in cases {
        assert_eq!(
            page_count(&data),
            direct_page_count(&data),
            "{}",
            String::from_utf8_lossy(&data)
        );
    }
}
