// SPDX-License-Identifier: MIT OR Apache-2.0
//! The options route of the service (ProcurAuth 5.6 to 5.8): `GET /.well-known/procurauth/resources`.
//!
//! The route lists the children of a node, page by page. It shows only the children that the subject of the
//! identity token can see. It asks the PDP one question for each child that it can show: the match `subtree`, no
//! usage. It asks the actions in this order: `object.read`, `object.write`, `object.delete`, `object.lock` and
//! `bucket.admin`, and only the actions that the action document publishes for the type of the child. A child is
//! visible when one answer is true; the route stops to ask for a child at its first true answer.
//!
//! The rules that the service chooses (ProcurAuth 5.6, 5.7):
//! - `q` for the buckets is a substring of the id or of the label, without case.
//! - `q` for the folders and the subfolders is a prefix of the id, with case: the storage searches only by prefix.
//! - A request asks at most 200 questions. When this bound stops the walk, the answer holds the items found so far
//!   and a cursor. The answer can have no item and a cursor.
//! - A node that does not exist gives an answer with no items.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Method};
use serde::Serialize;

use super::tree::{
    FOLDER_TYPES, Node, Resource, TYPE_BUCKET, TYPE_FOLDER, TYPE_SERVICE, percent_decode, percent_encode_id, valid_id,
    valid_id_bytes,
};
use super::{
    ACTION_BUCKET_ADMIN, ACTION_DELETE, ACTION_LOCK, ACTION_READ, ACTION_WRITE, AccessLayer, Answer, Ask,
    CODE_PDP_UNAVAILABLE, log_token, quote, run_guarded,
};
use crate::common::config::PERMISSION_READ;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Response, answer, api_error, empty, full, method_not_allowed, not_found};
use crate::common::storage::ListOptions;
use crate::instance::Instance;

/// The path of the options route.
pub const OPTIONS_PATH: &str = "/.well-known/procurauth/resources";
/// The most items of one answer (ProcurAuth 5.8).
pub const MAX_ITEMS: usize = 50;
/// The most questions to the PDP for one request (ProcurAuth 5.6).
pub const MAX_QUESTIONS: usize = 200;
/// The longest raw query that the route reads.
pub const MAX_QUERY_BYTES: usize = 16 << 10;
/// The longest value of `q`.
pub const MAX_SEARCH_BYTES: usize = 256;
/// The longest text that a cursor holds before its encoding.
pub const MAX_CURSOR_BYTES: usize = 2048;
/// The number of keys that one request to the storage asks for.
const PROVIDER_PAGE: u32 = 1000;
/// The longest parent that the log line shows.
const MAX_LOG_PARENT: usize = 200;
/// The code of a bad request of the route.
pub const ERROR_CODE: &str = "invalid_options_request";

/// The order of the actions that the route asks for each child.
const ACTION_ORDER: [&str; 5] = [
    ACTION_READ,
    ACTION_WRITE,
    ACTION_DELETE,
    ACTION_LOCK,
    ACTION_BUCKET_ADMIN,
];

/// The base64url engine of the cursors: no padding on output; on input, as the route always read them, the bits
/// after the last character can be other than zero.
const CURSOR_ENGINE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// One child in the answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OptionsItem {
    /// The id, not encoded.
    pub id: String,
    /// The label: 60 characters at most.
    pub label: String,
    /// True when the route can list children below this child.
    pub has_children: bool,
}

/// The JSON object of the answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OptionsAnswer {
    /// The visible children.
    pub items: Vec<OptionsItem>,
    /// The cursor of the next page, `null` on the last page.
    pub next: Option<String>,
}

/// The request after the check of its parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OptionsRequest {
    /// The type of the children.
    pub child_type: String,
    /// The chain of the nodes below the service, from the bucket.
    pub parent: Vec<Node>,
    /// The value of the parameter `parent`, decoded one time. It is for the log.
    pub parent_text: String,
    /// True when the parent cannot exist: one of its ids cannot be the id of a node.
    pub missing_parent: bool,
    /// The value of `q`.
    pub search: Vec<u8>,
    /// The most items of the answer.
    pub limit: usize,
    /// The payload of the cursor.
    pub after: Option<String>,
}

fn bad_request(message: impl Into<String>) -> Error {
    Error::api(400, ERROR_CODE, message)
}

/// The type of the children of a node at a depth below the service: 0 is the service, 1 a bucket, 2 a folder. A
/// subfolder has no children: `""`.
pub fn child_type(depth: usize) -> &'static str {
    match depth {
        0 => TYPE_BUCKET,
        1 | 2 => FOLDER_TYPES[depth - 1],
        _ => "",
    }
}

impl OptionsRequest {
    /// Read the raw query as ProcurAuth 5.7 says: split it at `&` and at the first `=` of each pair, and decode each
    /// name and each value one time. A `+` stays a `+`, and a bad escape gives `400`. A parameter that the route does
    /// not know is ignored, also its value. The fields that the check reads before an error stay filled, for the log.
    pub fn parse(&mut self, raw_query: &str) -> Result<()> {
        if raw_query.len() > MAX_QUERY_BYTES {
            return Err(bad_request("the query is too long"));
        }
        let mut values: [Option<Vec<u8>>; 5] = Default::default();
        const NAMES: [&str; 5] = ["parent", "type", "q", "limit", "after"];
        for pair in raw_query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            let Some(name) = percent_decode(raw_name.as_bytes()) else {
                continue;
            };
            let Some(slot) = NAMES.iter().position(|known| known.as_bytes() == name.as_slice()) else {
                continue;
            };
            let name = NAMES[slot];
            if values[slot].is_some() {
                return Err(bad_request(format!("the parameter {name} occurs more than one time")));
            }
            let value = percent_decode(raw_value.as_bytes())
                .ok_or_else(|| bad_request(format!("the parameter {name} has a bad percent-encoding")))?;
            values[slot] = Some(value);
        }
        let [parent, kind, search, limit, after] = values;

        let kind = kind.unwrap_or_default();
        if kind.is_empty() {
            return Err(bad_request("the parameter type is mandatory"));
        }
        if let Some(text) = parent {
            self.parse_parent(&text)?;
        }
        let want = child_type(self.parent.len());
        if kind.as_slice() != want.as_bytes() {
            if want.is_empty() {
                return Err(bad_request("the parent has no children"));
            }
            return Err(bad_request(format!(
                "the parameter type must be {want} for this parent"
            )));
        }
        self.child_type = want.to_owned();
        self.limit = match limit {
            Some(text) => parse_limit(&text)?,
            None => MAX_ITEMS,
        };
        if let Some(text) = search {
            if text.len() > MAX_SEARCH_BYTES {
                return Err(bad_request("the parameter q is too long"));
            }
            self.search = text;
        }
        if let Some(text) = after {
            let payload = decode_cursor(&text, &self.child_type)
                .ok_or_else(|| bad_request("the parameter after is not a cursor of this route"))?;
            self.after = Some(payload);
        }
        Ok(())
    }

    /// Read the value of the parameter `parent`: a path of nodes below the service, for example `bucket:b/folder:f`.
    /// The value is already decoded one time: the function splits it at each `/` and decodes each id.
    fn parse_parent(&mut self, text: &[u8]) -> Result<()> {
        self.parent_text = String::from_utf8_lossy(text).into_owned();
        if text.is_empty() {
            return Err(bad_request("the parameter parent is empty"));
        }
        for (index, part) in text.split(|byte| *byte == b'/').enumerate() {
            let colon = part.iter().position(|byte| *byte == b':');
            let (kind, raw_id) = match colon {
                Some(at) => (&part[..at], &part[at + 1..]),
                None => (part, &[][..]),
            };
            if colon.is_none() || kind.is_empty() || raw_id.is_empty() {
                return Err(bad_request(
                    "the parameter parent must have the form <type>:<id> for each node",
                ));
            }
            let want = child_type(index);
            if kind != want.as_bytes() {
                if want.is_empty() {
                    return Err(bad_request("the parameter parent has too many nodes"));
                }
                return Err(bad_request(format!(
                    "the parameter parent must have the type {want} at position {}",
                    index + 1
                )));
            }
            let id = percent_decode(raw_id)
                .ok_or_else(|| bad_request("the parameter parent has a bad percent-encoding in an id"))?;
            if id.is_empty() {
                return Err(bad_request("the parameter parent has an empty id"));
            }
            // An id that is not valid cannot be the id of a node that exists. The id of a folder never holds "/".
            if !valid_id_bytes(&id) || (index > 0 && id.contains(&b'/')) {
                self.missing_parent = true;
            }
            self.parent.push(Node::new(want, &String::from_utf8_lossy(&id)));
        }
        Ok(())
    }
}

/// Read the parameter `limit`: a whole number of digits only, from 1. A number above the maximum gives the maximum.
pub fn parse_limit(text: &[u8]) -> Result<usize> {
    let error = || bad_request("the parameter limit must be a whole number from 1");
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return Err(error());
    }
    let start = text.iter().position(|byte| *byte != b'0').ok_or_else(error)?;
    let digits = &text[start..];
    if digits.len() > 6 {
        return Ok(MAX_ITEMS);
    }
    let value = digits
        .iter()
        .fold(0usize, |value, digit| value * 10 + usize::from(digit - b'0'));
    Ok(value.min(MAX_ITEMS))
}

/// Make a cursor: the type of the children, a zero byte and the payload, in base64url. The payload for the buckets
/// is the id of the last bucket that the walk examined. The payload for the folders is a key, relative to the
/// parent: the listing of the storage continues after it.
pub fn encode_cursor(child_type: &str, payload: &str) -> String {
    CURSOR_ENGINE.encode(format!("{child_type}\0{payload}"))
}

/// Read a cursor. `None` when the text is not a cursor that this route made for this type.
pub fn decode_cursor(text: &[u8], child_type: &str) -> Option<String> {
    let cleaned: Vec<u8> = text
        .iter()
        .copied()
        .filter(|byte| *byte != b'\r' && *byte != b'\n')
        .collect();
    let raw = CURSOR_ENGINE.decode(cleaned).ok()?;
    let zero = raw.iter().position(|byte| *byte == 0)?;
    let (kind, payload) = (&raw[..zero], &raw[zero + 1..]);
    if kind != child_type.as_bytes() || payload.is_empty() || payload.len() > MAX_CURSOR_BYTES {
        return None;
    }
    String::from_utf8(payload.to_vec()).ok()
}

/// Cut a label to 60 characters (ProcurAuth 5.8).
fn label_of(text: &str) -> String {
    text.chars().take(super::actions::MAX_LABEL_CHARS).collect()
}

/// One child that the route can ask the PDP about.
#[derive(Clone, Debug)]
struct Candidate {
    id: String,
    label: String,
    has_children: bool,
}

/// Compare two ids in the order of the buckets: the lower-case id, then the id.
fn sort_key_less(a: &str, b: &str) -> bool {
    let (la, lb) = (a.to_lowercase(), b.to_lowercase());
    if la != lb {
        return la < lb;
    }
    a < b
}

/// The bucket blocks and the volume blocks.
struct BucketCandidates {
    list: Vec<Candidate>,
    index: usize,
    last_id: Option<String>,
    after: String,
}

impl BucketCandidates {
    /// Sort the instances by id, and keep those that `q` finds and that follow the cursor.
    fn new(instances: &[Arc<Instance>], search: &[u8], after: Option<&str>) -> Self {
        let needle = std::str::from_utf8(search).map(str::to_lowercase);
        let mut list = Vec::with_capacity(instances.len());
        for instance in instances {
            let id = instance.cfg.id.as_str();
            if !valid_id(id) {
                continue;
            }
            let label = super::actions::block_label(&instance.cfg.name).unwrap_or(id);
            let found = match &needle {
                Ok(needle) => {
                    needle.is_empty()
                        || id.to_lowercase().contains(needle.as_str())
                        || label.to_lowercase().contains(needle.as_str())
                }
                Err(_) => false,
            };
            if !found {
                continue;
            }
            list.push(Candidate {
                id: id.to_owned(),
                label: label_of(label),
                has_children: true,
            });
        }
        list.sort_by(|a, b| {
            if sort_key_less(&a.id, &b.id) {
                std::cmp::Ordering::Less
            } else if sort_key_less(&b.id, &a.id) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });
        if let Some(after) = after {
            let start = list.partition_point(|candidate| !sort_key_less(after, &candidate.id));
            list.drain(..start);
        }
        Self {
            list,
            index: 0,
            last_id: None,
            after: after.unwrap_or_default().to_owned(),
        }
    }

    fn take(&mut self, n: usize) -> Vec<Candidate> {
        let end = (self.index + n).min(self.list.len());
        let out = self.list[self.index..end].to_vec();
        self.index = end;
        if let Some(last) = out.last() {
            self.last_id = Some(last.id.clone());
        }
        out
    }

    fn cursor(&self) -> (String, bool) {
        let payload = self.last_id.clone().unwrap_or_else(|| self.after.clone());
        (payload, self.index < self.list.len())
    }
}

/// The folders or the subfolders below one node of a storage instance. They come from the listing of the storage
/// with the delimiter `/`, with the own credentials of the service.
struct FolderCandidates {
    instance: Arc<Instance>,
    /// `""` for the children of a bucket, or the relative path of the parent with `/` at the end.
    parent_relative: String,
    search: String,
    /// The cursor payload, relative to the parent.
    start_after: String,
    has_children: bool,
    buffer: std::collections::VecDeque<String>,
    page_token: String,
    started: bool,
    exhausted: bool,
    pages: u32,
    max_pages: u32,
    /// The largest key, relative to the parent, that the walk read. It is a valid start for the next request when
    /// the walk consumed all that it read.
    high: String,
    consumed_last: Option<String>,
}

/// The key to use as "start after" so that a listing skips the folder with this id and each key in it. Each key of
/// the folder starts with `id/`, and the character `0` follows `/` in the order of the bytes.
fn skip_key(id: &str) -> String {
    format!("{id}0")
}

impl FolderCandidates {
    fn new(
        instance: Arc<Instance>,
        parent_relative: String,
        search: String,
        after: String,
        has_children: bool,
    ) -> Self {
        let max_pages = instance.cfg.max_scan_pages.max(1);
        Self {
            instance,
            parent_relative,
            search,
            start_after: after,
            has_children,
            buffer: Default::default(),
            page_token: String::new(),
            started: false,
            exhausted: false,
            pages: 0,
            max_pages,
            high: String::new(),
            consumed_last: None,
        }
    }

    /// Read one page of the storage and add its folders to the buffer.
    async fn fetch(&mut self, ctx: &OpCtx) -> Result<()> {
        let mut options = ListOptions {
            prefix: self
                .instance
                .full_key(&format!("{}{}", self.parent_relative, self.search)),
            delimiter: "/".to_owned(),
            max_results: PROVIDER_PAGE,
            page_token: self.page_token.clone(),
            start_after: String::new(),
        };
        if !self.start_after.is_empty() {
            options.start_after = self
                .instance
                .full_key(&format!("{}{}", self.parent_relative, self.start_after));
        }
        let page = self.instance.list(ctx, &options).await?;
        self.pages += 1;
        self.started = true;
        self.page_token = page.next_page_token;
        if self.page_token.is_empty() {
            self.exhausted = true;
        }
        for full in &page.prefixes {
            let Some(relative) = self.instance.relative_key(full) else {
                continue;
            };
            let Some(rest) = relative.strip_prefix(self.parent_relative.as_str()) else {
                continue;
            };
            let name = rest.strip_suffix('/').unwrap_or(rest);
            if !name.is_empty() && !name.contains('/') {
                let key = skip_key(name);
                if key > self.high {
                    self.high = key;
                }
            }
            // A part that is not a valid id cannot be a node: the route skips it.
            if name.is_empty() || name.contains('/') || !valid_id(name) {
                continue;
            }
            self.buffer.push_back(name.to_owned());
        }
        for object in &page.objects {
            if let Some(relative) = self.instance.relative_key(&object.key)
                && let Some(rest) = relative.strip_prefix(self.parent_relative.as_str())
                && rest > self.high.as_str()
            {
                self.high = rest.to_owned();
            }
        }
        Ok(())
    }

    async fn take(&mut self, ctx: &OpCtx, n: usize) -> Result<Vec<Candidate>> {
        while self.buffer.len() < n && !self.exhausted && self.pages < self.max_pages {
            self.fetch(ctx).await?;
        }
        let n = n.min(self.buffer.len());
        let out: Vec<Candidate> = self
            .buffer
            .drain(..n)
            .map(|id| Candidate {
                label: label_of(&id),
                id,
                has_children: self.has_children,
            })
            .collect();
        if let Some(last) = out.last() {
            self.consumed_last = Some(last.id.clone());
        }
        Ok(out)
    }

    fn cursor(&self) -> (String, bool) {
        let more = !self.buffer.is_empty() || (self.started && !self.exhausted);
        let mut payload = match &self.consumed_last {
            Some(last) => skip_key(last),
            None => self.start_after.clone(),
        };
        if self.buffer.is_empty() && self.high > payload {
            // The walk read more keys than it consumed, and none of them is a candidate that it keeps.
            payload = self.high.clone();
        }
        (payload, more)
    }
}

/// The children of one node, in order, without the PDP.
enum Candidates {
    Buckets(BucketCandidates),
    Folders(FolderCandidates),
}

impl Candidates {
    async fn take(&mut self, ctx: &OpCtx, n: usize) -> Result<Vec<Candidate>> {
        match self {
            Self::Buckets(buckets) => Ok(buckets.take(n)),
            Self::Folders(folders) => folders.take(ctx, n).await,
        }
    }

    fn cursor(&self) -> (String, bool) {
        match self {
            Self::Buckets(buckets) => buckets.cursor(),
            Self::Folders(folders) => folders.cursor(),
        }
    }
}

/// The result of a walk.
struct Walk {
    items: Vec<OptionsItem>,
    next: Option<String>,
    questions: usize,
    failed: bool,
    /// The error of the storage, when a listing failed.
    error: Option<Error>,
}

/// The published actions whose types hold the type of the child, in the order of the questions.
fn actions_for(layer: &AccessLayer, child_type: &str) -> Vec<&'static str> {
    ACTION_ORDER
        .into_iter()
        .filter(|action| {
            layer
                .document
                .action(action)
                .is_some_and(|row| row.resource_types.contains(&child_type))
        })
        .collect()
}

/// Ask the PDP about the candidates and give the visible ones, `limit` at most, and the cursor of the next page.
async fn walk(
    layer: &AccessLayer,
    ctx: &OpCtx,
    who: (&str, &str),
    child_type: &str,
    ancestors: &[Node],
    candidates: &mut Candidates,
    limit: usize,
) -> Walk {
    let (_, request_id) = who;
    let identity = ctx
        .access
        .as_deref()
        .map(super::AccessRequest::identity)
        .unwrap_or_default();
    let mut out = Walk {
        items: Vec::new(),
        next: None,
        questions: 0,
        failed: false,
        error: None,
    };
    let actions = actions_for(layer, child_type);
    if actions.is_empty() {
        return out;
    }
    while out.items.len() < limit {
        // The chunk is small enough for the worst case: each child needs one question for each action.
        let size = (limit - out.items.len()).min((MAX_QUESTIONS - out.questions) / actions.len());
        if size < 1 {
            break;
        }
        let chunk = match candidates.take(ctx, size).await {
            Ok(chunk) => chunk,
            Err(error) => {
                out.error = Some(error);
                return out;
            }
        };
        if chunk.is_empty() {
            break;
        }
        let mut visible = vec![false; chunk.len()];
        let mut pending: Vec<usize> = (0..chunk.len()).collect();
        for action in &actions {
            if pending.is_empty() {
                break;
            }
            let asks: Vec<Ask> = pending
                .iter()
                .map(|index| Ask {
                    action: (*action).to_owned(),
                    resource: Resource {
                        node_type: child_type.to_owned(),
                        id: chunk[*index].id.clone(),
                        ancestors: ancestors.to_vec(),
                    }
                    .path(),
                })
                .collect();
            let count = asks.len();
            let answers = run_guarded(
                ctx,
                || layer.guard.display(request_id, &identity, &asks),
                || vec![Answer::failure(); count],
            )
            .await;
            out.questions += count;
            let mut still = Vec::with_capacity(pending.len());
            for (position, index) in pending.iter().enumerate() {
                let answer = answers.get(position).cloned().unwrap_or_else(Answer::failure);
                if answer.failed {
                    out.failed = true;
                    return out;
                }
                if answer.decision {
                    visible[*index] = true;
                } else {
                    still.push(*index);
                }
            }
            pending = still;
        }
        for (candidate, shown) in chunk.into_iter().zip(visible) {
            if shown {
                out.items.push(OptionsItem {
                    id: candidate.id,
                    label: candidate.label,
                    has_children: candidate.has_children,
                });
            }
        }
    }
    let (payload, more) = candidates.cursor();
    if more {
        out.next = Some(encode_cursor(child_type, &payload));
    }
    out
}

/// The parent for the log line. The mode `anonymous` keeps the ids of the folders out of the log.
fn log_parent(request: &OptionsRequest, detailed: bool) -> String {
    let text = if detailed {
        request.parent_text.clone()
    } else {
        request
            .parent
            .iter()
            .enumerate()
            .map(|(index, node)| {
                if index == 0 {
                    format!("{}:{}", node.node_type, percent_encode_id(&node.id))
                } else {
                    format!("{}:-", node.node_type)
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    let mut end = text.len().min(MAX_LOG_PARENT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// The answer of the route: JSON without the escape of `<`, `>` and `&`, with `Content-Length`. A `HEAD` gets no
/// body.
fn options_response(method: &Method, value: &OptionsAnswer) -> Response {
    let mut body = match super::plain_json(value) {
        Ok(body) => body,
        Err(error) => return api_error(&error),
    };
    body.push(b'\n');
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    let body = if *method == Method::HEAD { empty() } else { full(body) };
    answer(200, headers, body)
}

/// Answer one request of the options route. The middleware checked the identity token before: the subject and the
/// request id come from the context. The route never reads the identity header.
pub async fn serve(
    layer: &AccessLayer,
    instances: &[Arc<Instance>],
    method: &Method,
    raw_query: &str,
    ctx: &OpCtx,
) -> Response {
    if *method != Method::GET && *method != Method::HEAD {
        return method_not_allowed(&["GET", "HEAD"]);
    }
    if !layer.enforced() {
        return not_found();
    }
    let (subject, request_id) = ctx.access.as_deref().map_or(("", ""), |request| {
        (request.subject.as_str(), request.request_id.as_str())
    });
    let mut request = OptionsRequest::default();
    let (response, count, questions) = match request.parse(raw_query) {
        Err(error) => (api_error(&error), 0, 0),
        Ok(()) => answer_request(layer, instances, method, ctx, (subject, request_id), &request).await,
    };
    let type_text = if request.child_type.is_empty() {
        "-"
    } else {
        request.child_type.as_str()
    };
    crate::log!(
        "access.options request_id={} subject={} type={} parent={} items={} questions={}",
        log_token(request_id),
        quote(subject),
        type_text,
        quote(&log_parent(&request, layer.detailed_log())),
        count,
        questions
    );
    response
}

/// The answer of a request with good parameters, the number of its items and the number of its questions.
async fn answer_request(
    layer: &AccessLayer,
    instances: &[Arc<Instance>],
    method: &Method,
    ctx: &OpCtx,
    who: (&str, &str),
    request: &OptionsRequest,
) -> (Response, usize, usize) {
    let empty_answer = || {
        (
            options_response(
                method,
                &OptionsAnswer {
                    items: Vec::new(),
                    next: None,
                },
            ),
            0,
            0,
        )
    };
    let mut ancestors = vec![Node::new(TYPE_SERVICE, layer.audience())];
    let mut candidates = if request.child_type == TYPE_BUCKET {
        Candidates::Buckets(BucketCandidates::new(
            instances,
            &request.search,
            request.after.as_deref(),
        ))
    } else {
        if request.missing_parent {
            return empty_answer();
        }
        let Some(bucket) = request.parent.first() else {
            return empty_answer();
        };
        let Some(instance) = instances.iter().find(|instance| instance.cfg.id == bucket.id) else {
            return empty_answer();
        };
        ancestors.extend(request.parent.iter().cloned());
        if instance.require_permission(PERMISSION_READ).is_err() {
            // The storage cannot give the folders when the process may not read.
            return empty_answer();
        }
        // No id of a folder holds "/": a search with "/" finds nothing. A search that is not UTF-8 finds nothing.
        let Ok(search) = String::from_utf8(request.search.clone()) else {
            return empty_answer();
        };
        if search.contains('/') {
            return empty_answer();
        }
        let parent_relative: String = request.parent[1..].iter().map(|node| format!("{}/", node.id)).collect();
        Candidates::Folders(FolderCandidates::new(
            Arc::clone(instance),
            parent_relative,
            search,
            request.after.clone().unwrap_or_default(),
            request.child_type == TYPE_FOLDER,
        ))
    };
    let walked = walk(
        layer,
        ctx,
        who,
        &request.child_type,
        &ancestors,
        &mut candidates,
        request.limit,
    )
    .await;
    match walked {
        walk if walk.failed => (
            api_error(&Error::api(
                503,
                CODE_PDP_UNAVAILABLE,
                "the access service gave no valid answer",
            )),
            0,
            walk.questions,
        ),
        Walk {
            error: Some(error),
            questions,
            ..
        } => (api_error(&error), 0, questions),
        walk => {
            let count = walk.items.len();
            let response = options_response(
                method,
                &OptionsAnswer {
                    items: walk.items,
                    next: walk.next,
                },
            );
            (response, count, walk.questions)
        }
    }
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
