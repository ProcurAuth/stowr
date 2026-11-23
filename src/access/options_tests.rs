//! The tests of the options route (ProcurAuth 5.6 to 5.8, cases U05 and U70 to U83).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::access::fake::FakePdp;
use crate::access::test_support::{authzen_config, bucket, ctx_of, instance_over, memory};
use crate::common::BoxFuture;
use crate::common::config::{BucketConfig, LogMode, PERMISSION_DELETE, PERMISSION_WRITE};
use crate::common::http::{Body, read_limited};
use crate::common::storage::{Backend, DiscoveredCapabilities, ListPage, ObjectInfo, ObjectResponse};
use crate::testkit::MemoryBackend;

const SERVICE: &str = "stowr-test";

/// A back end that gives fixed pages to the listing, and counts the calls.
#[derive(Default)]
struct Scripted {
    pages: Vec<ListPage>,
    calls: Mutex<Vec<ListOptions>>,
    inner: Option<Arc<MemoryBackend>>,
}

impl Scripted {
    fn pages(pages: Vec<ListPage>) -> Arc<Self> {
        Arc::new(Self {
            pages,
            ..Self::default()
        })
    }

    fn over(inner: Arc<MemoryBackend>) -> Arc<Self> {
        Arc::new(Self {
            inner: Some(inner),
            ..Self::default()
        })
    }

    fn calls(&self) -> Vec<ListOptions> {
        self.calls.lock().unwrap().clone()
    }
}

fn not_here<T>() -> BoxFuture<'static, crate::common::error::Result<T>>
where
    T: Send + 'static,
{
    Box::pin(async { Err(Error::api(501, "unsupported", "This test does not use this call.")) })
}

impl Backend for Scripted {
    fn list<'a>(
        &'a self,
        ctx: &'a OpCtx,
        options: &'a ListOptions,
    ) -> BoxFuture<'a, crate::common::error::Result<ListPage>> {
        let index = {
            let mut calls = self.calls.lock().unwrap();
            calls.push(options.clone());
            calls.len() - 1
        };
        Box::pin(async move {
            match &self.inner {
                Some(inner) => inner.list(ctx, options).await,
                None => Ok(self.pages.get(index).cloned().unwrap_or_default()),
            }
        })
    }
    fn head<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
    ) -> BoxFuture<'a, crate::common::error::Result<ObjectResponse>> {
        not_here()
    }
    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, crate::common::error::Result<ObjectResponse>> {
        not_here()
    }
    fn put<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _body: Body,
        _size: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, crate::common::error::Result<()>> {
        not_here()
    }
    fn delete<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, crate::common::error::Result<()>> {
        not_here()
    }
    fn copy<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _source: &'a str,
        _destination: &'a str,
    ) -> BoxFuture<'a, crate::common::error::Result<()>> {
        not_here()
    }
    fn discover_capabilities<'a>(
        &'a self,
        _ctx: &'a OpCtx,
    ) -> BoxFuture<'a, crate::common::error::Result<DiscoveredCapabilities>> {
        Box::pin(async { Ok(DiscoveredCapabilities::default()) })
    }
}

/// A block with read, write and delete, one page of scan (no `max_scan_pages`), and a root prefix.
fn block(id: &str, name: &str, root: &str) -> BucketConfig {
    BucketConfig {
        root_prefix: root.to_owned(),
        max_scan_pages: 0,
        ..bucket(id, name, Some(&[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]))
    }
}

fn instance(id: &str, name: &str, backend: Arc<dyn Backend>, root: &str) -> Arc<Instance> {
    instance_over(block(id, name, root), backend)
}

fn buckets(n: usize) -> Vec<Arc<Instance>> {
    (0..n)
        .map(|i| {
            let id = format!("bucket{i:03}");
            instance(&id, &id, memory(&[]), "")
        })
        .collect()
}

fn folders(count: usize) -> Arc<MemoryBackend> {
    let keys: Vec<String> = (0..count).map(|i| format!("f{i:03}/x")).collect();
    let objects: Vec<(&str, &str)> = keys.iter().map(|key| (key.as_str(), "x")).collect();
    memory(&objects)
}

struct Fixture {
    layer: AccessLayer,
    fake: Arc<FakePdp>,
    instances: Vec<Arc<Instance>>,
}

struct Got {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Fixture {
    /// The route for the instances. The action document publishes the five actions.
    fn new(instances: Vec<Arc<Instance>>) -> Self {
        let blocks = instances
            .iter()
            .map(|instance| bucket(&instance.cfg.id, &instance.cfg.name, None))
            .collect();
        let fake = Arc::new(FakePdp::new());
        let layer = AccessLayer::with_guard(&authzen_config(SERVICE, blocks, Vec::new()), fake.clone()).unwrap();
        Self { layer, fake, instances }
    }

    fn answer_when(&self, test: impl Fn(&crate::access::fake::FakeQuestion) -> bool + Send + Sync + 'static) {
        self.fake.set_answer(move |q| json!({"decision": test(q)}));
    }

    async fn send(&self, method: Method, query: &str) -> Got {
        let response = serve(&self.layer, &self.instances, &method, query, &ctx_of("alice", "req-1")).await;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let (body, _) = read_limited(response.into_body(), 1 << 20).await.unwrap();
        Got {
            status,
            headers,
            body: body.to_vec(),
        }
    }

    async fn get(&self, query: &str) -> Got {
        self.send(Method::GET, query).await
    }

    /// Read an answer of status 200.
    async fn page(&self, query: &str) -> (Vec<OptionsItem>, Option<String>) {
        let got = self.get(query).await;
        assert_eq!(got.status, 200, "?{query}: {}", String::from_utf8_lossy(&got.body));
        decode(&got)
    }

    fn actions_of(&self) -> Vec<String> {
        self.fake.questions().iter().map(|q| q.action.clone()).collect()
    }
}

fn decode(got: &Got) -> (Vec<OptionsItem>, Option<String>) {
    assert_eq!(got.headers.get(CONTENT_TYPE).unwrap(), "application/json");
    assert_eq!(got.headers.get(CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(
        got.headers.get(CONTENT_LENGTH).unwrap(),
        got.body.len().to_string().as_str()
    );
    assert!(got.body.ends_with(b"\n"));
    let value: Value = serde_json::from_slice(&got.body).unwrap();
    let members = value.as_object().unwrap();
    assert_eq!(members.len(), 2, "{value}");
    assert!(members["items"].is_array(), "{value}");
    let items = members["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| OptionsItem {
            id: item["id"].as_str().unwrap().to_owned(),
            label: item["label"].as_str().unwrap().to_owned(),
            has_children: item["has_children"].as_bool().unwrap(),
        })
        .collect();
    (items, members["next"].as_str().map(str::to_owned))
}

fn ids(items: &[OptionsItem]) -> Vec<String> {
    items.iter().map(|item| item.id.clone()).collect()
}

#[tokio::test]
async fn the_route_asks_subtree_questions_without_usage() {
    let f = Fixture::new(buckets(3));
    let (items, _) = f.page("type=bucket").await;
    assert_eq!(items.len(), 3);
    let questions = f.fake.questions();
    assert!(!questions.is_empty());
    for q in questions {
        assert_eq!(q.match_mode, "subtree");
        assert!(!q.usage && !q.permission_only);
    }
}

#[tokio::test]
async fn a_question_has_the_type_of_the_child_and_the_chain_of_the_service() {
    let f = Fixture::new(buckets(2));
    f.page("type=bucket").await;
    let questions = f.fake.questions();
    assert_eq!(questions.len(), 2);
    for q in questions {
        assert_eq!(q.resource_type, "bucket");
        assert_eq!(q.match_mode, "subtree");
        assert_eq!(q.ancestors, vec![Node::new("service", SERVICE)]);
    }
}

#[tokio::test]
async fn no_child_that_the_pdp_refuses() {
    let f = Fixture::new(buckets(3));
    f.answer_when(|_| false);
    let (items, next) = f.page("type=bucket").await;
    assert!(items.is_empty() && next.is_none());
    // Each child got each action of its type: five for a bucket.
    assert_eq!(f.fake.questions().len(), 15);
}

#[tokio::test]
async fn the_children_have_an_id_a_label_and_has_children() {
    let f = Fixture::new(vec![instance("docs", "Documents", memory(&[]), "")]);
    let got = f.get("type=bucket").await;
    assert_eq!(got.status, 200);
    assert_eq!(
        String::from_utf8(got.body).unwrap(),
        "{\"items\":[{\"id\":\"docs\",\"label\":\"Documents\",\"has_children\":true}],\"next\":null}\n"
    );
}

#[tokio::test]
async fn the_answer_stays_within_the_numbers_of_a_caller() {
    let long = "é".repeat(100);
    let instances = (0..70)
        .map(|i| instance(&format!("{i:03}-{}", "x".repeat(252)), &long, memory(&[]), ""))
        .collect();
    let f = Fixture::new(instances);
    let got = f.get("type=bucket&limit=999").await;
    let (items, next) = decode(&got);
    assert_eq!(items.len(), 50);
    assert!(next.is_some());
    assert!(got.body.len() <= 64 << 10);
    for item in items {
        assert_eq!(item.id.len(), 256);
        assert!(item.label.chars().count() <= 60);
    }
}

#[tokio::test]
async fn a_failure_of_the_pdp_gives_503() {
    type Inject = fn(&FakePdp);
    let cases: [(&str, Inject); 3] = [
        ("HTTP 500", |p| p.set_status(500)),
        ("not a boolean", |p| p.set_raw(br#"{"decision":"yes"}"#)),
        ("no answer", |p| p.set_delay(Duration::from_secs(3))),
    ];
    for (name, inject) in cases {
        let f = Fixture::new(buckets(3));
        f.fake
            .configure(|settings| settings.timeout = Duration::from_millis(150));
        inject(&f.fake);
        let got = f.get("type=bucket").await;
        assert_eq!(got.status, 503, "{name}");
        let body: Value = serde_json::from_slice(&got.body).unwrap();
        assert_eq!(body["error"]["code"], "pdp_unavailable", "{name}");
        assert_eq!(body["error"]["message"], "the access service gave no valid answer");
        assert!(body["error"].get("action").is_none());
    }
}

#[tokio::test]
async fn a_failed_answer_for_folder_children_gives_503() {
    let f = Fixture::new(vec![instance("b", "b", folders(3), "")]);
    f.fake.set_status(500);
    assert_eq!(f.get("type=folder&parent=bucket%3Ab").await.status, 503);
}

#[tokio::test]
async fn the_type_is_mandatory() {
    let f = Fixture::new(buckets(1));
    for query in ["", "limit=5", "type=", "parent=bucket%3Ab"] {
        assert_eq!(f.get(query).await.status, 400, "?{query}");
    }
    assert!(f.fake.questions().is_empty());
}

#[tokio::test]
async fn a_parameter_that_occurs_two_times_gives_400() {
    let f = Fixture::new(buckets(1));
    for query in [
        "type=bucket&type=bucket",
        "type=bucket&limit=2&limit=2",
        "type=bucket&q=a&q=b",
        "type=bucket&%74ype=bucket",
        "type=folder&parent=bucket%3Ab&parent=bucket%3Ab",
        "type=bucket&after=YQ&after=YQ",
    ] {
        let got = f.get(query).await;
        assert_eq!(got.status, 400, "?{query}");
        let body: Value = serde_json::from_slice(&got.body).unwrap();
        assert_eq!(body["error"]["code"], "invalid_options_request");
    }
}

#[tokio::test]
async fn the_limit_is_a_whole_number_from_one() {
    let f = Fixture::new(buckets(60));
    for limit in ["0", "-1", "+5", "5x", "abc", "1.5", "", "00", "%205", "0x5"] {
        assert_eq!(
            f.get(&format!("type=bucket&limit={limit}")).await.status,
            400,
            "limit={limit:?}"
        );
    }
    for (limit, want) in [
        ("1", 1),
        ("5", 5),
        ("007", 7),
        ("50", 50),
        ("51", 50),
        ("99", 50),
        ("99999999999999999999999", 50),
    ] {
        let (items, _) = f.page(&format!("type=bucket&limit={limit}")).await;
        assert_eq!(items.len(), want, "limit={limit}");
    }
}

#[tokio::test]
async fn the_type_must_be_the_child_type_of_the_parent() {
    let f = Fixture::new(buckets(1));
    for query in [
        "parent=bucket%3Ax&type=bucket",
        "type=folder",
        "type=subfolder",
        "type=other",
        "parent=bucket%3Ax&type=subfolder",
        "parent=bucket%3Ax%2Ffolder%3Ay&type=folder",
        "parent=bucket%3Ax%2Ffolder%3Ay%2Fsubfolder%3Az&type=subfolder",
        "parent=bucket%3Ax%2Ffolder%3Ay&type=bucket",
    ] {
        assert_eq!(f.get(query).await.status, 400, "?{query}");
    }
    assert!(f.fake.questions().is_empty());
}

#[tokio::test]
async fn a_bad_escape_gives_400() {
    let f = Fixture::new(buckets(1));
    for query in [
        "parent=%zz&type=bucket",
        "type=bucket%",
        "type=bucket&q=%4",
        "type=bucket&limit=%3",
        "type=folder&parent=bucket%3Aa%25zz",
        "type=bucket&after=%zz",
    ] {
        assert_eq!(f.get(query).await.status, 400, "?{query}");
    }
}

#[tokio::test]
async fn an_unknown_parameter_is_ignored() {
    let f = Fixture::new(buckets(2));
    let (items, _) = f.page("type=bucket&x_unknown=1&x_unknown=2&x_bad=%zz&&").await;
    assert_eq!(items.len(), 2);
}

#[tokio::test]
async fn no_more_items_than_the_limit() {
    let f = Fixture::new(buckets(3));
    let (items, next) = f.page("type=bucket&limit=1").await;
    assert_eq!(items.len(), 1);
    assert!(next.is_some());
}

#[tokio::test]
async fn only_read_questions_when_the_read_is_true() {
    let f = Fixture::new(buckets(4));
    f.page("type=bucket").await;
    for q in f.fake.questions() {
        assert_eq!(
            (q.action.as_str(), q.match_mode.as_str(), q.usage),
            (ACTION_READ, "subtree", false)
        );
    }
    assert_eq!(f.fake.questions().len(), 4);
    assert_eq!(f.fake.requests(), 1, "one batch for the page");
}

#[tokio::test]
async fn the_next_actions_go_only_for_the_children_still_false() {
    let f = Fixture::new(vec![
        instance("b1", "b1", memory(&[]), ""),
        instance("b2", "b2", memory(&[]), ""),
    ]);
    f.answer_when(|q| {
        (q.resource_id == "b2" && q.action == ACTION_READ) || (q.resource_id == "b1" && q.action == ACTION_BUCKET_ADMIN)
    });
    let (items, _) = f.page("type=bucket").await;
    assert_eq!(ids(&items), vec!["b1", "b2"]);
    let questions = f.fake.questions();
    let for_b1: Vec<&str> = questions
        .iter()
        .filter(|q| q.resource_id == "b1")
        .map(|q| q.action.as_str())
        .collect();
    let for_b2: Vec<&str> = questions
        .iter()
        .filter(|q| q.resource_id == "b2")
        .map(|q| q.action.as_str())
        .collect();
    assert_eq!(
        for_b1,
        vec![
            ACTION_READ,
            ACTION_WRITE,
            ACTION_DELETE,
            ACTION_LOCK,
            ACTION_BUCKET_ADMIN
        ]
    );
    assert_eq!(for_b2, vec![ACTION_READ]);
    // The first batch holds the read of both buckets. Each later question holds only b1.
    assert_eq!(f.fake.requests(), 5);
}

#[tokio::test]
async fn the_folder_children_never_ask_bucket_admin() {
    let f = Fixture::new(vec![instance("b", "b", folders(2), "")]);
    f.answer_when(|q| q.resource_id == "f001" && q.action == ACTION_WRITE);
    let (items, _) = f.page("type=folder&parent=bucket%3Ab").await;
    assert_eq!(ids(&items), vec!["f001"]);
    assert!(f.actions_of().iter().all(|action| action != ACTION_BUCKET_ADMIN));
    let for_f001: Vec<String> = f
        .fake
        .questions()
        .iter()
        .filter(|q| q.resource_id == "f001")
        .map(|q| q.action.clone())
        .collect();
    assert_eq!(for_f001, vec![ACTION_READ, ACTION_WRITE]);
}

#[tokio::test]
async fn the_route_asks_only_the_published_actions() {
    let fake = Arc::new(FakePdp::new());
    let config = authzen_config(
        SERVICE,
        vec![
            bucket("bucket000", "bucket000", Some(&["read"])),
            bucket("bucket001", "", Some(&["read"])),
        ],
        Vec::new(),
    );
    let f = Fixture {
        layer: AccessLayer::with_guard(&config, fake.clone()).unwrap(),
        fake,
        instances: buckets(2),
    };
    f.answer_when(|_| false);
    let (items, _) = f.page("type=bucket").await;
    assert!(items.is_empty());
    assert_eq!(f.actions_of(), vec![ACTION_READ, ACTION_READ]);
}

#[tokio::test]
async fn the_buckets_are_sorted_and_searched_without_case() {
    let instances = vec![
        instance("b", "Beta", memory(&[]), ""),
        instance("a", "a", memory(&[]), ""),
        instance("B", "Gamma files", memory(&[]), ""),
        instance("A", "", memory(&[]), ""),
        instance("c1", &format!("Shared{}", "x".repeat(60)), memory(&[]), ""),
        instance("c2", "bad\nname", memory(&[]), ""),
    ];
    let f = Fixture::new(instances);
    let (items, _) = f.page("type=bucket").await;
    assert_eq!(ids(&items), vec!["A", "a", "B", "b", "c1", "c2"]);
    let label = |id: &str| items.iter().find(|item| item.id == id).unwrap().label.clone();
    // The label is the name, or the id when the name is empty, too long or has a control character.
    assert_eq!(
        (label("b"), label("A"), label("c1"), label("c2")),
        ("Beta".into(), "A".into(), "c1".into(), "c2".into())
    );
    assert!(items.iter().all(|item| item.has_children));
    for (query, want) in [
        ("q=GAMMA", vec!["B"]),
        ("q=b", vec!["B", "b"]),
        ("q=BET", vec!["b"]),
        ("q=a", vec!["A", "B", "a", "b"]),
        ("q=nothing", vec![]),
        ("q=%20files", vec!["B"]),
        ("q=%ff", vec![]),
    ] {
        let (items, _) = f.page(&format!("type=bucket&{query}")).await;
        let got: BTreeSet<String> = ids(&items).into_iter().collect();
        let want: BTreeSet<String> = want.into_iter().map(str::to_owned).collect();
        assert_eq!(got, want, "?{query}");
    }
}

#[tokio::test]
async fn the_bucket_pages_follow_the_cursor() {
    let f = Fixture::new(buckets(5));
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let mut query = "type=bucket&limit=2".to_owned();
        if let Some(cursor) = &cursor {
            query.push_str(&format!("&after={cursor}"));
        }
        let (items, next) = f.page(&query).await;
        all.extend(ids(&items));
        match next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(
        all,
        vec!["bucket000", "bucket001", "bucket002", "bucket003", "bucket004"]
    );
}

#[tokio::test]
async fn a_folder_page_of_120_folders_gives_pages_of_50_50_and_20() {
    let f = Fixture::new(vec![instance("b", "b", folders(120), "")]);
    let mut seen = BTreeSet::new();
    let mut sizes = Vec::new();
    let mut cursor: Option<String> = None;
    for page in 0..10 {
        f.fake.reset();
        let mut query = "type=folder&parent=bucket%3Ab".to_owned();
        if let Some(cursor) = &cursor {
            query.push_str(&format!("&after={cursor}"));
        }
        let (items, next) = f.page(&query).await;
        sizes.push(items.len());
        for item in &items {
            assert!(seen.insert(item.id.clone()), "{} is in two pages", item.id);
            assert!(item.has_children && item.label == item.id);
        }
        assert_eq!(f.fake.questions().len(), items.len(), "page {page}");
        match next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(sizes, vec![50, 50, 20]);
    assert_eq!(seen.len(), 120);
    assert!(seen.contains("f000") && seen.contains("f119"));
}

#[tokio::test]
async fn the_bound_of_200_questions_gives_an_empty_page_with_a_cursor() {
    let f = Fixture::new(vec![instance("b", "b", folders(120), "")]);
    f.answer_when(|q| q.resource_id == "f060" && q.action == ACTION_DELETE);
    let mut first: Option<String> = None;
    let mut found = Vec::new();
    let mut counts = Vec::new();
    let mut cursor: Option<String> = None;
    for page in 0..10 {
        f.fake.reset();
        let mut query = "type=folder&parent=bucket%3Ab".to_owned();
        if let Some(cursor) = &cursor {
            query.push_str(&format!("&after={cursor}"));
        }
        let (items, next) = f.page(&query).await;
        counts.push(f.fake.questions().len());
        assert!(f.fake.questions().len() <= 200);
        if page == 0 {
            // 50 folders, four actions each: 200 questions, no item, and a cursor.
            assert!(items.is_empty() && next.is_some());
            first = next.clone();
        }
        found.extend(ids(&items));
        match next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(counts, vec![200, 199, 80]);
    assert_eq!(found, vec!["f060"]);
    // The first cursor continues after the folder f049.
    assert_eq!(
        decode_cursor(first.unwrap().as_bytes(), "folder"),
        Some("f0490".to_owned())
    );
}

#[tokio::test]
async fn the_bound_stops_a_bucket_walk_too() {
    let f = Fixture::new(buckets(60));
    f.answer_when(|_| false);
    let (items, next) = f.page("type=bucket").await;
    // Five actions: 40 buckets use the 200 questions.
    assert!(items.is_empty());
    assert_eq!(f.fake.questions().len(), 200);
    assert_eq!(
        decode_cursor(next.unwrap().as_bytes(), "bucket"),
        Some("bucket039".to_owned())
    );
}

#[tokio::test]
async fn the_folder_search_is_a_prefix_of_the_id() {
    let backend = Scripted::over(memory(&[
        ("alpha/x", "x"),
        ("alps/x", "x"),
        ("beta/x", "x"),
        ("xalpha/x", "x"),
        ("alpha.txt", "x"),
    ]));
    let f = Fixture::new(vec![instance("b", "b", backend.clone(), "")]);
    let (items, _) = f.page("type=folder&parent=bucket%3Ab&q=alp").await;
    assert_eq!(ids(&items), vec!["alpha", "alps"]);
    let last = backend.calls().last().cloned().unwrap();
    assert_eq!((last.prefix.as_str(), last.delimiter.as_str()), ("alp", "/"));
    for query in ["q=lph", "q=alpha%2Fx", "q=zzz", "q=%ff"] {
        let (items, next) = f.page(&format!("type=folder&parent=bucket%3Ab&{query}")).await;
        assert!(items.is_empty() && next.is_none(), "?{query}");
    }
}

#[tokio::test]
async fn the_subfolders_use_the_root_prefix_and_the_chain_of_the_parent() {
    let backend = Scripted::over(memory(&[
        ("root/reports/2026/q1.csv", "x"),
        ("root/reports/2027/x", "x"),
        ("root/reports/a.txt", "x"),
        ("root/other/9/x", "x"),
        ("outside/reports/2099/x", "x"),
    ]));
    let f = Fixture::new(vec![instance("b", "b", backend.clone(), "root/")]);
    let (items, _) = f.page("type=subfolder&parent=bucket%3Ab%2Ffolder%3Areports").await;
    assert_eq!(ids(&items), vec!["2026", "2027"]);
    assert!(items.iter().all(|item| !item.has_children));
    assert_eq!(backend.calls().last().unwrap().prefix, "root/reports/");
    let q = &f.fake.questions()[0];
    assert_eq!(
        (q.resource_type.as_str(), q.resource_id.as_str()),
        ("subfolder", "2026")
    );
    assert_eq!(q.path, "service:stowr-test/bucket:b/folder:reports/subfolder:2026");
    assert_eq!(q.match_mode, "subtree");
    let (folders, _) = f.page("type=folder&parent=bucket%3Ab").await;
    assert_eq!(ids(&folders), vec!["other", "reports"]);
    assert!(folders.iter().all(|item| item.has_children));
}

#[tokio::test]
async fn an_unknown_parent_gives_no_items() {
    let f = Fixture::new(vec![instance("b", "b", memory(&[("a/x", "x")]), "")]);
    for query in [
        "type=folder&parent=bucket%3Aunknown",
        "type=subfolder&parent=bucket%3Ab%2Ffolder%3Anope",
        "type=subfolder&parent=bucket%3Ab%2Ffolder%3Aa%252Fb",
        "type=subfolder&parent=bucket%3Ab%2Ffolder%3A%25ff",
    ] {
        let (items, next) = f.page(query).await;
        assert!(items.is_empty() && next.is_none(), "?{query}");
    }
    assert_eq!(f.get("type=folder&parent=bucket%3Ab%2F").await.status, 400);
    assert!(
        f.fake.questions().is_empty(),
        "a node that does not exist needs no question"
    );
}

#[tokio::test]
async fn the_parent_is_decoded_two_times() {
    let mut request = OptionsRequest::default();
    request.parse("parent=bucket%3Aa%252Fb&type=folder").unwrap();
    assert_eq!(request.parent, vec![Node::new("bucket", "a/b")]);
    assert!(!request.missing_parent);
    assert_eq!(request.child_type, "folder");
    let mut request = OptionsRequest::default();
    request
        .parse("parent=bucket%3Ab%2Ffolder%3Ax%2By%252Fz&type=subfolder&q=a+b&limit=3")
        .unwrap();
    assert_eq!(
        request.parent,
        vec![Node::new("bucket", "b"), Node::new("folder", "x+y/z")]
    );
    assert_eq!((request.search.as_slice(), request.limit), (&b"a+b"[..], 3));
    assert!(request.missing_parent);
    // The id of an instance can hold "/": the route finds it.
    let f = Fixture::new(vec![instance("a/b", "a/b", memory(&[("f1/x", "x")]), "")]);
    let (items, _) = f.page("type=folder&parent=bucket%3Aa%252Fb").await;
    assert_eq!(ids(&items), vec!["f1"]);
    assert_eq!(f.fake.questions()[0].path, "service:stowr-test/bucket:a%2Fb/folder:f1");
}

#[tokio::test]
async fn a_bad_cursor_gives_400() {
    let f = Fixture::new(vec![instance("b", "b", folders(3), "")]);
    let (_, next) = f.page("type=folder&parent=bucket%3Ab&limit=1").await;
    let next = next.unwrap();
    for query in [
        format!("type=bucket&after={next}"),
        "type=bucket&after=!!!".to_owned(),
        "type=bucket&after=".to_owned(),
        "type=bucket&after=YQ".to_owned(),
        "type=folder&parent=bucket%3Ab&after=Zm9sZGVyAA".to_owned(),
    ] {
        assert_eq!(f.get(&query).await.status, 400, "?{query}");
    }
    assert_eq!(encode_cursor("folder", "f0000"), "Zm9sZGVyAGYwMDAw");
    assert_eq!(decode_cursor(b"Zm9sZGVyAGYwMDAw", "folder"), Some("f0000".to_owned()));
}

#[tokio::test]
async fn an_instance_that_does_not_allow_read_has_no_folders() {
    let backend = Scripted::over(folders(3));
    let mut cfg = block("b", "b", "");
    cfg.permissions = vec![PERMISSION_WRITE.to_owned()];
    let f = Fixture::new(vec![instance_over(cfg, backend.clone())]);
    let (items, next) = f.page("type=folder&parent=bucket%3Ab").await;
    assert!(items.is_empty() && next.is_none());
    assert!(backend.calls().is_empty());
    assert!(f.fake.questions().is_empty());
}

#[tokio::test]
async fn the_scan_of_the_storage_is_bounded_by_max_scan_pages() {
    let backend = Scripted::pages(vec![
        ListPage {
            prefixes: vec!["f1/".into(), "f2/".into()],
            next_page_token: "page-1".into(),
            ..ListPage::default()
        },
        ListPage {
            prefixes: vec!["f3/".into()],
            objects: vec![ObjectInfo {
                key: "f3a".into(),
                ..ObjectInfo::default()
            }],
            next_page_token: "page-2".into(),
        },
        ListPage {
            prefixes: vec!["f4/".into()],
            ..ListPage::default()
        },
    ]);
    let mut cfg = block("b", "b", "");
    cfg.max_scan_pages = 2;
    let f = Fixture::new(vec![instance_over(cfg, backend.clone())]);
    let (items, next) = f.page("type=folder&parent=bucket%3Ab").await;
    assert_eq!(ids(&items), vec!["f1", "f2", "f3"]);
    assert_eq!(backend.calls().len(), 2);
    assert_eq!(backend.calls()[1].page_token, "page-1");
    assert_eq!(
        decode_cursor(next.unwrap().as_bytes(), "folder"),
        Some("f3a".to_owned())
    );

    // A page of objects only gives no folder: the cursor still moves forward.
    let backend = Scripted::pages(vec![
        ListPage {
            objects: vec![
                ObjectInfo {
                    key: "o1".into(),
                    ..ObjectInfo::default()
                },
                ObjectInfo {
                    key: "o2".into(),
                    ..ObjectInfo::default()
                },
            ],
            next_page_token: "page-1".into(),
            ..ListPage::default()
        },
        ListPage {
            prefixes: vec!["z/".into()],
            ..ListPage::default()
        },
    ]);
    let f = Fixture::new(vec![instance("b", "b", backend, "")]);
    let (items, next) = f.page("type=folder&parent=bucket%3Ab").await;
    assert!(items.is_empty());
    assert_eq!(decode_cursor(next.unwrap().as_bytes(), "folder"), Some("o2".to_owned()));
}

#[tokio::test]
async fn a_listing_continues_after_the_cursor() {
    let backend = memory(&[
        ("a-b/x", "x"),
        ("a/x", "x"),
        ("empty/.keep", "x"),
        ("link-in/x", "x"),
        ("file.txt", "x"),
    ]);
    let f = Fixture::new(vec![instance("vol", "vol", backend, "")]);
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let mut query = "type=folder&parent=bucket%3Avol&limit=1".to_owned();
        if let Some(cursor) = &cursor {
            query.push_str(&format!("&after={cursor}"));
        }
        let (items, next) = f.page(&query).await;
        all.extend(ids(&items));
        match next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(all, vec!["a-b", "a", "empty", "link-in"]);
}

#[tokio::test]
async fn the_other_methods_give_405_and_head_gives_no_body() {
    let f = Fixture::new(buckets(1));
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        let got = f.send(method.clone(), "type=bucket").await;
        assert_eq!(got.status, 405, "{method}");
        assert_eq!(got.headers.get("allow").unwrap(), "GET, HEAD");
    }
    assert!(f.fake.questions().is_empty());
    let got = f.send(Method::HEAD, "type=bucket").await;
    assert_eq!(got.status, 200);
    assert!(got.body.is_empty());
    assert_ne!(got.headers.get(CONTENT_LENGTH).unwrap(), "0");
}

#[tokio::test]
async fn the_route_does_not_exist_in_mode_open() {
    let layer = AccessLayer::new(&crate::common::config::Config::default()).unwrap();
    let response = serve(&layer, &buckets(1), &Method::GET, "type=bucket", &OpCtx::default()).await;
    assert_eq!(response.status(), 404);
}

#[test]
fn the_log_line_shows_the_parent_without_the_folder_ids_in_mode_anonymous() {
    let mut request = OptionsRequest::default();
    request
        .parse("type=subfolder&parent=bucket%3Ab%2Ffolder%3Asecret")
        .unwrap();
    assert_eq!(log_parent(&request, false), "bucket:b/folder:-");
    assert_eq!(log_parent(&request, true), "bucket:b/folder:secret");
    let long = OptionsRequest {
        parent_text: "é".repeat(150),
        ..OptionsRequest::default()
    };
    assert!(log_parent(&long, true).len() <= 200);
    assert_eq!(LogMode::default(), LogMode::Anonymous);
}

#[test]
fn the_fields_of_a_bad_request_stay_for_the_log() {
    let mut request = OptionsRequest::default();
    let error = request.parse("type=folder&parent=bucket%3Ab&limit=0").unwrap_err();
    assert!(error.has_code(ERROR_CODE));
    assert_eq!(request.parent, vec![Node::new("bucket", "b")]);
    assert_eq!(request.parent_text, "bucket:b");
}
