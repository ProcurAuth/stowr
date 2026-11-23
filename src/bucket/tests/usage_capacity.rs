//! The tests of the capacity of the storage behind the buckets, and of the answer that takes the more constraining
//! part.

use std::sync::Arc;
use std::time::Duration;

use super::usage::{Clock, FakeReader, GARAGE_TOKEN, MINIO_KEY, garage_reader, minio_reader, usage_instance};
use crate::bucket::testing::{AdminReply, FakeAdmin};
use crate::bucket::usage::{STORAGE_SCOPE_CLUSTER, STORAGE_SCOPE_DISKS, USAGE_RETRY_INTERVAL, usage_answer_of};
use crate::bucket::usage_admin::AdminUrl;
use crate::bucket::usage_seaweedfs::SeaweedFsUsageReader;
use crate::bucket::{BucketUsage, StorageCapacity};
use crate::common::ctx::OpCtx;
use crate::common::error::Error;

const GARAGE_CLUSTER_STATUS: &str = r#"{
  "layoutVersion": 1,
  "nodes": [
    {"id": "c44aa6c7", "garageVersion": "v2.4.1", "addr": "10.0.0.1:3901", "hostname": "n1", "isUp": true, "lastSeenSecsAgo": null,
     "role": {"zone": "dc1", "tags": [], "capacity": 1000000000}, "draining": false,
     "dataPartition": {"available": 3000, "total": 4000}, "metadataPartition": {"available": 3000, "total": 4000}},
    {"id": "d55bb7d8", "garageVersion": "v2.4.1", "addr": "10.0.0.2:3901", "hostname": "n2", "isUp": true, "lastSeenSecsAgo": null,
     "role": {"zone": "dc2", "tags": [], "capacity": 1000000000}, "draining": false,
     "dataPartition": {"available": 1000, "total": 6000}, "metadataPartition": {"available": 1000, "total": 6000}},
    {"id": "e66cc8e9", "garageVersion": "v2.4.1", "addr": "10.0.0.3:3901", "hostname": "gw", "isUp": true, "lastSeenSecsAgo": null,
     "role": {"zone": "dc1", "tags": [], "capacity": null}, "draining": false,
     "dataPartition": {"available": 99999, "total": 99999}, "metadataPartition": null}
  ]
}"#;

fn ctx() -> OpCtx {
    OpCtx::default()
}

#[tokio::test]
async fn the_garage_capacity_adds_the_data_partitions_of_the_storage_nodes() {
    let admin = FakeAdmin::answer(200, GARAGE_CLUSTER_STATUS);
    let capacity = garage_reader(admin.clone()).capacity(&ctx()).await.unwrap();
    assert_eq!(capacity.scope, STORAGE_SCOPE_CLUSTER);
    assert_eq!(
        (capacity.total_bytes, capacity.free_bytes, capacity.used_bytes),
        (10_000, 4_000, 6_000)
    );
    assert!(!capacity.approximate);
    assert!(
        capacity.note.contains("2 storage nodes") && capacity.note.contains("before the replication"),
        "{}",
        capacity.note
    );
    assert!(capacity.as_of.is_some());
    let requests = admin.seen();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v2/GetClusterStatus");
    let authorization = requests[0]
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    assert_eq!(authorization, Some(format!("Bearer {GARAGE_TOKEN}").as_str()));
}

#[tokio::test]
async fn a_garage_node_that_is_down_is_not_counted_and_the_numbers_are_approximate() {
    let down = GARAGE_CLUSTER_STATUS.replacen(
        r#""hostname": "n2", "isUp": true"#,
        r#""hostname": "n2", "isUp": false"#,
        1,
    );
    let capacity = garage_reader(FakeAdmin::answer(200, &down))
        .capacity(&ctx())
        .await
        .unwrap();
    assert_eq!(capacity.total_bytes, 4000);
    assert!(capacity.approximate);
    assert_eq!(
        capacity.approximate_reason,
        "1 storage node did not give a data partition: it is not counted."
    );
}

#[tokio::test]
async fn a_garage_cluster_without_a_storage_node_or_with_a_refused_token_gives_no_capacity() {
    let empty = garage_reader(FakeAdmin::answer(200, r#"{"layoutVersion": 0, "nodes": []}"#));
    assert!(empty.capacity(&ctx()).await.is_err());
    let refused = garage_reader(FakeAdmin::answer(
        403,
        r#"{"code":"AccessDenied","message":"Forbidden"}"#,
    ));
    let error = refused.capacity(&ctx()).await.err().unwrap().to_string();
    assert!(
        !error.contains(GARAGE_TOKEN) && !error.contains("admin.test"),
        "{error}"
    );
}

const SEAWEED_VOLUME_SERVER_STATUS: &str = concat!(
    r#"{"DiskStatuses":[{"dir":"/data","all":4294967296,"used":131072,"free":4294836224,"percent_free":99.99695,"percent_used":0.0030517578},"#,
    r#"{"dir":"/data","all":4294967296,"used":131072,"free":4294836224,"percent_free":99.99695,"percent_used":0.0030517578},"#,
    r#"{"dir":"/ssd","all":1000,"used":600,"free":400,"percent_free":40,"percent_used":60}],"Version":"30GB 4.41 de34a1a8","Volumes":null}"#
);

/// The answer of `GET /dir/status` of the master with volume servers at these addresses.
fn seaweed_dir_status(addresses: &[&str]) -> String {
    let nodes: Vec<String> = addresses
        .iter()
        .map(|address| {
            format!(
                r#"{{"Url":"{address}","PublicUrl":"{address}","Volumes":0,"EcShards":0,"Max":30,"VolumeIds":" "}}"#
            )
        })
        .collect();
    format!(
        r#"{{"Topology":{{"Max":30,"Free":30,"DataCenters":[{{"Id":"DefaultDataCenter","Racks":[{{"Id":"DefaultRack","DataNodes":[{}]}}]}}],"Layouts":null}},"TopologyId":"a009a099","Version":"30GB 4.41 de34a1a8"}}"#,
        nodes.join(",")
    )
}

fn seaweed_master(admin: Arc<FakeAdmin>) -> SeaweedFsUsageReader {
    SeaweedFsUsageReader {
        master: AdminUrl::parse("usage", "http://127.0.0.1:9333").unwrap(),
        filer: None,
        transport: admin,
    }
}

#[tokio::test]
async fn the_seaweedfs_capacity_asks_each_volume_server_of_the_master() {
    // The volume server gives the loopback address of "weed server -ip=127.0.0.1": the reader asks the host of the
    // master at that port. It is the same server as the second address. A third volume server does not answer.
    let dir = seaweed_dir_status(&["localhost:8080", "127.0.0.1:8080", "10.9.9.9:8081"]);
    let admin = FakeAdmin::new(move |recorded| match recorded.url.as_str() {
        "http://127.0.0.1:9333/dir/status" => AdminReply::Answer(200, dir.clone()),
        "http://127.0.0.1:8080/status" => AdminReply::Answer(200, SEAWEED_VOLUME_SERVER_STATUS.to_owned()),
        _ => AdminReply::Failure(crate::bucket::usage_admin::AdminFailure::Connect),
    });
    let capacity = seaweed_master(admin.clone()).capacity(&ctx()).await.unwrap();
    assert_eq!(capacity.scope, STORAGE_SCOPE_DISKS);
    assert_eq!(
        (capacity.total_bytes, capacity.used_bytes, capacity.free_bytes),
        (4_294_968_296, 131_672, 4_294_836_624)
    );
    assert!(capacity.approximate);
    assert_eq!(
        capacity.approximate_reason,
        "1 volume server did not answer: it is not counted."
    );
    assert!(capacity.note.contains("1 volume server"), "{}", capacity.note);
    let requests = admin.seen();
    assert_eq!(
        requests.iter().filter(|request| request.path == "/dir/status").count(),
        1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url == "http://127.0.0.1:8080/status")
            .count(),
        1
    );
}

#[tokio::test]
async fn a_seaweedfs_master_without_a_volume_server_gives_no_capacity() {
    let dir = seaweed_dir_status(&[]);
    let reader = seaweed_master(FakeAdmin::answer(200, &dir));
    assert!(reader.capacity(&ctx()).await.is_err());
}

#[tokio::test]
async fn the_seaweedfs_capacity_asks_at_most_64_volume_servers() {
    let addresses: Vec<String> = (0..70).map(|index| format!("10.0.0.{index}:8080")).collect();
    let refs: Vec<&str> = addresses.iter().map(String::as_str).collect();
    let dir = seaweed_dir_status(&refs);
    let admin = FakeAdmin::new(move |recorded| {
        if recorded.path == "/dir/status" {
            AdminReply::Answer(200, dir.clone())
        } else {
            AdminReply::Answer(200, SEAWEED_VOLUME_SERVER_STATUS.to_owned())
        }
    });
    let capacity = seaweed_master(admin.clone()).capacity(&ctx()).await.unwrap();
    assert!(capacity.approximate);
    assert_eq!(
        capacity.approximate_reason,
        "Stowr asks 64 volume servers at most: 6 are not counted."
    );
    assert_eq!(
        admin.seen().iter().filter(|request| request.path == "/status").count(),
        64
    );
    assert!(capacity.note.contains("64 volume servers"), "{}", capacity.note);
}

const MINIO_STORAGE_INFO: &str = concat!(
    r#"{"Disks":[{"endpoint":"/data","path":"/data","state":"ok","uuid":"359b0251","major":0,"minor":391,"totalspace":4294967296,"usedspace":45056,"availspace":4294922240,"#,
    r#""metrics":{"lastMinute":{"DiskInfo":{"count":15,"acc_time_ns":142464}},"apiCalls":{"DiskInfo":16}},"used_inodes":13,"free_inodes":105698247,"local":true,"pool_index":0,"set_index":0,"disk_index":0},"#,
    r#"{"endpoint":"/data2","path":"/data2","state":"offline","uuid":"","totalspace":0,"usedspace":0,"availspace":0}],"#,
    r#""Backend":{"Type":2,"GatewayOnline":false,"OnlineDisks":null,"OfflineDisks":null,"StandardSCData":[1],"StandardSCParities":null,"RRSCData":[1],"RRSCParities":null,"TotalSets":[1],"DrivesPerSet":[2],"StandardSCParity":2,"RRSCParity":0}}"#
);

#[tokio::test]
async fn the_minio_capacity_adds_the_online_drives() {
    let admin = FakeAdmin::answer(200, MINIO_STORAGE_INFO);
    let capacity = minio_reader(admin.clone()).capacity(&ctx()).await.unwrap();
    assert_eq!(capacity.scope, STORAGE_SCOPE_DISKS);
    assert_eq!(
        (capacity.total_bytes, capacity.used_bytes, capacity.free_bytes),
        (4_294_967_296, 45_056, 4_294_922_240)
    );
    assert_eq!(
        capacity.note,
        "raw capacity of 1 drive, before the erasure code (parity EC:2)"
    );
    assert!(capacity.approximate);
    assert_eq!(capacity.approximate_reason, "1 drive is offline: it is not counted.");
    let requests = admin.seen();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/minio/admin/v3/storageinfo");
    let authorization = requests[0]
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        authorization.starts_with(&format!("AWS4-HMAC-SHA256 Credential={MINIO_KEY}/")),
        "{authorization}"
    );
    let refused = minio_reader(FakeAdmin::answer(
        403,
        r#"{"Code":"AccessDenied","Message":"Access Denied."}"#,
    ));
    let error = refused.capacity(&ctx()).await.err().unwrap().to_string();
    assert!(
        !error.contains("minio-secret-value") && !error.contains("admin.test"),
        "{error}"
    );
}

#[tokio::test]
async fn a_minio_server_without_an_online_drive_gives_no_capacity() {
    let body = r#"{"Disks":[{"state":"offline","totalspace":0}],"Backend":{}}"#;
    assert!(
        minio_reader(FakeAdmin::answer(200, body))
            .capacity(&ctx())
            .await
            .is_err()
    );
    let two = r#"{"Disks":[{"state":"offline"},{"state":"offline"},{"state":"ok","totalspace":10,"usedspace":1,"availspace":9}]}"#;
    let capacity = minio_reader(FakeAdmin::answer(200, two))
        .capacity(&ctx())
        .await
        .unwrap();
    assert_eq!(
        capacity.approximate_reason,
        "2 drives are offline: they are not counted."
    );
    assert_eq!(capacity.note, "raw capacity of 1 drive, before the erasure code");
}

// --- The answer with the two parts --------------------------------------------------------------------------------

fn storage(used: i64, total: i64) -> StorageCapacity {
    StorageCapacity {
        scope: STORAGE_SCOPE_CLUSTER.to_owned(),
        used_bytes: used,
        total_bytes: total,
        free_bytes: total - used,
        note: "raw".to_owned(),
        ..StorageCapacity::default()
    }
}

#[tokio::test]
async fn the_answer_takes_the_more_constraining_part() {
    struct Case {
        name: &'static str,
        value: Result<BucketUsage, Error>,
        storage: Result<StorageCapacity, Error>,
        percent: f64,
        level: &'static str,
        constraint: &'static str,
        quota: f64,
    }
    let bucket = |used, limit| {
        Ok(BucketUsage {
            used_bytes: used,
            limit_bytes: limit,
            ..BucketUsage::default()
        })
    };
    let cases = vec![
        Case {
            name: "storage over quota",
            value: bucket(50, 100),
            storage: Ok(storage(910, 1000)),
            percent: 91.0,
            level: "warning",
            constraint: "storage",
            quota: 50.0,
        },
        Case {
            name: "quota over storage",
            value: bucket(93, 100),
            storage: Ok(storage(100, 1000)),
            percent: 93.0,
            level: "warning",
            constraint: "quota",
            quota: 93.0,
        },
        Case {
            name: "no quota",
            value: bucket(93, 0),
            storage: Ok(storage(960, 1000)),
            percent: 96.0,
            level: "error",
            constraint: "storage",
            quota: 0.0,
        },
        Case {
            name: "no limit at all",
            value: bucket(93, 0),
            storage: Err(Error::internal("down")),
            percent: 0.0,
            level: "",
            constraint: "",
            quota: 0.0,
        },
        Case {
            name: "bucket part failed",
            value: Err(Error::internal("GetBucketInfo: down")),
            storage: Ok(storage(500, 1000)),
            percent: 50.0,
            level: "ok",
            constraint: "storage",
            quota: 0.0,
        },
        Case {
            name: "storage part failed",
            value: bucket(10, 100),
            storage: Err(Error::internal("GetClusterStatus: down")),
            percent: 10.0,
            level: "ok",
            constraint: "quota",
            quota: 10.0,
        },
    ];
    for case in cases {
        let value = case.value.clone();
        let reader = Arc::new(
            FakeReader::new()
                .with_behavior_result(value)
                .with_capacity(case.storage.clone()),
        );
        let instance = usage_instance(reader, 0);
        let answer = usage_answer_of(&instance, &instance.usage_read(&ctx(), false).await);
        assert_eq!(
            (
                answer.percent,
                answer.level.as_str(),
                answer.constraint.as_str(),
                answer.quota_percent
            ),
            (case.percent, case.level, case.constraint, case.quota),
            "{}",
            case.name
        );
        assert_eq!(case.value.is_err(), answer.error.is_some(), "{}", case.name);
        assert_eq!(case.value.is_err(), !answer.available, "{}", case.name);
        assert_eq!(case.storage.is_err(), answer.storage_error.is_some(), "{}", case.name);
        assert_eq!(case.storage.is_err(), answer.storage.is_none(), "{}", case.name);
        if let Some(part) = &answer.storage {
            assert_eq!(part.free_bytes, part.total_bytes - part.used_bytes, "{}", case.name);
            assert_eq!(part.note, "raw", "{}", case.name);
        }
    }
    // A reader without a storage part gives no storage.
    let instance = usage_instance(Arc::new(FakeReader::new()), 0);
    let answer = usage_answer_of(&instance, &instance.usage_read(&ctx(), false).await);
    assert!(answer.storage.is_none() && answer.storage_error.is_none());
    assert_eq!(answer.constraint, "quota");
}

#[tokio::test]
async fn the_cache_keeps_a_failed_part_for_the_retry_interval_only() {
    let reader = Arc::new(FakeReader::new().with_capacity(Err(Error::internal("down"))));
    let instance = usage_instance(reader.clone(), 0);
    let clock = Clock::new();
    clock.install(&instance);
    let result = instance.usage_read(&ctx(), false).await;
    assert!(result.storage_error.is_some() && result.error.is_none());
    reader.set_capacity(Ok(StorageCapacity {
        total_bytes: 10,
        used_bytes: 5,
        ..StorageCapacity::default()
    }));
    clock.advance(USAGE_RETRY_INTERVAL / 2);
    assert!(
        instance.usage_read(&ctx(), false).await.storage.is_none(),
        "the cache did not keep the failed read for the retry interval"
    );
    clock.advance(USAGE_RETRY_INTERVAL);
    let result = instance.usage_read(&ctx(), false).await;
    assert_eq!(
        result.storage.map(|value| value.total_bytes),
        Some(10),
        "the cache kept a failure longer than the retry interval"
    );
    assert_eq!(Duration::from_secs(10), USAGE_RETRY_INTERVAL);
}
