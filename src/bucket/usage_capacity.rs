//! The capacity of the storage behind the buckets, for the usage readers that can read it. The numbers are raw. The
//! replication or the erasure code of the provider uses more than one byte of the disks for one byte of an object.
//! Each request is a `GET` of the admin API of the `usage` block, with the same credentials and the same size limits.
//!
//! Measured on the test stack (each provider on a tmpfs of 4 GiB):
//!
//! - Garage v2.4.1: see `usage_garage` (`GetClusterStatus`).
//! - SeaweedFS 4.41: the master gives no bytes of the disks: `GET /dir/status` gives the volume servers in
//!   `Topology: {DataCenters: [{Racks: [{DataNodes: [{Url, PublicUrl, Max, ...}]}]}]}` with the counts of volumes.
//!   `GET http://<volume server>/status` gives `DiskStatuses: [{dir, all, used, free, percent_used}]`: the file
//!   system of each folder of the volume server. A volume server that listens on a loopback address is on the host
//!   of the master. The reader then asks the host of the master, at the port of the volume server.
//! - MinIO RELEASE.2025-10-15T17-29-55Z: `GET /minio/admin/v3/storageinfo` gives `Disks: [{state, totalspace,
//!   usedspace, availspace, ...}]` and `Backend: {StandardSCParity, ...}`. `usedspace` + `availspace` can be less
//!   than `totalspace`: the file system keeps blocks for itself.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use http::HeaderMap;
use http::header::{ACCEPT, HeaderValue};
use serde::Deserialize;
use tokio::task::JoinSet;

use super::StorageCapacity;
use super::usage::STORAGE_SCOPE_DISKS;
use super::usage_admin::{AdminError, AdminTransport, get_usage_json, join_host_port, split_host_port};
use super::usage_minio::MinioUsageReader;
use super::usage_seaweedfs::SeaweedFsUsageReader;
use crate::common::ctx::OpCtx;
use crate::common::time::Timestamp;

/// The size limit of the answer of `/dir/status` and `/status`.
const MAX_CAPACITY_ANSWER_BYTES: usize = 1 << 20;
/// The size limit of `storageinfo`: it has the metrics of each drive.
const MAX_MINIO_STORAGE_INFO_BYTES: usize = 16 << 20;
/// The largest number of volume servers that one read asks.
pub const MAX_SEAWEEDFS_VOLUME_SERVERS: usize = 64;
/// The number of requests to the volume servers that run at the same time.
const CAPACITY_WORKERS: usize = 4;

/// `1 node` or `3 nodes`.
pub fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// `it is` or `they are`.
pub fn pronoun(count: usize) -> &'static str {
    if count == 1 { "it is" } else { "they are" }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DiskStatus {
    dir: String,
    all: i64,
    used: i64,
    free: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct VolumeServerStatus {
    #[serde(rename = "DiskStatuses")]
    disk_statuses: Option<Vec<DiskStatus>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DirStatus {
    #[serde(rename = "Topology")]
    topology: Option<Topology>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Topology {
    #[serde(rename = "DataCenters")]
    data_centers: Option<Vec<DataCenter>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DataCenter {
    #[serde(rename = "Racks")]
    racks: Option<Vec<Rack>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Rack {
    #[serde(rename = "DataNodes")]
    data_nodes: Option<Vec<DataNode>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DataNode {
    #[serde(rename = "Url")]
    url: String,
    #[serde(rename = "PublicUrl")]
    public_url: String,
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|address| address.is_loopback())
}

impl SeaweedFsUsageReader {
    /// The address (`host:port`) of each volume server of the master, one time each. A loopback address is the host
    /// of the master, at the port of the volume server.
    async fn volume_servers(&self, ctx: &OpCtx) -> std::result::Result<Vec<String>, AdminError> {
        let url = self.master.join(&["dir", "status"]);
        let answer: DirStatus = get_usage_json(
            self.transport.as_ref(),
            ctx,
            &url,
            accept_json(),
            "master status",
            MAX_CAPACITY_ANSWER_BYTES,
        )
        .await?;
        let mut servers = Vec::new();
        let mut seen = BTreeSet::new();
        let centers = answer
            .topology
            .and_then(|topology| topology.data_centers)
            .unwrap_or_default();
        for center in centers {
            for rack in center.racks.unwrap_or_default() {
                for node in rack.data_nodes.unwrap_or_default() {
                    let address = if node.url.is_empty() { node.public_url } else { node.url };
                    let Some((host, port)) = split_host_port(&address) else {
                        continue;
                    };
                    if port.is_empty() {
                        continue;
                    }
                    let host = if is_loopback_host(host) {
                        self.master.hostname()
                    } else {
                        host
                    };
                    let address = join_host_port(host, port);
                    if seen.insert(address.clone()) {
                        servers.push(address);
                    }
                }
            }
        }
        Ok(servers)
    }

    /// The capacity of the disks of the volume servers.
    pub async fn capacity(&self, ctx: &OpCtx) -> std::result::Result<StorageCapacity, AdminError> {
        let servers = self.volume_servers(ctx).await?;
        if servers.is_empty() {
            return Err(AdminError::message("volume servers: the master knows no volume server"));
        }
        let asked: Vec<String> = servers.iter().take(MAX_SEAWEEDFS_VOLUME_SERVERS).cloned().collect();
        let mut disks: Vec<Option<Vec<DiskStatus>>> = (0..asked.len()).map(|_| None).collect();
        let mut work = JoinSet::new();
        let mut next = 0usize;
        while next < asked.len() || !work.is_empty() {
            while next < asked.len() && work.len() < CAPACITY_WORKERS {
                let index = next;
                next += 1;
                let transport = self.transport.clone();
                let ctx = ctx.clone();
                let url = format!("{}://{}/status", self.master.scheme, asked[index]);
                work.spawn(async move { (index, disk_status(transport, ctx, url).await) });
            }
            if let Some(joined) = work.join_next().await
                && let Ok((index, status)) = joined
            {
                disks[index] = status;
            }
        }
        let mut capacity = StorageCapacity {
            scope: STORAGE_SCOPE_DISKS.to_owned(),
            as_of: Some(Timestamp::now()),
            ..StorageCapacity::default()
        };
        let (mut counted, mut missing) = (0usize, 0usize);
        for status in &disks {
            let Some(status) = status else {
                missing += 1;
                continue;
            };
            counted += 1;
            let mut seen = BTreeSet::new();
            for disk in status {
                if disk.all <= 0 || !seen.insert(disk.dir.clone()) {
                    continue;
                }
                capacity.total_bytes += disk.all;
                capacity.used_bytes += disk.used.max(0);
                capacity.free_bytes += disk.free.max(0);
            }
        }
        if counted == 0 || capacity.total_bytes == 0 {
            return Err(AdminError::message(
                "volume server status: no volume server gives its disks",
            ));
        }
        capacity.note = format!(
            "raw capacity of the disks of {}, before the replication",
            plural(counted, "volume server")
        );
        if missing > 0 {
            capacity.approximate = true;
            capacity.approximate_reason = format!(
                "{} did not answer: {} not counted.",
                plural(missing, "volume server"),
                pronoun(missing)
            );
        } else if servers.len() > asked.len() {
            capacity.approximate = true;
            capacity.approximate_reason = format!(
                "Stowr asks {MAX_SEAWEEDFS_VOLUME_SERVERS} volume servers at most: {} are not counted.",
                servers.len() - asked.len()
            );
        }
        Ok(capacity)
    }
}

fn accept_json() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers
}

/// Read the disks of one volume server, with the scheme of the master. A failure gives `None`.
async fn disk_status(transport: Arc<dyn AdminTransport>, ctx: OpCtx, url: String) -> Option<Vec<DiskStatus>> {
    let answer: VolumeServerStatus = get_usage_json(
        transport.as_ref(),
        &ctx,
        &url,
        accept_json(),
        "volume server status",
        MAX_CAPACITY_ANSWER_BYTES,
    )
    .await
    .ok()?;
    Some(answer.disk_statuses.unwrap_or_default())
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct StorageInfo {
    #[serde(rename = "Disks")]
    disks: Option<Vec<MinioDisk>>,
    #[serde(rename = "Backend")]
    backend: Option<MinioBackend>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct MinioDisk {
    state: String,
    totalspace: i64,
    usedspace: i64,
    availspace: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct MinioBackend {
    #[serde(rename = "StandardSCParity")]
    standard_sc_parity: i64,
}

impl MinioUsageReader {
    /// The capacity of the online drives.
    pub async fn capacity(&self, ctx: &OpCtx) -> std::result::Result<StorageCapacity, AdminError> {
        let answer: StorageInfo = self.get(ctx, "storageinfo", &[], MAX_MINIO_STORAGE_INFO_BYTES).await?;
        let mut capacity = StorageCapacity {
            scope: STORAGE_SCOPE_DISKS.to_owned(),
            as_of: Some(Timestamp::now()),
            ..StorageCapacity::default()
        };
        let (mut counted, mut missing) = (0usize, 0usize);
        for disk in answer.disks.unwrap_or_default() {
            if disk.state != "ok" || disk.totalspace <= 0 {
                missing += 1;
                continue;
            }
            counted += 1;
            capacity.total_bytes += disk.totalspace;
            capacity.used_bytes += disk.usedspace.max(0);
            capacity.free_bytes += disk.availspace.max(0);
        }
        if counted == 0 {
            return Err(AdminError::message("storageinfo: no drive is online"));
        }
        capacity.note = format!("raw capacity of {}, before the erasure code", plural(counted, "drive"));
        let parity = answer.backend.map_or(0, |backend| backend.standard_sc_parity);
        if parity > 0 {
            capacity.note.push_str(&format!(" (parity EC:{parity})"));
        }
        if missing > 0 {
            capacity.approximate = true;
            capacity.approximate_reason = format!(
                "{} {} offline: {} not counted.",
                plural(missing, "drive"),
                if missing == 1 { "is" } else { "are" },
                pronoun(missing)
            );
        }
        Ok(capacity)
    }
}
