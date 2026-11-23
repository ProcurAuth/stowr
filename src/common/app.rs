//! The application: the configuration, the storage instances and the managers that live in the memory of the
//! process. The module `server` builds it at start (`crate::server::build_app`).

use std::collections::BTreeMap;
use std::sync::Arc;

use super::config::Config;
use super::error::{Error, Result};

/// The application.
pub struct App {
    /// The configuration.
    pub config: Arc<Config>,
    /// The instances: the buckets, then the volumes, each in the order of the file.
    pub instances: Vec<Arc<crate::instance::Instance>>,
    /// The shared provider clients of the `auth` blocks, by label.
    pub auths: BTreeMap<String, Arc<crate::provider::SharedAuth>>,
    /// The background jobs.
    pub jobs: crate::jobs::JobManager,
    /// The upload sessions.
    pub uploads: crate::uploads::UploadManager,
    /// The SQLite preview sessions.
    pub sqlite: crate::pv_data::SqliteSessions,
    /// The access policy: the identity token, the PDP and the action document.
    pub access: crate::access::AccessLayer,
    /// The random key of the resume tokens of the instances without a credential (a volume).
    pub resume_token_key: [u8; 32],
}

impl App {
    /// The instance with this id, or `404 unknown_instance`.
    pub fn instance(&self, id: &str) -> Result<&Arc<crate::instance::Instance>> {
        self.instances
            .iter()
            .find(|instance| instance.cfg.id == id)
            .ok_or_else(|| {
                Error::api(
                    404,
                    "unknown_instance",
                    format!("storage instance {id:?} does not exist"),
                )
            })
    }

    /// The instance of a request: the instance of the body, else the query parameter `instance`, else the first
    /// instance.
    pub fn instance_of(&self, body_instance: &str, query_instance: &str) -> Result<&Arc<crate::instance::Instance>> {
        let mut id = body_instance.trim();
        if id.is_empty() {
            id = query_instance.trim();
        }
        if id.is_empty() {
            id = self.instances.first().map_or("", |instance| instance.cfg.id.as_str());
        }
        self.instance(id)
    }
}
