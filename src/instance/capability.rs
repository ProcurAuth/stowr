// SPDX-License-Identifier: MIT OR Apache-2.0
//! The permissions of an instance: their states, the states at start, the merge of a discovery, and the states of
//! the operations of the interface (docs/SECURITY-MODEL.md, "Permission enforcement").

use std::collections::BTreeMap;

use crate::common::config::{BucketConfig, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::error::Error;
use crate::common::storage::{Capabilities, CapabilityState, CapabilityStateName, DiscoveredCapabilities};
use crate::common::time::Timestamp;

/// The three permissions, in the order of the answers.
pub const PERMISSIONS: [&str; 3] = [PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE];

/// The time in seconds that a denial of one provider call stays in the answers.
pub const OBSERVED_DENIAL_SECONDS: i64 = 60;

/// The reason of a permission that no check proved.
pub const REASON_NOT_TESTED: &str =
    "the provider permission has not been tested; the action remains available and will be verified when used";
/// The reason of a permission that the configuration lets, before any check.
pub const REASON_CONFIGURED: &str =
    "the permission is enabled by the configuration ceiling and will be verified when used";
/// The reason of a denial of `force_read_only`.
pub const REASON_FORCE_READ_ONLY: &str = "mutations are disabled by the administrative force_read_only policy";
/// The reason of a denial of the configuration.
pub const REASON_CONFIGURATION: &str = "action is disabled by the storage permission ceiling";

/// A state with the rules of the answers: `unknown` lets the action and proves nothing, `allowed` lets it, `denied`
/// refuses it. A state without a name gets one from its flags.
pub fn normalized(mut state: CapabilityState, named: bool) -> CapabilityState {
    if !named {
        state.state = match (state.verified, state.allowed) {
            (true, true) => CapabilityStateName::Allowed,
            (true, false) => CapabilityStateName::Denied,
            _ => CapabilityStateName::Unknown,
        };
    }
    match state.state {
        CapabilityStateName::Unknown => {
            state.allowed = true;
            state.verified = false;
        }
        CapabilityStateName::Allowed => state.allowed = true,
        CapabilityStateName::Denied => state.allowed = false,
    }
    state
}

/// A permission that no check proved: the action stays available.
pub fn unknown(source: &str, reason: &str) -> CapabilityState {
    CapabilityState {
        state: CapabilityStateName::Unknown,
        allowed: true,
        verified: false,
        source: source.to_owned(),
        reason: reason.to_owned(),
        expires: None,
    }
}

/// An allowed permission.
pub fn allowed(source: &str, reason: &str, verified: bool) -> CapabilityState {
    CapabilityState {
        state: CapabilityStateName::Allowed,
        allowed: true,
        verified,
        source: source.to_owned(),
        reason: reason.to_owned(),
        expires: None,
    }
}

/// A denied permission.
pub fn denied(source: &str, reason: &str, verified: bool) -> CapabilityState {
    CapabilityState {
        state: CapabilityStateName::Denied,
        allowed: false,
        verified,
        source: source.to_owned(),
        reason: reason.to_owned(),
        expires: None,
    }
}

/// The state of one permission of a set (`read`, `write` or `delete`), or an empty state for another name.
pub fn state_of(caps: &Capabilities, name: &str) -> CapabilityState {
    match name {
        PERMISSION_READ => caps.read.clone(),
        PERMISSION_WRITE => caps.write.clone(),
        PERMISSION_DELETE => caps.delete.clone(),
        _ => CapabilityState::default(),
    }
}

/// Set the state of one permission of a set, with the rules of [`normalized`].
pub fn set_state(caps: &mut Capabilities, name: &str, state: CapabilityState) {
    let state = normalized(state, true);
    match name {
        PERMISSION_READ => caps.read = state,
        PERMISSION_WRITE => caps.write = state,
        PERMISSION_DELETE => caps.delete = state,
        _ => {}
    }
}

/// True when the configuration names the permission, or has no `permissions` key.
fn configured(cfg: &BucketConfig, name: &str) -> bool {
    !cfg.permissions_defined || cfg.permissions.iter().any(|value| value == name)
}

/// The permissions at start: `force_read_only` and the configuration, and no check of the provider.
pub fn initial_capabilities(cfg: &BucketConfig, force_read_only: bool) -> Capabilities {
    let mut out = Capabilities::default();
    for name in PERMISSIONS {
        if force_read_only && name != PERMISSION_READ {
            set_state(&mut out, name, denied("runtime", REASON_FORCE_READ_ONLY, true));
            continue;
        }
        if !configured(cfg, name) {
            set_state(&mut out, name, denied("configuration", REASON_CONFIGURATION, true));
            continue;
        }
        let reason = if cfg.permissions_defined {
            REASON_CONFIGURED
        } else {
            REASON_NOT_TESTED
        };
        set_state(&mut out, name, unknown("credentials", reason));
    }
    out
}

/// The permissions after a discovery: `force_read_only` and the configuration first, then the states that the
/// discovery proved. A failed discovery keeps each action available, with the public text of the error.
pub fn merge_capabilities(
    cfg: &BucketConfig,
    force_read_only: bool,
    discovered: &DiscoveredCapabilities,
    discovery_error: Option<&Error>,
) -> Capabilities {
    let public_error = discovery_error.map(Error::public_message).unwrap_or_default();
    let mut permissions = discovered.permissions.clone();
    permissions.sort();
    let mut out = Capabilities {
        permissions,
        checked_at: Some(Timestamp::now()),
        error: public_error.clone(),
        ..Capabilities::default()
    };
    for name in PERMISSIONS {
        if force_read_only && name != PERMISSION_READ {
            set_state(&mut out, name, denied("runtime", REASON_FORCE_READ_ONLY, true));
            continue;
        }
        if !configured(cfg, name) {
            set_state(&mut out, name, denied("configuration", REASON_CONFIGURATION, true));
            continue;
        }
        if let Some(found) = discovered.states.get(name) {
            // A back end gives the flags of a discovered state: the name comes from them.
            let found = normalized(found.clone(), false);
            if found.verified {
                set_state(&mut out, name, found);
                continue;
            }
            let reason = if found.reason.is_empty() {
                "the provider cannot verify this permission without executing the real operation"
            } else {
                found.reason.as_str()
            };
            set_state(&mut out, name, unknown(&found.source, reason));
            continue;
        }
        let reason = match discovery_error {
            Some(_) => format!("permission discovery failed; the action remains tentable: {public_error}"),
            None => REASON_NOT_TESTED.to_owned(),
        };
        set_state(&mut out, name, unknown("credentials", &reason));
    }
    out
}

/// The state of an operation that needs several permissions: the first denial, else `unknown` when one state is
/// unknown, else `allowed`. The reasons are joined without repetition.
pub fn combine(states: &[&CapabilityState]) -> CapabilityState {
    if states.is_empty() {
        return denied("application", "operation is not implemented", true);
    }
    let mut unknown_seen = false;
    let mut reasons: Vec<String> = Vec::with_capacity(states.len());
    for state in states {
        let state = normalized((*state).clone(), true);
        if !state.reason.is_empty() && !reasons.contains(&state.reason) {
            reasons.push(state.reason.clone());
        }
        match state.state {
            CapabilityStateName::Denied => return denied(&state.source, &state.reason, state.verified),
            CapabilityStateName::Unknown => unknown_seen = true,
            CapabilityStateName::Allowed => {}
        }
    }
    let reason = reasons.join("; ");
    if unknown_seen {
        unknown("derived", &reason)
    } else {
        allowed("derived", &reason, true)
    }
}

/// The states of the operations of the interface, from the three permissions.
pub fn operation_capabilities(caps: &Capabilities) -> BTreeMap<String, CapabilityState> {
    let (read, write, remove) = (&caps.read, &caps.write, &caps.delete);
    let mut out = BTreeMap::new();
    for name in ["list", "preview", "download"] {
        out.insert(name.to_owned(), read.clone());
    }
    for name in ["upload", "overwrite", "createFolder"] {
        out.insert(name.to_owned(), write.clone());
    }
    out.insert("copy".to_owned(), combine(&[read, write]));
    out.insert("move".to_owned(), combine(&[read, write, remove]));
    out.insert("rename".to_owned(), combine(&[read, write, remove]));
    out.insert("delete".to_owned(), remove.clone());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(permissions: &[&str]) -> BucketConfig {
        BucketConfig {
            permissions_defined: true,
            permissions: permissions.iter().map(|value| (*value).to_owned()).collect(),
            ..BucketConfig::default()
        }
    }

    #[test]
    fn the_permissions_at_start_come_from_the_configuration_without_a_probe() {
        let caps = initial_capabilities(&config(&[PERMISSION_READ, PERMISSION_WRITE]), false);
        assert!(caps.read.allowed && caps.write.allowed && !caps.delete.allowed);
        assert!(caps.checked_at.is_none());
        assert!(!caps.read.verified && !caps.write.verified);
        assert!(caps.delete.verified);
        assert_eq!(caps.delete.state, CapabilityStateName::Denied);
        assert_eq!(caps.delete.source, "configuration");
        assert_eq!(caps.read.state, CapabilityStateName::Unknown);
        assert!(caps.read.reason.contains("verified when used"));
    }

    #[test]
    fn force_read_only_is_an_administrative_ceiling() {
        let caps = initial_capabilities(&BucketConfig::default(), true);
        assert_eq!(caps.read.state, CapabilityStateName::Unknown);
        assert!(caps.read.allowed);
        for state in [&caps.write, &caps.delete] {
            assert_eq!(state.state, CapabilityStateName::Denied);
            assert!(!state.allowed && state.verified);
            assert_eq!(state.source, "runtime");
        }
    }

    #[test]
    fn the_errors_of_a_discovery_are_public_safe() {
        let error = Error::Connect(
            "gcs request failed: cannot get https://internal.example.test/storage/v1/b/private: connection refused"
                .to_owned(),
        );
        let caps = merge_capabilities(
            &config(&[PERMISSION_READ]),
            false,
            &DiscoveredCapabilities::default(),
            Some(&error),
        );
        for value in [&caps.error, &caps.read.reason, &caps.write.reason, &caps.delete.reason] {
            assert!(!value.contains("internal.example.test"), "{value}");
            assert!(!value.contains("/storage/v1/"), "{value}");
        }
        assert_eq!(
            caps.error,
            "unable to connect to or authenticate with the storage provider"
        );
        assert!(caps.read.reason.starts_with("permission discovery failed"));
        let upstream = Error::upstream(403, "AccessDenied", "bucket secret details");
        assert_eq!(
            upstream.public_message(),
            "the storage provider returned HTTP 403 (AccessDenied)"
        );
    }

    #[test]
    fn a_verified_discovery_sets_the_state_and_an_unverified_one_stays_unknown() {
        let mut discovered = DiscoveredCapabilities::default();
        discovered.states.insert(
            PERMISSION_READ.to_owned(),
            denied("provider", "the probe is denied", true),
        );
        discovered
            .states
            .insert(PERMISSION_WRITE.to_owned(), unknown("provider", ""));
        discovered.permissions = vec!["b".to_owned(), "a".to_owned()];
        let caps = merge_capabilities(&BucketConfig::default(), false, &discovered, None);
        assert_eq!(caps.read.state, CapabilityStateName::Denied);
        assert_eq!(caps.write.state, CapabilityStateName::Unknown);
        assert_eq!(
            caps.write.reason,
            "the provider cannot verify this permission without executing the real operation"
        );
        assert_eq!(caps.delete.reason, REASON_NOT_TESTED);
        assert_eq!(caps.permissions, vec!["a", "b"]);
        assert!(caps.checked_at.is_some());
    }

    #[test]
    fn an_operation_needs_each_of_its_permissions() {
        let caps = initial_capabilities(&config(&[PERMISSION_READ, PERMISSION_WRITE]), false);
        let operations = operation_capabilities(&caps);
        assert_eq!(operations["copy"].state, CapabilityStateName::Unknown);
        assert_eq!(operations["copy"].source, "derived");
        assert_eq!(operations["copy"].reason, REASON_CONFIGURED);
        assert_eq!(operations["move"].state, CapabilityStateName::Denied);
        assert_eq!(operations["move"].source, "configuration");
        assert_eq!(operations.len(), 10);
        let all = allowed("observed", "", true);
        assert_eq!(combine(&[&all, &all]).state, CapabilityStateName::Allowed);
        assert_eq!(combine(&[]).state, CapabilityStateName::Denied);
    }
}
