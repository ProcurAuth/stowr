// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stowr: a self-contained browser for S3-compatible storage, Google Cloud Storage and folders of the server.
//!
//! The crate has one module for each part of the program, and the shared module `common`. docs/DEVELOPMENT.md gives
//! the layout, the rules of the code and the build.

pub mod common;

pub mod access;
pub mod archive;
pub mod bucket;
pub mod config;
pub mod instance;
pub mod jobs;
pub mod lifecycle;
pub mod provider;
pub mod pv_data;
pub mod pv_docs;
pub mod pv_media;
pub mod pv_structured;
pub mod server;
pub mod uploads;
pub mod volume;

#[cfg(test)]
pub mod testkit;
