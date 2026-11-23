//! The shared part of the program: the types that the work packages agree on.
//!
//! The coordinator owns this folder. A work package that needs a change here asks the coordinator.

pub mod app;
pub mod assets;
pub mod config;
pub mod ctx;
pub mod error;
pub mod http;
pub mod json;
pub mod md5;
pub mod mediatype;
pub mod misc;
pub mod query;
pub mod request_json;
pub mod storage;
pub mod time;

use std::future::Future;
use std::pin::Pin;

/// A boxed future that can move to another thread: the return type of the asynchronous trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub use error::{Error, Result};
