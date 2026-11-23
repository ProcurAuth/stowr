//! Small helpers that each part of the program uses: random identifiers, the log line, the cancellation token.

use std::fmt;
use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use tokio::sync::Notify;

use super::error::{Error, Result};
use super::time::Timestamp;

/// Fill a buffer with random bytes of the operating system.
pub fn random_bytes(buffer: &mut [u8]) -> Result<()> {
    SystemRandom::new()
        .fill(buffer)
        .map_err(|_| Error::internal("the random generator failed"))
}

/// The lower-case hexadecimal text of bytes.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    out
}

/// A random identifier of 16 bytes, in hexadecimal.
pub fn random_hex16() -> Result<String> {
    let mut random = [0u8; 16];
    random_bytes(&mut random)?;
    Ok(hex(&random))
}

/// The identifier of a state in memory: `<prefix>_` and 32 hexadecimal characters, for example `job_...`.
pub fn new_state_id(prefix: &str) -> Result<String> {
    Ok(format!("{prefix}_{}", random_hex16()?))
}

/// Write one line in the log (the standard error): the date and time in UTC, a space and the text.
#[allow(clippy::print_stderr)]
pub fn log_line(args: fmt::Arguments<'_>) {
    let mut line = Timestamp::now().log_form();
    line.push(' ');
    line.push_str(&args.to_string());
    if !line.ends_with('\n') {
        line.push('\n');
    }
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

/// Write one line in the log: `log!("config.warning {}", text)`.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::common::misc::log_line(format_args!($($arg)*))
    };
}

/// A token that tells the tasks of an operation to stop. A clone shares the state.
#[derive(Clone, Debug, Default)]
pub struct CancelToken {
    inner: Arc<CancelInner>,
}

#[derive(Debug, Default)]
struct CancelInner {
    canceled: AtomicBool,
    notify: Notify,
}

impl CancelToken {
    /// A new token that is not canceled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel the token and wake each waiter.
    pub fn cancel(&self) {
        self.inner.canceled.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    /// True after `cancel`.
    pub fn is_canceled(&self) -> bool {
        self.inner.canceled.load(Ordering::SeqCst)
    }

    /// Wait until the token is canceled.
    pub async fn canceled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_canceled() {
                return;
            }
            notified.await;
        }
    }

    /// `Err(Error::Canceled)` after `cancel`.
    pub fn check(&self) -> Result<()> {
        if self.is_canceled() {
            Err(Error::Canceled)
        } else {
            Ok(())
        }
    }
}

/// The relative key of a request: the NUL bytes and the `/` at the start removed. A key is opaque: the other parts
/// stay (repeated `/`, `.`, `..`, `\`).
pub fn clean_relative_key(value: &str) -> String {
    value.replace('\0', "").trim_start_matches('/').to_owned()
}

/// A relative prefix: the `/` at the start removed, and one `/` at the end. An empty prefix stays empty.
pub fn normalize_prefix(value: &str) -> String {
    let value = value.trim_start_matches('/');
    if value.is_empty() {
        return String::new();
    }
    format!("{}/", value.trim_end_matches('/'))
}

/// An integer of a query: the fallback for a text that is not an integer or is below the minimum, the maximum for
/// a larger value.
pub fn parse_bounded_int(raw: &str, fallback: i64, minimum: i64, maximum: i64) -> i64 {
    match raw.parse::<i64>() {
        Ok(value) if value >= minimum => value.min(maximum),
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_ids_have_the_prefix_and_32_digits() {
        let id = new_state_id("job").unwrap();
        assert!(id.starts_with("job_"));
        assert_eq!(id.len(), 36);
    }

    #[tokio::test]
    async fn a_canceled_token_wakes_its_waiter() {
        let token = CancelToken::new();
        let waiter = token.clone();
        let task = tokio::spawn(async move { waiter.canceled().await });
        token.cancel();
        task.await.unwrap();
        assert!(token.check().is_err());
    }
}
