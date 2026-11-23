//! The streamed bodies of the archive routes.
//!
//! [`stream`] gives a body that a task fills through a [`StreamSender`]. Each send waits at most the idle time for
//! the client: a client that stops to read stops the task, and the task gives back its storage slot. A sender that
//! the task drops before [`StreamSender::finish`] stops the body with an error, so a cut archive never looks complete.
//!
//! [`EntryBody`] gives the bytes of an archive entry as the body of a write: it reads the next bytes only when the
//! writer asks for them, checks the context before each read, and counts the bytes.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use http_body::Frame;
use http_body_util::BodyExt;
use tokio::sync::mpsc;

use super::zip::{ByteSource, EntryStream, ZipReader};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::Body;

/// The longest wait for a client that does not take the next bytes.
pub const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The frames that wait in memory for the client.
const STREAM_DEPTH: usize = 4;

/// The sending side of a streamed body.
#[derive(Debug)]
pub struct StreamSender {
    sender: mpsc::Sender<Frame<Bytes>>,
    aborted: Arc<AtomicBool>,
    idle: Duration,
    finished: bool,
}

impl StreamSender {
    async fn deliver(&self, frame: Frame<Bytes>) -> Result<()> {
        match tokio::time::timeout(self.idle, self.sender.send(frame)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Error::Canceled),
            Err(_) => {
                self.abort();
                Err(Error::Timeout)
            }
        }
    }

    /// Send bytes. `Err(Error::Canceled)` when the client is gone, `Err(Error::Timeout)` when the client did not
    /// take the bytes in the idle time.
    pub async fn send(&self, data: Bytes) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.deliver(Frame::data(data)).await
    }

    /// Send the trailers: the last frame.
    pub async fn send_trailers(&self, trailers: HeaderMap) -> Result<()> {
        self.deliver(Frame::trailers(trailers)).await
    }

    /// Stop the body with an error: the client never gets a normal end.
    pub fn abort(&self) {
        self.aborted.store(true, Ordering::SeqCst);
    }

    /// End the body normally after the frames that wait.
    pub fn finish(mut self) {
        self.finished = true;
    }
}

impl Drop for StreamSender {
    fn drop(&mut self) {
        if !self.finished {
            self.abort();
        }
    }
}

struct StreamBody {
    receiver: mpsc::Receiver<Frame<Bytes>>,
    aborted: Arc<AtomicBool>,
}

impl http_body::Body for StreamBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if self.aborted.load(Ordering::SeqCst) {
            return Poll::Ready(Some(Err(Error::Timeout)));
        }
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(frame)) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(None) if self.aborted.load(Ordering::SeqCst) => Poll::Ready(Some(Err(Error::Timeout))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A streamed body and its sender, with this idle time.
pub fn stream(idle: Duration) -> (StreamSender, Body) {
    let (sender, receiver) = mpsc::channel(STREAM_DEPTH);
    let aborted = Arc::new(AtomicBool::new(false));
    let body = StreamBody {
        receiver,
        aborted: aborted.clone(),
    };
    (
        StreamSender {
            sender,
            aborted,
            idle,
            finished: false,
        },
        body.boxed_unsync(),
    )
}

type NextChunk<S> = Pin<Box<dyn Future<Output = (EntryStream<Arc<ZipReader<S>>>, Result<Option<Bytes>>)> + Send>>;

/// The bytes of an archive entry as a body. The body reads the next bytes when the consumer polls it.
pub struct EntryBody<S: ByteSource + 'static> {
    stream: Option<EntryStream<Arc<ZipReader<S>>>>,
    next: Option<NextChunk<S>>,
    ctx: OpCtx,
    counter: Arc<AtomicU64>,
}

impl<S: ByteSource + 'static> EntryBody<S> {
    /// A body over an entry stream. Each read checks the context first; `counter` counts the bytes of the body.
    pub fn new(stream: EntryStream<Arc<ZipReader<S>>>, ctx: OpCtx, counter: Arc<AtomicU64>) -> Self {
        Self {
            stream: Some(stream),
            next: None,
            ctx,
            counter,
        }
    }
}

impl<S: ByteSource + 'static> http_body::Body for EntryBody<S> {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        let this = &mut *self;
        if this.next.is_none() {
            let Some(mut stream) = this.stream.take() else {
                return Poll::Ready(None);
            };
            let ctx = this.ctx.clone();
            this.next = Some(Box::pin(async move {
                let chunk = match ctx.check() {
                    Ok(()) => stream.next_chunk().await,
                    Err(error) => Err(error),
                };
                (stream, chunk)
            }));
        }
        let Some(next) = this.next.as_mut() else {
            return Poll::Ready(None);
        };
        let (stream, chunk) = match next.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(output) => output,
        };
        this.next = None;
        match chunk {
            Ok(Some(chunk)) => {
                this.counter.fetch_add(chunk.len() as u64, Ordering::SeqCst);
                this.stream = Some(stream);
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            Ok(None) => Poll::Ready(None),
            Err(error) => Poll::Ready(Some(Err(error))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::http::read_limited;

    #[tokio::test]
    async fn a_finished_stream_ends_normally_with_its_trailers() {
        let (sender, mut body) = stream(STREAM_IDLE_TIMEOUT);
        tokio::spawn(async move {
            sender.send(Bytes::from_static(b"abc")).await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("x-test", "1".parse().unwrap());
            sender.send_trailers(trailers).await.unwrap();
            sender.finish();
        });
        let first = body.frame().await.unwrap().unwrap();
        assert_eq!(first.into_data().unwrap(), &b"abc"[..]);
        let trailers = body.frame().await.unwrap().unwrap().into_trailers().unwrap();
        assert_eq!(trailers.get("x-test").unwrap(), "1");
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn a_sender_that_goes_away_stops_the_body_with_an_error() {
        let (sender, body) = stream(STREAM_IDLE_TIMEOUT);
        tokio::spawn(async move {
            sender.send(Bytes::from_static(b"partial")).await.unwrap();
        });
        assert!(read_limited(body, 1 << 20).await.is_err());
    }

    #[tokio::test]
    async fn a_client_that_stops_to_read_stops_the_sender() {
        let (sender, body) = stream(Duration::from_millis(50));
        let mut result = Ok(());
        for _ in 0..(STREAM_DEPTH + 2) {
            result = sender.send(Bytes::from_static(b"block")).await;
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(Error::Timeout));
        drop(sender);
        assert!(read_limited(body, 1 << 20).await.is_err());
    }
}
