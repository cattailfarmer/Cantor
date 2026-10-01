use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use rmcp::{
    ServiceExt,
    service::{RoleServer, RxJsonRpcMessage, TxJsonRpcMessage},
    transport::{Transport, async_rw::JsonRpcMessageCodec},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf, Take},
    sync::Mutex,
};
use tokio_util::{
    codec::{FramedRead, FramedWrite},
    sync::CancellationToken,
};

use crate::{
    InspectionMcpServer, MAX_INPUT_BYTES, MAX_INPUT_FRAME_BYTES, MAX_MESSAGES,
    MAX_OUTPUT_FRAME_BYTES, MAX_RESERVED_OUTPUT_BYTES, SESSION_SECONDS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionFault {
    Handshake,
    Transport,
    Worker,
    Deadline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionReport {
    pub input_bytes: usize,
    pub reserved_output_bytes: usize,
    pub decoded_messages: usize,
}

#[derive(Clone, Copy)]
struct Limits {
    input_frame: usize,
    output_frame: usize,
    input: usize,
    output: usize,
    messages: usize,
    deadline: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            input_frame: MAX_INPUT_FRAME_BYTES,
            output_frame: MAX_OUTPUT_FRAME_BYTES,
            input: MAX_INPUT_BYTES,
            output: MAX_RESERVED_OUTPUT_BYTES,
            messages: MAX_MESSAGES,
            deadline: Duration::from_secs(SESSION_SECONDS),
        }
    }
}

#[derive(Default)]
struct State {
    fault: AtomicBool,
    input: AtomicUsize,
    output: AtomicUsize,
    messages: AtomicUsize,
    cancel: CancellationToken,
}
impl State {
    fn refuse(&self) -> io::Error {
        self.fault.store(true, Ordering::Release);
        self.cancel.cancel();
        io::Error::other("cantor_mcp_transport_refused")
    }
    fn report(&self) -> SessionReport {
        SessionReport {
            input_bytes: self.input.load(Ordering::Acquire),
            reserved_output_bytes: self.output.load(Ordering::Acquire),
            decoded_messages: self.messages.load(Ordering::Acquire),
        }
    }
}

struct CountedRead<R> {
    inner: Take<R>,
    state: Arc<State>,
    ceiling: usize,
}
impl<R: AsyncRead + Unpin> AsyncRead for CountedRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if let Poll::Ready(Ok(())) = result {
            let added = buffer.filled().len() - before;
            let old = self.state.input.fetch_add(added, Ordering::AcqRel);
            if old.checked_add(added).is_none_or(|n| n > self.ceiling) {
                // AsyncRead errors must not expose newly filled bytes. Retain
                // the physical witness in accounting but roll back its buffer.
                buffer.set_filled(before);
                return Poll::Ready(Err(self.state.refuse()));
            }
        } else if matches!(result, Poll::Ready(Err(_))) {
            buffer.set_filled(before);
            return Poll::Ready(Err(self.state.refuse()));
        }
        result
    }
}

type Writer<W> = Arc<Mutex<FramedWrite<W, JsonRpcMessageCodec<TxJsonRpcMessage<RoleServer>>>>>;
struct BoundedTransport<R, W> {
    reader: FramedRead<CountedRead<R>, JsonRpcMessageCodec<RxJsonRpcMessage<RoleServer>>>,
    writer: Writer<W>,
    state: Arc<State>,
    limits: Limits,
}
impl<R: AsyncRead + Unpin, W: AsyncWrite> BoundedTransport<R, W> {
    fn new(read: R, write: W, state: Arc<State>, limits: Limits) -> Self {
        let read = CountedRead {
            inner: read.take((limits.input + 1) as u64),
            state: state.clone(),
            ceiling: limits.input,
        };
        Self {
            // SDK length excludes the delimiter. Reserve its byte so a line
            // including newline never exceeds the advertised input-frame bound.
            reader: FramedRead::new(
                read,
                JsonRpcMessageCodec::new_with_max_length(limits.input_frame - 1),
            ),
            writer: Arc::new(Mutex::new(FramedWrite::new(
                write,
                JsonRpcMessageCodec::new(),
            ))),
            state,
            limits,
        }
    }
}

fn reserve_output(state: &State, limits: Limits, bytes: usize) -> io::Result<()> {
    if bytes > limits.output_frame {
        return Err(state.refuse());
    }
    state
        .output
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            old.checked_add(bytes).filter(|n| *n <= limits.output)
        })
        .map(|_| ())
        .map_err(|_| state.refuse())
}

impl<R, W> Transport<RoleServer> for BoundedTransport<R, W>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;
    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = io::Result<()>> + Send + 'static {
        let state = self.state.clone();
        let writer = self.writer.clone();
        let limits = self.limits;
        async move {
            let bytes = serde_json::to_vec(&item)
                .map_err(|_| state.refuse())?
                .len()
                .checked_add(1)
                .ok_or_else(|| state.refuse())?;
            reserve_output(&state, limits, bytes)?;
            // Reservation is not delivered-byte evidence. SDK encoding remains
            // authoritative, while all physical writes are serialized.
            writer
                .lock()
                .await
                .send(item)
                .await
                .map_err(|_| state.refuse())
        }
    }
    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        match self.reader.next().await {
            Some(Ok(message)) => {
                let old = self.state.messages.fetch_add(1, Ordering::AcqRel);
                if old >= self.limits.messages {
                    self.state.refuse();
                    None
                } else {
                    Some(message)
                }
            }
            Some(Err(_)) => {
                self.state.refuse();
                None
            }
            None => None,
        }
    }
    async fn close(&mut self) -> io::Result<()> {
        self.writer
            .lock()
            .await
            .close()
            .await
            .map_err(|_| self.state.refuse())
    }
}

/// Serve supplied streams under fixed P0 budgets. This does not open paths,
/// launch processes, or terminate the caller's runtime on a deadline.
pub async fn run_io<R, W>(read: R, write: W) -> Result<SessionReport, SessionFault>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    run_with_limits(read, write, Limits::default()).await
}

async fn run_with_limits<R, W>(
    read: R,
    write: W,
    limits: Limits,
) -> Result<SessionReport, SessionFault>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let state = Arc::new(State::default());
    let transport = BoundedTransport::new(read, write, state.clone(), limits);
    let exchange = async {
        let service = InspectionMcpServer::default()
            .serve_with_ct(transport, state.cancel.clone())
            .await
            .map_err(|_| {
                if state.fault.load(Ordering::Acquire) {
                    SessionFault::Transport
                } else {
                    SessionFault::Handshake
                }
            })?;
        service.waiting().await.map_err(|_| SessionFault::Worker)?;
        if state.fault.load(Ordering::Acquire) {
            Err(SessionFault::Transport)
        } else {
            Ok(state.report())
        }
    };
    match tokio::time::timeout(limits.deadline, exchange).await {
        Ok(result) => result,
        Err(_) => {
            state.cancel.cancel();
            Err(SessionFault::Deadline)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    fn small() -> Limits {
        Limits {
            input_frame: 128,
            output_frame: 64,
            input: 256,
            output: 128,
            messages: 2,
            deadline: Duration::from_millis(25),
        }
    }
    fn notification() -> Vec<u8> {
        b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n".to_vec()
    }
    #[test]
    fn output_reservation_exact_plus_one_and_checked_overflow() {
        let state = State::default();
        reserve_output(&state, small(), 64).unwrap();
        reserve_output(&state, small(), 64).unwrap();
        assert_eq!(state.report().reserved_output_bytes, 128);
        assert!(reserve_output(&state, small(), 1).is_err());
        let state = State::default();
        assert!(reserve_output(&state, small(), 65).is_err());
        assert_eq!(state.report().reserved_output_bytes, 0);
        state.output.store(usize::MAX, Ordering::Release);
        assert!(reserve_output(&state, small(), 1).is_err());
    }
    #[tokio::test]
    async fn encoded_sdk_output_frame_exact_and_plus_one() {
        let item = || {
            serde_json::from_value::<TxJsonRpcMessage<RoleServer>>(
                serde_json::json!({"jsonrpc":"2.0","id":1,"result":{}}),
            )
            .unwrap()
        };
        let bytes = serde_json::to_vec(&item()).unwrap().len() + 1;
        for allowed in [bytes, bytes - 1] {
            let state = Arc::new(State::default());
            let mut limits = small();
            limits.output_frame = allowed;
            let mut transport = BoundedTransport::new(
                std::io::Cursor::new(Vec::<u8>::new()),
                tokio::io::sink(),
                state.clone(),
                limits,
            );
            assert_eq!(transport.send(item()).await.is_ok(), allowed == bytes);
            assert_eq!(
                state.report().reserved_output_bytes,
                if allowed == bytes { bytes } else { 0 }
            );
            assert_eq!(state.cancel.is_cancelled(), allowed != bytes);
        }
    }
    #[tokio::test]
    async fn message_count_refuses_third_and_cancels() {
        let input = notification().repeat(3);
        let state = Arc::new(State::default());
        let mut transport = BoundedTransport::new(
            std::io::Cursor::new(input),
            tokio::io::sink(),
            state.clone(),
            small(),
        );
        assert!(transport.receive().await.is_some());
        assert!(transport.receive().await.is_some());
        assert!(transport.receive().await.is_none());
        assert_eq!(state.report().decoded_messages, 3);
        assert!(state.cancel.is_cancelled());
    }
    #[tokio::test]
    async fn raw_aggregate_allows_exact_and_reads_only_one_overflow_witness() {
        for count in [256, 257, 4096] {
            let state = Arc::new(State::default());
            let mut reader = CountedRead {
                inner: std::io::Cursor::new(vec![b'x'; count]).take(257),
                state: state.clone(),
                ceiling: 256,
            };
            let mut output = Vec::new();
            let result = reader.read_to_end(&mut output).await;
            assert_eq!(state.report().input_bytes, count.min(257));
            assert_eq!(result.is_err(), count > 256);
        }
    }
    #[tokio::test]
    async fn codec_frame_exact_and_plus_one() {
        let base = notification();
        let payload = &base[..base.len() - 1];
        for extra in [0, 1] {
            let mut input = payload.to_vec();
            input.resize(127 + extra, b' ');
            input.push(b'\n');
            let state = Arc::new(State::default());
            let mut transport = BoundedTransport::new(
                std::io::Cursor::new(input),
                tokio::io::sink(),
                state.clone(),
                small(),
            );
            assert_eq!(transport.receive().await.is_some(), extra == 0);
            assert_eq!(state.fault.load(Ordering::Acquire), extra == 1);
        }
    }
    #[tokio::test]
    async fn malformed_codec_is_fatal_without_echo() {
        let state = Arc::new(State::default());
        let mut transport = BoundedTransport::new(
            std::io::Cursor::new(b"secret-invalid\n"),
            tokio::io::sink(),
            state.clone(),
            small(),
        );
        assert!(transport.receive().await.is_none());
        assert!(state.cancel.is_cancelled());
    }
    #[tokio::test]
    async fn pending_handshake_deadline_is_not_caller_runtime_shutdown() {
        let (_held, server) = tokio::io::duplex(64);
        let (read, write) = tokio::io::split(server);
        assert_eq!(
            run_with_limits(read, write, small()).await,
            Err(SessionFault::Deadline)
        );
        let mut other = tokio::io::sink();
        other
            .write_all(b"caller runtime remains usable")
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn sdk_complete_eof_and_bom_compatibility_are_retained() {
        for input in [
            notification()[..notification().len() - 1].to_vec(),
            [b"\xef\xbb\xbf".as_slice(), &notification()].concat(),
        ] {
            let state = Arc::new(State::default());
            let mut transport = BoundedTransport::new(
                std::io::Cursor::new(input),
                tokio::io::sink(),
                state,
                small(),
            );
            assert!(transport.receive().await.is_some());
        }
    }
}
