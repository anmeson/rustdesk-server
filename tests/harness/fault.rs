//! A fault injector between `hbbs` and `apps/api` — TASK.md T5.6.
//!
//! T5.6 asks what `hbbs` does when the api is down, slow, or answering nonsense.
//! Two of those three cannot be produced by touching the api itself: `apps/api`
//! has no "be slow" switch and no "return HTML" switch, and adding either would
//! mean shipping a fault mode in the product to make a test possible.
//!
//! So the fault goes in the wire instead. This is a plain TCP proxy that `hbbs`
//! is pointed at with `--auth-api-url`, forwarding to the real api by default
//! and misbehaving on demand. Three properties are worth knowing before using
//! it:
//!
//!   - **Only hbbs is behind it.** `Console` and `ClientApi` keep talking to the
//!     api directly, so fixtures can still be built, grants still written and
//!     sessions still read *while hbbs cannot get an answer at all*. That is the
//!     honest shape of the outage — the api is fine, hbbs's path to it is not —
//!     and it is the only way to check afterwards what the api actually saw.
//!   - **The mode is switched live**, not at boot. hbbs reads the auth URL once
//!     and never again, so a fault that needed a restart would be testing a
//!     different thing: a server that came up broken, rather than one that was
//!     working and then was not.
//!   - **[`Fault::Slow`] still asks the api.** The upstream request is made, the
//!     answer comes back, and only then is it held. So a `Slow` denial is the
//!     sharp case: the api said *allow* and hbbs denied anyway, because the
//!     answer missed `AUTH_TIMEOUT_MS`. A proxy that simply slept before
//!     connecting would prove nothing about who made the decision.
//!
//! Upstream requests carry an injected `connection: close`, so the response can
//! be read to EOF rather than trusting a `content-length` that a fault mode may
//! be about to invalidate. Fastify honours it, and hbbs's own reqwest client
//! sees one connection per request, which is what it already gets from
//! `harness::stub`.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use hbb_common::tokio::{
    self,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::sleep,
};

/// What the proxy does with the next request.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Fault {
    /// Forward to the api and hand back what it said. The healthy state.
    None,
    /// Forward, wait for the api's answer, then hold it this long before
    /// replying. The api *did* decide; hbbs just never heard it in time.
    Slow(u64),
    /// Accept the request, read it, and never answer. The socket stays open, so
    /// hbbs is waiting on a live connection rather than a closed one — the case
    /// where only its own timeout ends the wait.
    Blackhole,
    /// Accept and close immediately, without a byte of response.
    Hangup,
    /// Answer this status and body without ever reaching the api.
    Reply(u16, String),
}

pub struct FaultProxy {
    pub addr: SocketAddr,
    mode: Arc<Mutex<Fault>>,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl FaultProxy {
    /// Binds in front of `target` (a port on loopback) and starts forwarding.
    pub async fn in_front_of(target: u16) -> FaultProxy {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mode = Arc::new(Mutex::new(Fault::None));
        let calls = Arc::new(AtomicUsize::new(0));
        let (m, c) = (mode.clone(), calls.clone());

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut down, _)) = listener.accept().await else {
                    return;
                };
                let (m, c) = (m.clone(), c.clone());
                // One task per connection, so a `Blackhole` that is still being
                // held does not stop the next request arriving. The proxy must
                // not be the thing that serialises hbbs.
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut down).await else {
                        return;
                    };
                    c.fetch_add(1, Ordering::SeqCst);
                    let fault = m.lock().unwrap().clone();
                    match fault {
                        Fault::Hangup => {}
                        Fault::Blackhole => {
                            // Held, not dropped: closing here would give hbbs a
                            // connection error in microseconds, which is the
                            // `Hangup` case and not this one.
                            sleep(Duration::from_secs(120)).await;
                        }
                        Fault::Reply(status, body) => {
                            let _ = down.write_all(&canned(status, &body)).await;
                            let _ = down.flush().await;
                        }
                        Fault::None | Fault::Slow(_) => {
                            let answer = forward(target, &request).await;
                            if let Fault::Slow(ms) = fault {
                                sleep(Duration::from_millis(ms)).await;
                            }
                            if let Some(answer) = answer {
                                let _ = down.write_all(&answer).await;
                                let _ = down.flush().await;
                            }
                        }
                    }
                });
            }
        });

        FaultProxy { addr, mode, calls, task }
    }

    /// What `hbbs` is given as `--auth-api-url`.
    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn set(&self, fault: Fault) {
        *self.mode.lock().unwrap() = fault;
    }

    /// Back to forwarding. Named for what it means at a call site — the api
    /// path is working again — rather than for the variant.
    pub fn heal(&self) {
        self.set(Fault::None);
    }

    /// How many requests hbbs has sent through here. The number T5.6 asserts on
    /// when the question is whether a refusal cost a round trip or not.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn reset_calls(&self) {
        self.calls.store(0, Ordering::SeqCst);
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        // The accept loop owns the listener; aborting it is what frees the port
        // for the next world in the same process.
        self.task.abort();
    }
}

/// Reads one whole HTTP request — head, then `content-length` bytes of body.
///
/// The same framing `harness::stub` uses, and for the same reason: `read` on a
/// socket returns what has arrived, not what was sent, and a body split across
/// two segments would otherwise be forwarded truncated and read as the api
/// misbehaving rather than as the proxy doing so.
async fn read_request(sock: &mut TcpStream) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let read = sock.read(&mut buf).await.ok()?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..read]);
        let text = String::from_utf8_lossy(&raw).to_lowercase();
        if let (Some(head), Some(len)) = (
            raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4),
            text.find("content-length:").and_then(|i| {
                text[i + 15..].split("\r\n").next()?.trim().parse::<usize>().ok()
            }),
        ) {
            if raw.len() >= head + len {
                break;
            }
        }
    }
    (!raw.is_empty()).then_some(raw)
}

/// Sends the request on to the real api and returns its whole answer.
async fn forward(target: u16, request: &[u8]) -> Option<Vec<u8>> {
    let mut up = TcpStream::connect(("127.0.0.1", target)).await.ok()?;
    up.write_all(&with_connection_close(request)).await.ok()?;
    up.flush().await.ok()?;
    let mut answer = Vec::new();
    up.read_to_end(&mut answer).await.ok()?;
    Some(answer)
}

/// Inserts `connection: close` after the request line, so the api closes the
/// socket when it is done and the answer can be read to EOF.
fn with_connection_close(request: &[u8]) -> Vec<u8> {
    let Some(end_of_line) = request.windows(2).position(|w| w == b"\r\n").map(|p| p + 2) else {
        return request.to_vec();
    };
    let mut out = Vec::with_capacity(request.len() + 19);
    out.extend_from_slice(&request[..end_of_line]);
    out.extend_from_slice(b"connection: close\r\n");
    out.extend_from_slice(&request[end_of_line..]);
    out
}

/// A complete response invented here, never touching the api.
fn canned(status: u16, body: &str) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}
