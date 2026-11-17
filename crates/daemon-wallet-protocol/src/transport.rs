//! A blocking unix-domain-socket transport for the wire contract.
//!
//! This is the first real [`Transport`] (M3): it carries a CLI<->daemon control
//! channel over a connected [`UnixStream`]. Framing is deliberately boring so
//! both ends agree without a handshake: each message is a 4-byte little-endian
//! `u32` length prefix followed by that many bytes of the envelope's
//! `serde_json` encoding. A [`MAX_FRAME_LEN`] guard bounds the allocation a
//! peer can force on the reader.
//!
//! The client side is [`UnixTransport`]. The daemon side gets framing-free
//! helpers ([`read_request`], [`write_response`], [`serve_connection`]) so a
//! daemon can serve this protocol without re-deriving the framing. Everything
//! here is std and blocking; no async runtime is involved.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::client::Transport;
use crate::{Error, PROTOCOL_VERSION, Request, RequestEnvelope, Response, ResponseEnvelope};

/// Result alias for transport calls.
type Result<T> = core::result::Result<T, Error>;

/// Largest frame body this side will send or accept, in bytes.
///
/// A length prefix is attacker-controlled, so the reader refuses anything
/// bigger rather than trusting it and allocating. 16 MiB is far above any
/// legitimate envelope yet small enough to stay harmless.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// A blocking [`Transport`] over a connected unix stream.
///
/// One [`Transport::call`] writes the request frame and blocks reading the one
/// response frame. The stream is shared (`&UnixStream` is both [`Read`] and
/// [`Write`]), so `call` needs only `&self`, matching the trait.
pub struct UnixTransport {
    /// The connected socket both directions travel over.
    stream: UnixStream,
}

impl UnixTransport {
    /// Connect to a daemon listening on the unix socket at `path`.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        let stream = UnixStream::connect(path).map_err(|_| Error::Internal)?;
        Ok(Self { stream })
    }

    /// Wrap an already-connected stream (for example one half of a
    /// [`UnixStream::pair`], or a stream accepted by a listener).
    pub fn from_stream(stream: UnixStream) -> Self {
        Self { stream }
    }
}

impl Transport for UnixTransport {
    fn call(&self, request: RequestEnvelope) -> Result<ResponseEnvelope> {
        let bytes = serde_json::to_vec(&request).map_err(|_| Error::Internal)?;
        let mut sock = &self.stream;
        write_frame(&mut sock, &bytes)?;
        match read_frame(&mut sock)? {
            Some(frame) => serde_json::from_slice(&frame).map_err(|_| Error::Internal),
            // A clean EOF where a response was expected is a broken exchange.
            None => Err(Error::Internal),
        }
    }
}

/// Read one framed [`RequestEnvelope`] from `reader`.
///
/// Returns `Ok(None)` on a clean EOF at a frame boundary (the peer hung up),
/// and an [`Error::Internal`] on a truncated frame or a decode failure.
pub fn read_request(reader: &mut impl Read) -> Result<Option<RequestEnvelope>> {
    match read_frame(reader)? {
        Some(frame) => {
            let envelope = serde_json::from_slice(&frame).map_err(|_| Error::Internal)?;
            Ok(Some(envelope))
        }
        None => Ok(None),
    }
}

/// Write one framed [`ResponseEnvelope`] to `writer` and flush it.
pub fn write_response(writer: &mut impl Write, response: &ResponseEnvelope) -> Result<()> {
    let bytes = serde_json::to_vec(response).map_err(|_| Error::Internal)?;
    write_frame(writer, &bytes)
}

/// Serve the protocol on one connection until the peer hangs up.
///
/// Reads requests, hands each [`Request`] to `handler`, and writes the
/// [`Response`] back in an envelope that echoes the request's [`crate::RequestId`]
/// and is stamped with [`PROTOCOL_VERSION`]. An incoming envelope built against
/// a version this side does not speak is answered with
/// [`Error::UnsupportedVersion`] (the handler is not consulted) rather than
/// dropping the connection, so the peer learns why. Returns `Ok(())` on a clean
/// EOF.
pub fn serve_connection<F>(stream: UnixStream, mut handler: F) -> Result<()>
where
    F: FnMut(Request) -> Response,
{
    let mut reader = &stream;
    let mut writer = &stream;
    loop {
        let envelope = match read_request(&mut reader)? {
            Some(envelope) => envelope,
            None => return Ok(()),
        };
        let result = if envelope.protocol_version == PROTOCOL_VERSION {
            Ok(handler(envelope.request))
        } else {
            Err(Error::UnsupportedVersion {
                got: envelope.protocol_version,
                expected: PROTOCOL_VERSION,
            })
        };
        let response = ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            id: envelope.id,
            result,
        };
        write_response(&mut writer, &response)?;
    }
}

/// Write a length-prefixed frame: a 4-byte LE `u32` length, then `bytes`.
fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FRAME_LEN {
        return Err(Error::Internal);
    }
    let len = u32::try_from(bytes.len()).map_err(|_| Error::Internal)?;
    writer
        .write_all(&len.to_le_bytes())
        .map_err(|_| Error::Internal)?;
    writer.write_all(bytes).map_err(|_| Error::Internal)?;
    writer.flush().map_err(|_| Error::Internal)?;
    Ok(())
}

/// Read one length-prefixed frame body.
///
/// `Ok(None)` means a clean EOF arrived before any byte of the length prefix.
/// A frame whose declared length exceeds [`MAX_FRAME_LEN`], or an EOF partway
/// through a frame, is an [`Error::Internal`].
fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let mut filled = 0;
    while filled < len_buf.len() {
        match reader.read(&mut len_buf[filled..]) {
            Ok(0) => {
                // No bytes yet means a clean hang-up; a partial prefix is a
                // truncated frame.
                return if filled == 0 {
                    Ok(None)
                } else {
                    Err(Error::Internal)
                };
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Internal),
        }
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(Error::Internal);
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).map_err(|_| Error::Internal)?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestId;
    use crate::client::Client;
    use crate::dto::{Origin, StatusDto};
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// A canned status the test daemon hands back for `Request::Status`.
    fn canned_status() -> StatusDto {
        StatusDto {
            locked: false,
            protocol_version: PROTOCOL_VERSION,
            account_count: 3,
            connected_origins: vec![Origin("https://app.uniswap.org".into())],
        }
    }

    #[test]
    fn status_round_trip_over_socket() {
        let (client_end, server_end) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            serve_connection(server_end, |req| match req {
                Request::Status => Response::Status(canned_status()),
                Request::Unlock { .. } => Response::Unlocked,
                _ => Response::Locked,
            })
            .unwrap();
        });

        let mut client = Client::new(UnixTransport::from_stream(client_end));
        assert_eq!(client.status().unwrap(), canned_status());

        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn framed_requests_work_back_to_back() {
        let (client_end, server_end) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            serve_connection(server_end, |req| match req {
                Request::Status => Response::Status(canned_status()),
                Request::Unlock { .. } => Response::Unlocked,
                _ => Response::Locked,
            })
            .unwrap();
        });

        let mut client = Client::new(UnixTransport::from_stream(client_end));
        // Two full exchanges over the same connection, back to back.
        assert_eq!(client.status().unwrap(), canned_status());
        client.unlock(None).unwrap();
        assert_eq!(client.status().unwrap(), canned_status());

        drop(client);
        server.join().unwrap();
    }

    #[test]
    fn monotonic_request_ids_survive_the_wire() {
        let (client_end, server_end) = UnixStream::pair().unwrap();
        let seen: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_server = Arc::clone(&seen);

        // A hand-rolled daemon loop so it can observe the envelope ids the
        // client allocates (serve_connection hides them behind the handler).
        let server = thread::spawn(move || {
            let mut reader = &server_end;
            let mut writer = &server_end;
            while let Some(envelope) = read_request(&mut reader).unwrap() {
                seen_server.lock().unwrap().push(envelope.id.0);
                let response = ResponseEnvelope {
                    protocol_version: PROTOCOL_VERSION,
                    id: envelope.id,
                    result: Ok(Response::Locked),
                };
                write_response(&mut writer, &response).unwrap();
            }
        });

        let mut client = Client::new(UnixTransport::from_stream(client_end));
        client.lock().unwrap();
        client.lock().unwrap();
        client.lock().unwrap();

        drop(client);
        server.join().unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![0, 1, 2]);
    }

    #[test]
    fn version_mismatch_yields_unsupported_version_response() {
        let (client_end, server_end) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            // The handler must never run for a mismatched request.
            serve_connection(server_end, |_req| panic!("handler must not be called")).unwrap();
        });

        // A request from a future protocol version.
        let bad = RequestEnvelope {
            protocol_version: PROTOCOL_VERSION + 1,
            id: RequestId(42),
            request: Request::Status,
        };
        let bytes = serde_json::to_vec(&bad).unwrap();
        let mut sock = &client_end;
        write_frame(&mut sock, &bytes).unwrap();

        let frame = read_frame(&mut sock).unwrap().unwrap();
        let response: ResponseEnvelope = serde_json::from_slice(&frame).unwrap();
        assert_eq!(response.id, RequestId(42));
        match response.result {
            Err(Error::UnsupportedVersion { got, expected }) => {
                assert_eq!(got, PROTOCOL_VERSION + 1);
                assert_eq!(expected, PROTOCOL_VERSION);
            }
            other => panic!("expected unsupported version, got {other:?}"),
        }

        drop(client_end);
        server.join().unwrap();
    }
}
