//! A thin, typed client over the wire contract.
//!
//! The client turns ergonomic method calls into [`crate::RequestEnvelope`]s,
//! hands them to a [`Transport`], and unwraps the [`crate::ResponseEnvelope`]
//! back into typed results. It owns no transport of its own: the actual moving
//! of bytes (a unix socket, a browser message port, stdio) is M3, so here the
//! transport is only a trait and every call body is left unimplemented.
//!
//! Keeping the client generic over [`Transport`] means the same typed surface
//! serves every future transport without change, and tests can drive it with an
//! in-memory fake.

use crate::dto::{AccountDto, GroupDto, StatusDto};
use crate::{
    Error, PROTOCOL_VERSION, Request, RequestEnvelope, RequestId, Response, ResponseEnvelope,
};

/// Result alias for client calls.
type Result<T> = core::result::Result<T, Error>;

/// A synchronous round-trip transport for envelopes.
///
/// One call sends a [`RequestEnvelope`] and returns the matching
/// [`ResponseEnvelope`]. Transport-level failures (a dropped socket, a decode
/// error) are surfaced as [`Error::Internal`] for now; a richer transport error
/// channel is an M3 concern.
pub trait Transport {
    /// Send one request and block until its response arrives.
    fn call(&self, request: RequestEnvelope) -> Result<ResponseEnvelope>;
}

/// A typed client bound to one [`Transport`].
pub struct Client<T: Transport> {
    /// The underlying transport.
    #[allow(dead_code)]
    transport: T,
    /// Monotonic source of the next [`RequestId`].
    #[allow(dead_code)]
    next_id: u64,
}

impl<T: Transport> Client<T> {
    /// Wrap a transport in a typed client.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_id: 0,
        }
    }

    /// Allocate the next correlation id.
    fn next_request_id(&mut self) -> RequestId {
        let id = RequestId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Frame a request, send it, and return the daemon's [`Response`].
    ///
    /// Wraps `request` in a [`RequestEnvelope`] stamped with
    /// [`PROTOCOL_VERSION`], hands it to the transport, and unwraps the reply. A
    /// response built against a protocol version this side cannot speak is
    /// mapped to [`Error::UnsupportedVersion`]; a daemon-reported failure is
    /// propagated as-is.
    fn round_trip(&mut self, request: Request) -> Result<Response> {
        let id = self.next_request_id();
        let envelope = RequestEnvelope {
            protocol_version: PROTOCOL_VERSION,
            id,
            request,
        };
        let response = self.transport.call(envelope)?;
        if response.protocol_version != PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion {
                got: response.protocol_version,
                expected: PROTOCOL_VERSION,
            });
        }
        response.result
    }

    /// Unlock the wallet.
    pub fn unlock(&mut self, password: Option<String>) -> Result<()> {
        match self.round_trip(Request::Unlock { password })? {
            Response::Unlocked => Ok(()),
            _ => Err(Error::Internal),
        }
    }

    /// Lock the wallet.
    pub fn lock(&mut self) -> Result<()> {
        match self.round_trip(Request::Lock)? {
            Response::Locked => Ok(()),
            _ => Err(Error::Internal),
        }
    }

    /// Fetch daemon status.
    pub fn status(&mut self) -> Result<StatusDto> {
        match self.round_trip(Request::Status)? {
            Response::Status(status) => Ok(status),
            _ => Err(Error::Internal),
        }
    }

    /// List the group tree.
    pub fn list_tree(&mut self) -> Result<Vec<GroupDto>> {
        match self.round_trip(Request::ListTree)? {
            Response::Tree(tree) => Ok(tree),
            _ => Err(Error::Internal),
        }
    }

    /// List accounts.
    pub fn list_accounts(&mut self) -> Result<Vec<AccountDto>> {
        match self.round_trip(Request::ListAccounts)? {
            Response::Accounts(accounts) => Ok(accounts),
            _ => Err(Error::Internal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::Origin;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// In-memory transport: records every outbound envelope and replies by
    /// running a responder closure against it.
    #[derive(Clone)]
    struct FakeTransport {
        seen: Rc<RefCell<Vec<RequestEnvelope>>>,
        responder: Rc<dyn Fn(&RequestEnvelope) -> ResponseEnvelope>,
    }

    impl FakeTransport {
        /// A transport whose reply is always `result`, echoing the request id
        /// and this build's protocol version.
        fn ok(response: Response) -> Self {
            Self::with(move |req| ResponseEnvelope {
                protocol_version: PROTOCOL_VERSION,
                id: req.id,
                result: Ok(response.clone()),
            })
        }

        fn with(f: impl Fn(&RequestEnvelope) -> ResponseEnvelope + 'static) -> Self {
            Self {
                seen: Rc::new(RefCell::new(Vec::new())),
                responder: Rc::new(f),
            }
        }

        /// The single request the client sent, panicking if not exactly one.
        fn only_request(&self) -> Request {
            let seen = self.seen.borrow();
            assert_eq!(seen.len(), 1, "expected exactly one request");
            seen[0].request.clone()
        }
    }

    impl Transport for FakeTransport {
        fn call(&self, request: RequestEnvelope) -> Result<ResponseEnvelope> {
            let response = (self.responder)(&request);
            self.seen.borrow_mut().push(request);
            Ok(response)
        }
    }

    #[test]
    fn new_client_starts_ids_at_zero_and_increments() {
        let fake = FakeTransport::ok(Response::Locked);
        let mut client = Client::new(fake.clone());
        client.lock().unwrap();
        client.lock().unwrap();
        let seen = fake.seen.borrow();
        assert_eq!(seen[0].id, RequestId(0));
        assert_eq!(seen[1].id, RequestId(1));
        // Each envelope is stamped with this build's protocol version.
        assert_eq!(seen[0].protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn unlock_round_trips() {
        let fake = FakeTransport::ok(Response::Unlocked);
        let mut client = Client::new(fake.clone());
        client.unlock(Some("pw".into())).unwrap();
        match fake.only_request() {
            Request::Unlock { password } => assert_eq!(password.as_deref(), Some("pw")),
            other => panic!("wrong request: {other:?}"),
        }
    }

    #[test]
    fn lock_round_trips() {
        let fake = FakeTransport::ok(Response::Locked);
        let mut client = Client::new(fake.clone());
        client.lock().unwrap();
        assert!(matches!(fake.only_request(), Request::Lock));
    }

    #[test]
    fn status_decodes_typed_result() {
        let status = StatusDto {
            locked: false,
            protocol_version: PROTOCOL_VERSION,
            account_count: 3,
            connected_origins: vec![Origin("https://app.uniswap.org".into())],
        };
        let fake = FakeTransport::ok(Response::Status(status.clone()));
        let mut client = Client::new(fake.clone());
        assert_eq!(client.status().unwrap(), status);
        assert!(matches!(fake.only_request(), Request::Status));
    }

    #[test]
    fn list_tree_and_list_accounts_round_trip() {
        let fake = FakeTransport::ok(Response::Tree(vec![]));
        let mut client = Client::new(fake.clone());
        assert_eq!(client.list_tree().unwrap(), vec![]);
        assert!(matches!(fake.only_request(), Request::ListTree));

        let fake = FakeTransport::ok(Response::Accounts(vec![]));
        let mut client = Client::new(fake.clone());
        assert_eq!(client.list_accounts().unwrap(), vec![]);
        assert!(matches!(fake.only_request(), Request::ListAccounts));
    }

    #[test]
    fn daemon_error_result_propagates() {
        let fake = FakeTransport::with(|req| ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            id: req.id,
            result: Err(Error::Locked),
        });
        let mut client = Client::new(fake);
        assert_eq!(client.status().unwrap_err(), Error::Locked);
    }

    #[test]
    fn version_mismatch_in_envelope_surfaces_as_unsupported_version() {
        let fake = FakeTransport::with(|req| ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION + 1,
            id: req.id,
            result: Ok(Response::Unlocked),
        });
        let mut client = Client::new(fake);
        assert_eq!(
            client.unlock(None).unwrap_err(),
            Error::UnsupportedVersion {
                got: PROTOCOL_VERSION + 1,
                expected: PROTOCOL_VERSION,
            }
        );
    }

    #[test]
    fn peer_reported_unsupported_version_propagates() {
        let fake = FakeTransport::with(|req| ResponseEnvelope {
            protocol_version: PROTOCOL_VERSION,
            id: req.id,
            result: Err(Error::UnsupportedVersion {
                got: 99,
                expected: PROTOCOL_VERSION,
            }),
        });
        let mut client = Client::new(fake);
        assert_eq!(
            client.status().unwrap_err(),
            Error::UnsupportedVersion {
                got: 99,
                expected: PROTOCOL_VERSION,
            }
        );
    }

    #[test]
    fn unexpected_response_variant_is_clean_error_not_panic() {
        // A `status()` call that somehow gets a `Locked` reply must not panic.
        let fake = FakeTransport::ok(Response::Locked);
        let mut client = Client::new(fake);
        assert_eq!(client.status().unwrap_err(), Error::Internal);
    }

    #[test]
    fn transport_failure_surfaces() {
        struct Broken;
        impl Transport for Broken {
            fn call(&self, _request: RequestEnvelope) -> Result<ResponseEnvelope> {
                Err(Error::Internal)
            }
        }
        let mut client = Client::new(Broken);
        assert_eq!(client.lock().unwrap_err(), Error::Internal);
    }
}
