extern crate aws_sig_verify;
extern crate chrono;
extern crate futures;
extern crate gotham;
extern crate hyper;

use std::collections::HashMap;
use std::io;

use aws_sig_verify::{
    AWSSigV4, Request, SigningKeyFn, SigningKeyKind
};

use futures::future;
use futures::Async::{Ready, NotReady};
use futures::stream::Stream;
use chrono::Duration;
use gotham::handler::{HandlerFuture, IntoHandlerError};
use gotham::middleware::{Middleware, NewMiddleware};
use gotham::state::{FromState, State};
use hyper::{Body, HeaderMap, Method, Uri};
use hyper::header::HeaderValue;
use http::status::StatusCode;

/// AWSSigV4Verifier implements middleware for Gotham that implements the
/// AWS SigV4 signing protocol.
///
/// Verifying the signature requires reading (and thus consuming) the body.
/// Upon a successful signature verification, the `hyper::Body` object in the
/// state is replaced with a new body that contains all of the bytes read.
#[derive(Clone)]
pub struct AWSSigV4Verifier {
    pub signing_key_kind: SigningKeyKind,
    pub signing_key_fn: SigningKeyFn,
    pub allowed_mismatch: Option<Duration>,
    pub service: String,
    pub region: String,
}

impl AWSSigV4Verifier {
    /// The new method creates a AWSSigV4Verifier with preferred defaults
    /// for `signing_key_kind` (`KSigning`) and `allowed_mismatch` (5 minutes).
    pub fn new(
        signing_key_fn: SigningKeyFn, service: &str, region: &str)
    -> Self {
        AWSSigV4Verifier{
            signing_key_kind: SigningKeyKind::KSigning,
            signing_key_fn: signing_key_fn,
            allowed_mismatch: Some(Duration::minutes(5)),
            service: service.to_string(),
            region: region.to_string(),
        }
    }
}

impl NewMiddleware for AWSSigV4Verifier {
    type Instance = Self;

    fn new_middleware(&self) -> io::Result<Self::Instance> {
        Ok(self.clone())
    }
}

impl Middleware for AWSSigV4Verifier {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Box<HandlerFuture>
    where
        Chain: FnOnce(State) -> Box<HandlerFuture> + Send + 'static,
    {
        let mut body: Vec<u8> = Vec::new();
        if let Some(mut hyper_body) = state.try_take::<Body>() {
            // Read the body, consuming all of the bytes from it.
            loop {
                match hyper_body.poll() {
                    Err(e) => return Box::new(future::err((
                        state,
                        e.into_handler_error().with_status(StatusCode::UNPROCESSABLE_ENTITY),
                    ))),
                    Ok(asyncopt) => match asyncopt {
                        NotReady => (),
                        Ready(opt) => match opt {
                            Some(chunk) => body.append(&mut chunk.as_ref().to_vec()),
                            None => break,
                        }
                    }
                }
            }

            // Replace the body with the bytes we read.
            state.put(Body::from(body.clone()));
        }

        // Read the other attributes of the request.
        let method = Method::borrow_from(&state);
        let uri = Uri::borrow_from(&state);
        let header_map = HeaderMap::<HeaderValue>::borrow_from(&state);
        let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();

        // Push header key/values onto the HashMap for aws_sig_verify.
        for (hyper_key, hyper_value) in header_map.iter() {
            let key = hyper_key.as_str().to_string();
            let values = headers.entry(key).or_insert_with(|| {
                Vec::<Vec<u8>>::new()
            });
            values.push(hyper_value.as_bytes().to_vec());
        }

        let request = Request{
            request_method: method.to_string(),
            uri_path: uri.path().to_string(),
            query_string: match uri.query() {
                Some(s) => s.to_string(),
                None => "".to_string(),
            },
            headers: headers,
            body: body,
            region: self.region,
            service: self.service,
        };

        let sigv4 = AWSSigV4::new();
        if let Err(e) = sigv4.verify(
            &request, self.signing_key_kind, self.signing_key_fn,
            self.allowed_mismatch)
        {
            return Box::new(future::err((
                state,
                e.into_handler_error().with_status(StatusCode::UNAUTHORIZED),
            )));
        }

        chain(state)
    }
}

#[cfg(test)]
mod tests {
    #[test]
            fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
