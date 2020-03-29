extern crate aws_sig_verify;
extern crate chrono;
extern crate futures;
extern crate gotham;
extern crate hyper;

use std::collections::HashMap;
use std::io;

/// Re-export aws_sig_verify so users don't have to compute versions.
pub use aws_sig_verify::{
    AWSSigV4Algorithm, AWSSigV4, ErrorKind, Request, SignatureError,
    SigningKeyFn, SigningKeyKind, normalize_uri_path_component,
    canonicalize_uri_path, normalize_query_parameters,
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
    use aws_sig_verify::{ErrorKind, SignatureError, SigningKeyKind};
    use gotham::pipeline::new_pipeline;
    use gotham::pipeline::single::single_pipeline;
    use gotham::plain::test::TestServer;
    use gotham::router::builder::{build_router, DefineSingleRoute, DrawRoutes};
    use gotham::router::Router;
    use gotham::state::State;
    use http::status::StatusCode;
    use hyper::{Body, Response};
    use hyper::header::HeaderValue;
    use ring::digest::SHA256;
    use ring::hmac;
    use super::AWSSigV4Verifier;

    fn generic_handler(state: State) -> (State, Response<Body>) {
        let response: Response<Body> = Response::builder()
            .header("Content-Type", "text/plain; charset=utf-8")
            .status(StatusCode::OK)
            .body(Body::from("OK"))
            .unwrap();

        (state, response)
    }

    fn get_signing_key(
        kind: SigningKeyKind,
        _access_key_id: &str,
        _session_token: Option<&str>,
        req_date_opt: Option<&str>,
        region_opt: Option<&str>,
        service_opt: Option<&str>
    ) -> Result<Vec<u8>, SignatureError> {
        let k_secret = "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".as_bytes();
        match kind {
            SigningKeyKind::KSecret => Ok(k_secret.to_vec()),
            _ => get_signing_key_kdate(kind, k_secret, req_date_opt, region_opt, service_opt)
        }
    }

    fn get_signing_key_kdate(
        kind: SigningKeyKind,
        k_secret: &[u8],
        req_date_opt: Option<&str>,
        region_opt: Option<&str>,
        service_opt: Option<&str>
    ) -> Result<Vec<u8>, SignatureError> {
        if let Some(req_date) = req_date_opt {
            let k_date = hmac::sign(
                &hmac::SigningKey::new(&SHA256, k_secret.as_ref()),
                req_date.as_bytes());
            match kind {
                SigningKeyKind::KDate => Ok(k_date.as_ref().to_vec()),
                _ => get_signing_key_kregion(kind, k_date.as_ref(), region_opt, service_opt)
            }
        } else {
            Err(SignatureError::new(ErrorKind::InvalidCredential, "Missing request date parameter"))
        }
    }

    fn get_signing_key_kregion(
        kind: SigningKeyKind,
        k_date: &[u8],
        region_opt: Option<&str>,
        service_opt: Option<&str>
    ) -> Result<Vec<u8>, SignatureError> {
        if let Some(region) = region_opt {
            let k_region = hmac::sign(
                &hmac::SigningKey::new(&SHA256, k_date.as_ref()),
                region.as_bytes());
            match kind {
                SigningKeyKind::KRegion => Ok(k_region.as_ref().to_vec()),
                _ => get_signing_key_kservice(kind, k_region.as_ref(), service_opt)
            }
        } else {
            Err(SignatureError::new(ErrorKind::InvalidCredential, "Missing request region parameter"))
        }
    }

    fn get_signing_key_kservice(
        kind: SigningKeyKind,
        k_region: &[u8],
        service_opt: Option<&str>
    ) -> Result<Vec<u8>, SignatureError> {
        if let Some(service) = service_opt {
            let k_service = hmac::sign(
                &hmac::SigningKey::new(&SHA256, k_region.as_ref()),
                service.as_bytes());
            match kind {
                SigningKeyKind::KService => Ok(k_service.as_ref().to_vec()),
                _ => {
                    let k_signing = hmac::sign(
                        &hmac::SigningKey::new(&SHA256, k_service.as_ref()),
                        "aws4_request".as_bytes());
                    Ok(k_signing.as_ref().to_vec())
                }
            }
        } else {
            Err(SignatureError::new(ErrorKind::InvalidCredential, "Missing service parameter"))
        }
    }

    fn router() -> Router {
        let verifier = AWSSigV4Verifier{
            signing_key_kind: SigningKeyKind::KSigning,
            signing_key_fn: get_signing_key,
            allowed_mismatch: None,
            service: "service".to_string(),
            region: "us-east-1".to_string(),
        };
        let (chain, pipelines) = single_pipeline(new_pipeline().add(verifier).build());

        build_router(chain, pipelines, |route| {
            route.get("/").to(generic_handler);
        })
    }
    #[test]
    fn check_verify() {
        let test_server = TestServer::new(router()).unwrap();
        let test_client = test_server.client();

        // This is the get-vanilla AWS testcase.
        let response = test_client.get("http://localhost/")
            .with_header("Host", HeaderValue::from_static("example.amazonaws.com"))
            .with_header("X-Amz-Date", HeaderValue::from_static("20150830T123600Z"))
            .with_header("Authorization", HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"))
            .perform().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
