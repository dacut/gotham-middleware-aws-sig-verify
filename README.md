# Gotham middleware for AWS SigV4 verification
## Crate: [gotham_middleware_aws_sig_verify](https://crates.io/crates/gotham_middleware_aws_sig_verify)

The `gotham_middleware_aws_sig_verify` crate integrates AWS SigV4 verification
(from [aws_sig_verify](https://github.com/dacut/rust-aws-sig/)) into the
[Gotham](https://gotham.rs/) web framework.

Assuming you have a function `get_signing_key` that can return signing keys
given AWS access keys (and optionally tokens), integration would be done
similarly to:

```rust
use gotham;
use gotham::pipeline::new_pipeline;
use gotham::pipeline::single::single_pipeline;
use gotham::router::builder::{build_router, DefineSingleRoute, DrawRoutes};
use gotham::router::Router;
use gotham::state::State;
use gotham_middleware_aws_sig_verify::{AWSSigV4Verifier, SigningKeyKind, SignatureError};
use http::status::StatusCode;
use hyper::{Body, Response};

const SERVICE: &str = "myservice";
const REGION: &str = "local";

fn router() -> Router {
    let verifier = AWSSigV4Verifier::new(get_signing_key, SERVICE, REGION);
    let (chain, pipelines) = single_pipeline(new_pipeline().add(verifier).build());
    build_router(chain, pipelines, |route| {
        route.get("/").to(my_handler);
    })
}

fn my_handler(state: State) -> (State, Response<Body>) {
    let response: Response<Body> = Response::builder()
        .header("Content-Type", "text/plain; charset=utf-8")
        .status(StatusCode::OK)
        .body(Body::from("OK"))
        .unwrap();

    (state, response)
}

fn get_signing_key(
    kind: SigningKeyKind,
    access_key_id: &str,
    session_token: Option<&str>,
    req_date_opt: Option<&str>,
    region_opt: Option<&str>,
    service_opt: Option<&str>
) -> Result<Vec<u8>, SignatureError> {
    ...
}

pub fn main() {
    gotham::start("127.0.0.1:8080", router())
}
```