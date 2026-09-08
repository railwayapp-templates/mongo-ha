//! HTTP Basic auth for the health server's mutating route.
//!
//! `HEALTH_API_PASSWORD` set → `POST /switchover` requires
//! `Authorization: Basic base64(HEALTH_API_USERNAME:HEALTH_API_PASSWORD)`
//! (username default `railway`); anything else answers 401 with a
//! `WWW-Authenticate` challenge. Unset → the route stays open, which is what
//! lets a running set adopt enforcement one variable edit at a time: callers
//! send the credential whenever the member has one, and a member that does
//! not enforce yet simply ignores the header.
//!
//! Reads (`/health`, `/role`, `/rs/state`) never require it — HAProxy's
//! routing probe and the peers' initiate guards read them — and
//! `/rs/keyfile` keeps its own body credential: the joiner proves the root
//! password against this node's mongod, the one secret a fresh member is
//! guaranteed to hold.

use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::sync::Arc;
use tracing::warn;

/// The credential the mutating route requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

/// What the layer enforces: `None` leaves the route open.
pub type Guard = Arc<Option<Credential>>;

pub const REALM: &str = "railway-ha";

/// Wraps `routes` so every one of them requires the credential in `guard`.
/// A `route_layer` on purpose: it applies to the routes it wraps and to
/// nothing merged in beside them.
pub fn protect<S>(routes: Router<S>, guard: Guard) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    routes.route_layer(from_fn_with_state(guard, require))
}

/// The `Authorization` header value a caller sends for `cred`.
pub fn basic_header(cred: &Credential) -> String {
    format!(
        "Basic {}",
        BASE64.encode(format!("{}:{}", cred.username, cred.password))
    )
}

async fn require(State(guard): State<Guard>, req: Request, next: Next) -> Response {
    let Some(expected) = guard.as_ref() else {
        return next.run(req).await;
    };
    if authorized(expected, req.headers().get(header::AUTHORIZATION)) {
        return next.run(req).await;
    }
    warn!(
        method = %req.method(),
        path = req.uri().path(),
        "refused a request to a mutating route: missing or wrong credential"
    );
    unauthorized()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, format!("Basic realm=\"{REALM}\""))],
        "unauthorized",
    )
        .into_response()
}

/// Whether `header` carries exactly `expected` as HTTP Basic.
pub fn authorized(expected: &Credential, header: Option<&HeaderValue>) -> bool {
    let Some(value) = header.and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(encoded) = basic_payload(value) else {
        return false;
    };
    let Ok(decoded) = BASE64.decode(encoded) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((username, password)) = decoded.split_once(':') else {
        return false;
    };
    // Both halves are always compared so a wrong username costs the same as
    // a wrong password.
    let user_ok = constant_time_eq(username.as_bytes(), expected.username.as_bytes());
    let pass_ok = constant_time_eq(password.as_bytes(), expected.password.as_bytes());
    user_ok & pass_ok
}

/// The base64 payload of a `Basic <payload>` header (scheme case-insensitive,
/// as RFC 7235 has it); None for any other scheme or shape.
fn basic_payload(value: &str) -> Option<&str> {
    let (scheme, rest) = value.trim().split_once(char::is_whitespace)?;
    scheme
        .eq_ignore_ascii_case("basic")
        .then(|| rest.trim())
        .filter(|p| !p.is_empty())
}

/// Length-independent comparison: the length difference is folded into the
/// accumulator and the walk always covers the longer input, so a wrong guess
/// costs the same however much of a prefix it shares with the secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};

    fn cred() -> Credential {
        Credential {
            username: "railway".into(),
            password: "s3cr3t:with:colons".into(),
        }
    }

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    #[test]
    fn missing_header_is_refused() {
        assert!(!authorized(&cred(), None));
    }

    #[test]
    fn other_scheme_is_refused() {
        let token = BASE64.encode("railway:s3cr3t:with:colons");
        assert!(!authorized(&cred(), Some(&hv(&format!("Bearer {token}")))));
    }

    #[test]
    fn bad_base64_is_refused() {
        assert!(!authorized(&cred(), Some(&hv("Basic not*base64*"))));
        assert!(!authorized(&cred(), Some(&hv("Basic"))));
        assert!(!authorized(&cred(), Some(&hv("Basic "))));
    }

    #[test]
    fn payload_without_colon_is_refused() {
        let token = BASE64.encode("railway");
        assert!(!authorized(&cred(), Some(&hv(&format!("Basic {token}")))));
    }

    #[test]
    fn wrong_username_is_refused() {
        let token = BASE64.encode("root:s3cr3t:with:colons");
        assert!(!authorized(&cred(), Some(&hv(&format!("Basic {token}")))));
    }

    #[test]
    fn wrong_password_is_refused() {
        let token = BASE64.encode("railway:s3cr3t");
        assert!(!authorized(&cred(), Some(&hv(&format!("Basic {token}")))));
        let longer = BASE64.encode("railway:s3cr3t:with:colons:more");
        assert!(!authorized(&cred(), Some(&hv(&format!("Basic {longer}")))));
    }

    #[test]
    fn correct_credential_is_accepted() {
        // The password itself contains colons: only the FIRST one separates
        // username from password.
        assert!(authorized(&cred(), Some(&hv(&basic_header(&cred())))));
    }

    #[test]
    fn scheme_is_case_insensitive_and_whitespace_tolerant() {
        let token = BASE64.encode("railway:s3cr3t:with:colons");
        assert!(authorized(&cred(), Some(&hv(&format!("basic {token}")))));
        assert!(authorized(&cred(), Some(&hv(&format!("BASIC   {token} ")))));
    }

    #[test]
    fn basic_header_round_trips() {
        assert_eq!(
            basic_header(&Credential {
                username: "railway".into(),
                password: "pw".into(),
            }),
            "Basic cmFpbHdheTpwdw=="
        );
    }

    #[test]
    fn constant_time_eq_handles_lengths() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    /// The router shape health_server.rs builds: open reads and the
    /// keyfile exchange merged beside a protected switchover.
    fn app(guard: Guard) -> Router {
        let mutating = protect(
            Router::new().route("/switchover", post(|| async { "switched" })),
            guard,
        );
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/role", get(|| async { "primary" }))
            .route("/rs/state", get(|| async { "{}" }))
            .route("/rs/keyfile", post(|| async { "KEYFILE" }))
            .merge(mutating)
    }

    /// Serves `app` on a loopback port for the lifetime of the test.
    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn no_credential_configured_leaves_every_route_open() {
        let base = serve(app(Arc::new(None))).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{base}/switchover"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "switched");
    }

    #[tokio::test]
    async fn only_the_protected_route_requires_the_credential() {
        let base = serve(app(Arc::new(Some(cred())))).await;
        let client = reqwest::Client::new();

        for path in ["/health", "/role", "/rs/state"] {
            let resp = client.get(format!("{base}{path}")).send().await.unwrap();
            assert_eq!(resp.status(), 200, "{path} must stay open");
        }
        let resp = client
            .post(format!("{base}/rs/keyfile"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "/rs/keyfile keeps its own body check");
        assert_eq!(resp.text().await.unwrap(), "KEYFILE");

        let resp = client
            .post(format!("{base}/switchover"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        assert_eq!(
            resp.headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Basic realm=\"railway-ha\"")
        );
        assert_eq!(resp.text().await.unwrap(), "unauthorized");

        let resp = client
            .post(format!("{base}/switchover"))
            .header(header::AUTHORIZATION, "Basic cmFpbHdheTp3cm9uZw==")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "wrong password");

        let resp = client
            .post(format!("{base}/switchover"))
            .header(header::AUTHORIZATION, basic_header(&cred()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "switched");
    }
}
