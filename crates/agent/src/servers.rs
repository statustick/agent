//! The optional ports: health (`/healthz`, `/readyz`), metrics (`/metrics`) and the heartbeat relay. Each answers only
//! its own paths, reads headers and the request within 5 seconds, and the relay takes at most 256 connections.
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower_service::Service;

use crate::agent::Agent;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const RELAY_MAX_CONNECTIONS: usize = 256;

fn text(status: StatusCode, body: &str) -> Response {
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

/// Serves [router] on [listener] until the process ends.
pub async fn serve(listener: TcpListener, router: Router, max_connections: Option<usize>) {
    let limit = max_connections.map(|count| Arc::new(Semaphore::new(count)));
    loop {
        let Ok((stream, peer)) = listener.accept().await else { continue };
        let permit = match &limit {
            Some(limit) => match limit.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => continue,
            },
            None => None,
        };
        let router = router.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
                request.extensions_mut().insert(ConnectInfo(peer));
                let mut router = router.clone();
                async move {
                    let request = request.map(Body::new);
                    match tokio::time::timeout(REQUEST_TIMEOUT, router.call(request)).await {
                        Ok(response) => response,
                        Err(_) => Ok::<_, Infallible>(text(StatusCode::REQUEST_TIMEOUT, "")),
                    }
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(REQUEST_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service)
                .await;
            drop(permit);
        });
    }
}

/// `/healthz` while the process runs, `/readyz` while StatusTick answers (`paused` while paused in the dashboard).
pub fn health_router(agent: Arc<Agent>) -> Router {
    Router::new().fallback(move |request: Request| {
        let agent = agent.clone();
        async move {
            match request.uri().path() {
                "/healthz" => text(StatusCode::OK, "ok\n"),
                "/readyz" if agent.ready() => text(StatusCode::OK, if agent.paused() { "paused\n" } else { "ok\n" }),
                "/readyz" => text(StatusCode::SERVICE_UNAVAILABLE, "not connected to StatusTick\n"),
                _ => text(StatusCode::NOT_FOUND, "not found\n"),
            }
        }
    })
}

/// `GET /metrics` and nothing else.
pub fn metrics_router(agent: Arc<Agent>) -> Router {
    Router::new().fallback(move |request: Request| {
        let agent = agent.clone();
        async move {
            if request.method() != Method::GET || request.uri().path() != "/metrics" {
                return text(StatusCode::NOT_FOUND, "not found\n");
            }
            let mut response = text(StatusCode::OK, &agent.metrics.text(&agent.snapshot()));
            response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"));
            response
        }
    })
}

/// Every address of the host, IPv6 and IPv4.
pub fn bind_any(port: u16) -> std::io::Result<TcpListener> {
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
    socket.listen(511)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

pub async fn bind(host: &str, port: u16) -> std::io::Result<TcpListener> {
    let address: SocketAddr =
        format!("{}:{port}", if host.contains(':') { format!("[{host}]") } else { host.to_string() }).parse().map_err(std::io::Error::other)?;
    TcpListener::bind(address).await
}
