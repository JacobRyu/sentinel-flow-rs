//! HTTP endpoints for Prometheus scraping and Kubernetes probes.

use std::convert::Infallible;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use tracing::info;

use crate::metrics::SensorMetrics;

/// Serve Prometheus metrics and health probes on `listener` until `shutdown`
/// resolves.
///
/// Routes:
/// - `GET /metrics` — Prometheus text exposition (sentinel_* metrics)
/// - `GET /healthz` — liveness: always 200 while the process runs
/// - `GET /readyz` — readiness: 200 once capture has started, 503 before
pub async fn serve(
    listener: TcpListener,
    metrics: Arc<SensorMetrics>,
    ready: Arc<AtomicBool>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), hyper::Error> {
    let addr = listener.local_addr().expect("listener address");
    let make_service = make_service_fn(move |_conn| {
        let metrics = metrics.clone();
        let ready = ready.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let metrics = metrics.clone();
                let ready = ready.clone();
                async move { Ok::<_, Infallible>(respond(&req, &metrics, &ready)) }
            }))
        }
    });

    info!("Metrics endpoint listening on http://{addr}/metrics");
    Server::from_tcp(listener)?.serve(make_service).with_graceful_shutdown(shutdown).await
}

fn respond(req: &Request<Body>, metrics: &SensorMetrics, ready: &AtomicBool) -> Response<Body> {
    match req.uri().path() {
        "/metrics" => match metrics.export() {
            Ok(body) => Response::builder()
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Body::from(body))
                .expect("static metrics response"),
            Err(err) => Response::builder()
                .status(500)
                .body(Body::from(format!("metrics export failed: {err}")))
                .expect("static error response"),
        },
        "/healthz" => Response::new(Body::from("ok")),
        "/readyz" => {
            if ready.load(Ordering::Relaxed) {
                Response::new(Body::from("ready"))
            } else {
                Response::builder()
                    .status(503)
                    .body(Body::from("not ready"))
                    .expect("static not-ready response")
            }
        }
        _ => Response::builder()
            .status(404)
            .body(Body::from("not found"))
            .expect("static not-found response"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct TestServer {
        addr: std::net::SocketAddr,
        shutdown: tokio::sync::oneshot::Sender<()>,
        task: tokio::task::JoinHandle<Result<(), hyper::Error>>,
        ready: Arc<AtomicBool>,
    }

    async fn start_server() -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test port");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("listener address");
        let metrics = Arc::new(SensorMetrics::new().expect("metrics"));
        let ready = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve(listener, metrics, ready.clone(), async move {
            let _ = shutdown_rx.await;
        }));
        TestServer { addr, shutdown: shutdown_tx, task, ready }
    }

    async fn get(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.expect("write request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read response");
        let text = String::from_utf8_lossy(&response).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .expect("status line")
            .parse::<u16>()
            .expect("status code");
        (status, text)
    }

    #[tokio::test]
    async fn serves_metrics_and_probes() {
        let server = start_server().await;

        let (status, body) = get(server.addr, "/metrics").await;
        assert_eq!(status, 200);
        assert!(body.contains("sentinel_packets_captured_total"), "metrics missing: {body}");

        let (status, _) = get(server.addr, "/healthz").await;
        assert_eq!(status, 200);

        // Not ready until capture starts.
        let (status, _) = get(server.addr, "/readyz").await;
        assert_eq!(status, 503);
        server.ready.store(true, Ordering::Relaxed);
        let (status, _) = get(server.addr, "/readyz").await;
        assert_eq!(status, 200);

        let (status, _) = get(server.addr, "/nope").await;
        assert_eq!(status, 404);

        let _ = server.shutdown.send(());
        assert!(server.task.await.expect("server task").is_ok());
    }
}
