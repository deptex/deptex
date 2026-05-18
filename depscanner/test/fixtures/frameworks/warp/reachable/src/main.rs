use warp::Filter;

// CVE-2023-26964 (proxy) — warp 0.3.3 transitive h2 DoS via excessive memory.
// Reachable via any HTTP/2-capable warp filter that consumes large request bodies.
// We add a body-echo route to demonstrate the surface.
#[tokio::main]
async fn main() {
    let echo = warp::path!("echo")
        .and(warp::body::bytes())
        .map(|b: bytes::Bytes| {
            // Sink: handle attacker-controlled body bytes.
            warp::reply::with_status(format!("len={}", b.len()), warp::http::StatusCode::OK)
        });
    warp::serve(echo).run(([127, 0, 0, 1], 8080)).await;
}
