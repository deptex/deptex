use axum::Router;

// axum is in deps, but no routes are added and no Server is started.
fn main() {
    let _app: Router = Router::new();
}
