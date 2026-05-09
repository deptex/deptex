// warp is in dependencies but no filters are constructed and warp::serve
// is never called. The HTTP attack surface does not exist.
fn main() {
    println!("nothing to serve");
}
