// rocket is in dependencies but the binary contains no #[launch] attribute,
// no #[get]/#[post] handlers, and never calls rocket::build().
fn main() {
    println!("nothing to do");
}
