#[macro_use]
extern crate rocket;

use std::process::Command;

// Pair rocket 0.5.0-rc.1 with a command-injection sink driven by user input
// so the dataflow analysis sees a concrete reachable flow.
#[post("/run?<cmd>")]
fn run(cmd: &str) -> &'static str {
    // Sink: user-controlled command via shell.
    let _ = Command::new("sh").arg("-c").arg(cmd).output();
    "ok"
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![run])
}
