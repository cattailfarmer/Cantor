#[path = "../tests/support/mod.rs"]
mod support;

fn main() {
    use std::io::Write;
    std::io::stdout()
        .lock()
        .write_all(&support::bundle_bytes())
        .unwrap();
}
