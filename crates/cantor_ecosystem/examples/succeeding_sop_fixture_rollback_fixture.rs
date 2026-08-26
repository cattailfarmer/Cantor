#[cfg(all(not(test), not(windows)))]
#[path = "../tests/succeeding_sop_fixture_rollback.rs"]
mod fixture;

#[cfg(all(not(test), not(windows)))]
fn main() {
    println!("{}", fixture::development_success_receipt_machine_form());
}

#[cfg(any(test, windows))]
fn main() {}
