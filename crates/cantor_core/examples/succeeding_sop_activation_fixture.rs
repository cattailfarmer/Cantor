#[cfg(not(test))]
#[path = "../tests/succeeding_sop_activation_transaction.rs"]
#[allow(dead_code, unused_imports)]
mod fixture;

#[cfg(not(test))]
use cantor_core::{
    SucceedingSopActivationPolicyUseStatus, admit_succeeding_sop_activation_transaction,
    to_succeeding_sop_activation_transaction_receipt_machine_form,
};

#[cfg(not(test))]
fn main() {
    let request =
        fixture::activation_request(SucceedingSopActivationPolicyUseStatus::SyntheticFixtureOnly);
    let receipt =
        admit_succeeding_sop_activation_transaction(&request).expect("synthetic fixture receipt");
    let form = to_succeeding_sop_activation_transaction_receipt_machine_form(&receipt)
        .expect("synthetic fixture machine form");
    println!("{form}");
}
