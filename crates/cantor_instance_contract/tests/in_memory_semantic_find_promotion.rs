use cantor_instance_contract::fixture::{
    eclipse_kernel_candidate_fixture, published_kernel_fixture,
};
use cantor_instance_contract::{
    CompatibilityStatus, compile_compatibility, seal_kernel_capabilities,
};

const PROJECT_ASSEMBLY_BOOKEND: &str = "b31ee13cd4246f5be73d64bdaa68baf5357a601c";

#[test]
fn semantic_find_promotes_without_admitting_whole_scribe() {
    let mut kernel = published_kernel_fixture();
    kernel.capabilities_digest.clear();
    kernel.implementation_commit = PROJECT_ASSEMBLY_BOOKEND.to_owned();
    kernel
        .capabilities
        .insert(cantor_sop_semantics::CAPABILITY.to_owned());
    kernel
        .capabilities
        .insert(cantor_sop_project::CAPABILITY.to_owned());
    kernel
        .capabilities
        .insert(cantor_sop_query::CAPABILITY.to_owned());
    let promoted = seal_kernel_capabilities(kernel).unwrap();
    assert!(promoted.capabilities.contains("kernel.sop.semantic-find"));

    let whole_scribe = compile_compatibility(&promoted, &eclipse_kernel_candidate_fixture())
        .expect("whole-crate candidate remains structurally readable");
    assert_eq!(whole_scribe.status, CompatibilityStatus::Held);
    assert!(
        whole_scribe
            .refusals
            .contains("kernel_candidate_requires_separate_promotion:compiled-sop-reader")
    );
}
