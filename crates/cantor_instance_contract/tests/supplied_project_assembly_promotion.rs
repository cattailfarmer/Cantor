use cantor_instance_contract::fixture::{
    eclipse_kernel_candidate_fixture, published_kernel_fixture,
};
use cantor_instance_contract::{
    CompatibilityStatus, compile_compatibility, seal_kernel_capabilities,
};

const SEMANTIC_KERNEL_BOOKEND: &str = "f9dcaebdcd97ece5ada0ba54648fdae7e5a61ea9";

#[test]
fn supplied_project_capability_promotes_without_admitting_whole_scribe() {
    let mut kernel = published_kernel_fixture();
    kernel.capabilities_digest.clear();
    kernel.implementation_commit = SEMANTIC_KERNEL_BOOKEND.to_owned();
    kernel
        .capabilities
        .insert(cantor_sop_semantics::CAPABILITY.to_owned());
    kernel
        .capabilities
        .insert(cantor_sop_project::CAPABILITY.to_owned());
    let promoted = seal_kernel_capabilities(kernel).unwrap();
    assert!(
        promoted
            .capabilities
            .contains("kernel.sop.semantic-analyze")
    );
    assert!(
        promoted
            .capabilities
            .contains("kernel.sop.project-assemble")
    );

    let whole_scribe = compile_compatibility(&promoted, &eclipse_kernel_candidate_fixture())
        .expect("whole-crate candidate remains structurally readable");
    assert_eq!(whole_scribe.status, CompatibilityStatus::Held);
    assert!(
        whole_scribe
            .refusals
            .contains("kernel_candidate_requires_separate_promotion:compiled-sop-reader")
    );
}
