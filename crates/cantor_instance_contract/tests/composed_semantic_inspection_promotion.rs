use cantor_instance_contract::fixture::{
    eclipse_kernel_candidate_fixture, published_kernel_fixture,
};
use cantor_instance_contract::{
    CompatibilityStatus, compile_compatibility, seal_kernel_capabilities,
};

const FORMATION_BOOKEND: &str = "136261efd3733fbb671394fb5b908a38ec41b52d";

#[test]
fn composed_inspection_promotes_without_admitting_whole_scribe() {
    let mut kernel = published_kernel_fixture();
    kernel.capabilities_digest.clear();
    kernel.implementation_commit = FORMATION_BOOKEND.to_owned();
    for capability in [
        cantor_sop_semantics::CAPABILITY,
        cantor_sop_project::CAPABILITY,
        cantor_sop_query::CAPABILITY,
        cantor_sop_excerpt::CAPABILITY,
        cantor_sop_inspect::CAPABILITY,
    ] {
        kernel.capabilities.insert(capability.to_owned());
    }
    let promoted = seal_kernel_capabilities(kernel).unwrap();
    assert!(
        promoted
            .capabilities
            .contains("kernel.sop.semantic-inspect")
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
