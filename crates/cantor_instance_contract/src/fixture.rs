//! Deterministic structural fixtures for the first hosted instance candidate.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ComponentBinding, ComponentRole, INSTANCE_PROFILE, InstanceManifest, KERNEL_API_PROFILE,
    KERNEL_PROFILE, KernelCapabilities, NON_AUTHORITY, SourceLineage, seal_instance_manifest,
    seal_kernel_capabilities,
};

const PUBLISHED_CANTOR_HEAD: &str = "80f2ef9a8c1709e9e0dc12d70fc340a53919eec2";
const ECLIPSE_SOURCE_HEAD: &str = "82a3e19b839fd4e937ecb1f366859289364529c0";
const SOURCE_SNAPSHOT_UUID: &str = "670483d0-3f70-49b5-8d7c-d924065ce004";

pub fn published_kernel_fixture() -> KernelCapabilities {
    seal_kernel_capabilities(KernelCapabilities {
        profile: KERNEL_PROFILE.to_owned(),
        api_profile: KERNEL_API_PROFILE.to_owned(),
        implementation_commit: PUBLISHED_CANTOR_HEAD.to_owned(),
        capabilities: set(&[
            "kernel.attention.retention",
            "kernel.audit.explanation",
            "kernel.instance.contract",
            "kernel.package.identity",
            "kernel.semantic.recipe.evaluate",
            "kernel.semantic.three-valued",
            "kernel.sop.source.read",
        ]),
        non_authority: NON_AUTHORITY.to_owned(),
        capabilities_digest: String::new(),
    })
    .expect("published kernel fixture must remain valid")
}

pub fn eclipse_instance_candidate_fixture() -> InstanceManifest {
    let required = set(&[
        "kernel.attention.retention",
        "kernel.audit.explanation",
        "kernel.package.identity",
        "kernel.semantic.recipe.evaluate",
        "kernel.semantic.three-valued",
        "kernel.sop.source.read",
    ]);
    let mut components = BTreeMap::new();
    components.insert(
        "recipe-view".to_owned(),
        ComponentBinding {
            component_id: "recipe-view".to_owned(),
            role: ComponentRole::InstanceAdapter,
            relative_path: "docs/SCRIBE_RECIPE_ECLIPSE_0_1.md".to_owned(),
            content_sha256: "dfc993c2c5b92d51117aa65c664b2b45075b35eec3ee892fb9b39f05128becbb"
                .to_owned(),
            required_capabilities: set(&[
                "kernel.semantic.recipe.evaluate",
                "kernel.sop.source.read",
            ]),
            provided_capabilities: set(&["instance.sop.eclipse.recipe-view"]),
            requested_authorities: BTreeSet::new(),
            kernel_slot: None,
        },
    );
    components.insert(
        "recipe-suite".to_owned(),
        ComponentBinding {
            component_id: "recipe-suite".to_owned(),
            role: ComponentRole::Package,
            relative_path: "docs/SCRIBE_RECIPE_SUITE_20260930.md".to_owned(),
            content_sha256: "0560d1ab4428631ae5c0c1b6a48ccbb1b189296463f145914bb0f5696e6ad3b5"
                .to_owned(),
            required_capabilities: required.clone(),
            provided_capabilities: set(&["package.sop.eclipse.recipe-suite"]),
            requested_authorities: BTreeSet::new(),
            kernel_slot: None,
        },
    );
    components.insert(
        "source-specification".to_owned(),
        ComponentBinding {
            component_id: "source-specification".to_owned(),
            role: ComponentRole::Evidence,
            relative_path: "specifications/Eclipse_SOP_Scribe_P0.sop".to_owned(),
            content_sha256: "95e2bfe3cb045f5748d42212277a0c0845532a0bb65f85171a8b456f9d21c7ed"
                .to_owned(),
            required_capabilities: BTreeSet::new(),
            provided_capabilities: BTreeSet::new(),
            requested_authorities: BTreeSet::new(),
            kernel_slot: None,
        },
    );
    seal_instance_manifest(InstanceManifest {
        profile: INSTANCE_PROFILE.to_owned(),
        instance_id: "sop.eclipse".to_owned(),
        display_name: "SOP Eclipse".to_owned(),
        revision: 1,
        kernel_api_profile: KERNEL_API_PROFILE.to_owned(),
        source_lineage: SourceLineage {
            repository: "https://github.com/cattailfarmer/Cantor".to_owned(),
            base_commit: ECLIPSE_SOURCE_HEAD.to_owned(),
            source_snapshot_uuid: SOURCE_SNAPSHOT_UUID.to_owned(),
        },
        required_capabilities: required,
        provided_capabilities: set(&[
            "instance.sop.eclipse.recipe-view",
            "package.sop.eclipse.recipe-suite",
        ]),
        requested_authorities: BTreeSet::new(),
        components,
        non_authority: NON_AUTHORITY.to_owned(),
        manifest_digest: String::new(),
    })
    .expect("Eclipse instance fixture must remain structurally valid")
}

pub fn eclipse_kernel_candidate_fixture() -> InstanceManifest {
    let mut fixture = eclipse_instance_candidate_fixture();
    fixture.manifest_digest.clear();
    fixture.components.insert(
        "compiled-sop-reader".to_owned(),
        ComponentBinding {
            component_id: "compiled-sop-reader".to_owned(),
            role: ComponentRole::KernelCandidate,
            relative_path: "crates/cantor_scribe/src/lib.rs".to_owned(),
            content_sha256: "f25148ebf2b02578896ec1bdd7b06992b95144b305f85b6253880b61fdb2c89b"
                .to_owned(),
            required_capabilities: BTreeSet::new(),
            provided_capabilities: set(&["kernel.sop.compiled-reader"]),
            requested_authorities: BTreeSet::new(),
            kernel_slot: Some("kernel.sop.compiled-reader".to_owned()),
        },
    );
    seal_instance_manifest(fixture)
        .expect("kernel candidate fixture must remain structurally valid")
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
