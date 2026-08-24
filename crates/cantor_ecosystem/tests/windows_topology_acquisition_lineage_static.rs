use std::{fs, path::Path};

use cantor_ecosystem::{
    sha256_file,
    windows_supplied_ordered_topology_inventory_digest::WindowsSuppliedOrderedTopologyInventoryDigest,
    windows_supplied_ordered_topology_inventory_digest_reconciliation::WindowsSuppliedOrderedTopologyInventoryDigestReconciliation,
    windows_topology_acquisition_lineage::{
        AcquisitionIdentity, AcquisitionLineageBinding, AcquisitionLineageMetadataClaim,
        AcquisitionScopeClaim, CausalOrderClaim, CausalOrderKind, CompletionDisposition,
        OrderedAcquisitionPairBinding, OrderedAcquisitionPairMetadataClaim,
        REPEATED_INVENTORY_EVIDENCE_PLAN_MAX_BYTES, RepeatedInventoryEvidenceClaim,
        RepeatedInventoryEvidencePlan, WINDOWS_TOPOLOGY_ACQUISITION_LINEAGE_PROFILE,
    },
};
use serde::{Serialize, de::DeserializeOwned};

macro_rules! assert_not_deserialize_owned {
    ($ty:ty) => {
        const _: fn() = || {
            struct IfImpl;
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + DeserializeOwned> AmbiguousIfImpl<IfImpl> for T {}
            let _ = <$ty as AmbiguousIfImpl<_>>::check;
        };
    };
}

assert_not_deserialize_owned!(WindowsSuppliedOrderedTopologyInventoryDigest);
assert_not_deserialize_owned!(AcquisitionLineageBinding);
assert_not_deserialize_owned!(OrderedAcquisitionPairBinding);
assert_not_deserialize_owned!(WindowsSuppliedOrderedTopologyInventoryDigestReconciliation);
assert_not_deserialize_owned!(RepeatedInventoryEvidenceClaim);

fn assert_metadata<T: Serialize + DeserializeOwned>() {}

#[test]
fn acquisition_lineage_surface_is_strict_output_only_and_effect_free() {
    assert_metadata::<AcquisitionIdentity>();
    assert_metadata::<AcquisitionScopeClaim>();
    assert_metadata::<CompletionDisposition>();
    assert_metadata::<AcquisitionLineageMetadataClaim>();
    assert_metadata::<CausalOrderKind>();
    assert_metadata::<CausalOrderClaim>();
    assert_metadata::<OrderedAcquisitionPairMetadataClaim>();
    assert_metadata::<RepeatedInventoryEvidencePlan>();
    assert_eq!(
        WINDOWS_TOPOLOGY_ACQUISITION_LINEAGE_PROFILE,
        "cantor-phase3-topology-acquisition-lineage-forms/0.2"
    );
    assert_eq!(REPEATED_INVENTORY_EVIDENCE_PLAN_MAX_BYTES, 131_072);

    let source = include_str!("../src/windows_topology_acquisition_lineage.rs");
    let production = source.split_once("#[cfg(test)]").expect("test boundary").0;
    for forbidden in [
        "unsafe {",
        "cfg(windows)",
        "windows_sys",
        "std::fs",
        "std::path",
        "std::process",
        "std::time",
        "std::net",
        "std::env",
        "std::thread",
        "File::",
        "Command::",
        "SystemTime",
        "Instant",
        "TopologyReceipt {",
        "impl From<",
        "impl Into<",
        "pub fn new(",
        "pub fn from_",
        "Default",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden production token: {forbidden}"
        );
    }
    for required in [
        "decode_repeated_inventory_evidence_plan(",
        "derive_repeated_inventory_evidence_claim(",
        "derive_windows_supplied_ordered_topology_inventory_digest(",
        "reconcile_windows_supplied_ordered_topology_inventory_digests(",
        "!= WindowsSuppliedOrderedTopologyInventoryDigestReconciliationDisposition::Equal",
        "AcquisitionLineageFaultCode::Different",
        "InventoryConsistencyEvidence::NonAtomicRepeatedInventoryEqual",
        "AcquisitionEvidenceProvenanceGrade::ClaimOnly",
        "TopologyEntryKind::RootDirectory",
        "scope_mismatch(role, \"root.identity\")",
        "scope_mismatch(role, \"limits\")",
        "current carrier rederivation contradicted the supplied complete carrier",
    ] {
        assert!(production.contains(required), "missing token: {required}");
    }
    assert_eq!(production.matches("pub fn ").count(), 41);
    assert_eq!(
        production.matches("#[serde(deny_unknown_fields)]").count(),
        7
    );

    for declaration in [
        "pub struct AcquisitionLineageBinding {",
        "pub struct OrderedAcquisitionPairBinding {",
        "pub struct RepeatedInventoryEvidenceClaim {",
    ] {
        let position = production.find(declaration).expect("output declaration");
        let derive_start = production[..position]
            .rfind("#[derive(")
            .expect("output derive");
        let derive = &production[derive_start..position];
        assert!(derive.contains("Serialize"));
        assert!(!derive.contains("Deserialize"));
        let body = production[position..]
            .split_once('{')
            .expect("output body")
            .1
            .split_once('}')
            .expect("output body end")
            .0;
        assert!(!body.contains("pub "), "output fields must remain private");
    }

    let lib = include_str!("../src/lib.rs");
    assert_eq!(
        lib.matches("pub mod windows_topology_acquisition_lineage;")
            .count(),
        1
    );
}

#[test]
fn acquisition_lineage_evidence_manifest_is_current_portable_and_non_authorizing() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository_root = crate_root
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(
            crate_root.join("evidence/windows_topology_acquisition_lineage_evidence_manifest.json"),
        )
        .expect("manifest"),
    )
    .expect("JSON");
    assert_eq!(
        manifest["schema"],
        "cantor-windows-topology-acquisition-lineage-evidence-manifest/0.2"
    );
    assert_eq!(
        manifest["evidence_manifest_uuid"],
        "3925aeb0-e6a6-4f1e-91d1-393aef979568"
    );
    assert_eq!(
        manifest["authority"]["satisfaction_signature_uuid"],
        "ee5898fe-26cc-410c-b82b-f25f6738d77d"
    );
    assert_eq!(manifest["scope"]["metadata_deserialize_owned"], true);
    assert_eq!(manifest["scope"]["carrier_graph_deserialize_owned"], false);
    assert_eq!(manifest["scope"]["current_rederivation"], true);
    assert_eq!(manifest["scope"]["current_reconciliation"], true);
    assert_eq!(manifest["scope"]["claim_only_equal_release"], true);
    for absent in [
        "physical_acquisition_authority",
        "causal_truth_authority",
        "producer_authority",
        "issuer_authority",
        "consumer_authority",
        "receipt_authority",
        "admission_authority",
        "mutation_authority",
        "provider_authority",
        "persistence_authority",
    ] {
        assert_eq!(manifest["scope"][absent], false, "absent: {absent}");
    }
    let artifacts = manifest["artifacts"].as_array().expect("artifacts");
    assert!(artifacts.len() >= 30);
    for artifact in artifacts {
        let path = artifact["path"].as_str().expect("path");
        assert!(!Path::new(path).is_absolute());
        assert!(!path.contains('\\'));
        assert!(!path.split('/').any(|part| part == ".."));
        let full = repository_root.join(path);
        let bytes = fs::read(&full).unwrap_or_else(|error| panic!("{path}: {error}"));
        assert_eq!(
            artifact["bytes"].as_u64(),
            u64::try_from(bytes.len()).ok(),
            "bytes: {path}"
        );
        assert_eq!(
            artifact["sha256"].as_str().unwrap().to_ascii_lowercase(),
            sha256_file(&full).unwrap(),
            "hash: {path}"
        );
    }
}
