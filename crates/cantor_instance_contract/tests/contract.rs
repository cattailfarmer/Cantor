use std::collections::BTreeSet;

use cantor_instance_contract::fixture::{
    eclipse_instance_candidate_fixture, eclipse_kernel_candidate_fixture, published_kernel_fixture,
};
use cantor_instance_contract::{
    CompatibilityStatus, ComponentRole, ContractFaultCode, compile_compatibility,
    seal_instance_manifest, validate_compatibility_result, validate_instance_manifest,
};

#[test]
fn eclipse_adapter_and_package_admit_without_kernel_authority() {
    let kernel = published_kernel_fixture();
    let manifest = eclipse_instance_candidate_fixture();
    let result = compile_compatibility(&kernel, &manifest).unwrap();
    assert_eq!(result.status, CompatibilityStatus::Admitted);
    assert!(result.missing_capabilities.is_empty());
    assert!(result.refusals.is_empty());
    validate_compatibility_result(&kernel, &manifest, &result).unwrap();
}

#[test]
fn missing_kernel_capability_holds_with_exact_reason() {
    let mut kernel = published_kernel_fixture();
    kernel.capabilities_digest.clear();
    kernel
        .capabilities
        .remove("kernel.semantic.recipe.evaluate");
    let kernel = cantor_instance_contract::seal_kernel_capabilities(kernel).unwrap();
    let result = compile_compatibility(&kernel, &eclipse_instance_candidate_fixture()).unwrap();
    assert_eq!(result.status, CompatibilityStatus::Held);
    assert_eq!(
        result.missing_capabilities,
        BTreeSet::from(["kernel.semantic.recipe.evaluate".to_owned()])
    );
}

#[test]
fn kernel_candidate_requires_separate_promotion() {
    let manifest = eclipse_kernel_candidate_fixture();
    let result = compile_compatibility(&published_kernel_fixture(), &manifest).unwrap();
    assert_eq!(result.status, CompatibilityStatus::Held);
    assert_eq!(
        result.refusals,
        BTreeSet::from([
            "kernel_candidate_requires_separate_promotion:compiled-sop-reader".to_owned()
        ])
    );
}

#[test]
fn digest_tamper_refuses_before_compatibility() {
    let mut manifest = eclipse_instance_candidate_fixture();
    manifest.display_name.push_str(" changed");
    let error = validate_instance_manifest(&manifest).unwrap_err();
    assert_eq!(error.code, ContractFaultCode::DigestMismatch);
}

#[test]
fn duplicate_component_identity_refuses() {
    let mut manifest = eclipse_instance_candidate_fixture();
    manifest.manifest_digest.clear();
    manifest
        .components
        .get_mut("recipe-view")
        .unwrap()
        .component_id = "different".to_owned();
    let error = seal_instance_manifest(manifest).unwrap_err();
    assert_eq!(error.code, ContractFaultCode::InvalidComponent);
}

#[test]
fn path_traversal_refuses() {
    let mut manifest = eclipse_instance_candidate_fixture();
    manifest.manifest_digest.clear();
    manifest
        .components
        .get_mut("recipe-view")
        .unwrap()
        .relative_path = "../outside".to_owned();
    let error = seal_instance_manifest(manifest).unwrap_err();
    assert_eq!(error.code, ContractFaultCode::InvalidComponent);
}

#[test]
fn adapter_cannot_occupy_kernel_slot() {
    let mut manifest = eclipse_instance_candidate_fixture();
    manifest.manifest_digest.clear();
    manifest
        .components
        .get_mut("recipe-view")
        .unwrap()
        .kernel_slot = Some("kernel.sop.source.read".to_owned());
    let error = seal_instance_manifest(manifest).unwrap_err();
    assert_eq!(error.code, ContractFaultCode::AuthorityEscalation);
}

#[test]
fn instance_and_component_authority_requests_refuse() {
    let mut instance = eclipse_instance_candidate_fixture();
    instance.manifest_digest.clear();
    instance.requested_authorities.insert("operator".to_owned());
    assert_eq!(
        seal_instance_manifest(instance).unwrap_err().code,
        ContractFaultCode::AuthorityEscalation
    );

    let mut component = eclipse_instance_candidate_fixture();
    component.manifest_digest.clear();
    component
        .components
        .get_mut("recipe-view")
        .unwrap()
        .requested_authorities
        .insert("provider".to_owned());
    assert_eq!(
        seal_instance_manifest(component).unwrap_err().code,
        ContractFaultCode::AuthorityEscalation
    );
}

#[test]
fn evidence_cannot_provide_capability() {
    let mut manifest = eclipse_instance_candidate_fixture();
    manifest.manifest_digest.clear();
    let evidence = manifest.components.get_mut("source-specification").unwrap();
    assert_eq!(evidence.role, ComponentRole::Evidence);
    evidence
        .provided_capabilities
        .insert("instance.sop.eclipse.false-proof".to_owned());
    manifest
        .provided_capabilities
        .insert("instance.sop.eclipse.false-proof".to_owned());
    assert_eq!(
        seal_instance_manifest(manifest).unwrap_err().code,
        ContractFaultCode::AuthorityEscalation
    );
}

#[test]
fn unknown_machine_form_field_refuses() {
    let manifest = eclipse_instance_candidate_fixture();
    let mut value = serde_json::to_value(manifest).unwrap();
    value.as_object_mut().unwrap().insert(
        "execution_authorized".to_owned(),
        serde_json::Value::Bool(true),
    );
    let error =
        cantor_instance_contract::parse_instance_manifest(&serde_json::to_vec(&value).unwrap())
            .unwrap_err();
    assert_eq!(error.code, ContractFaultCode::MachineForm);
}

#[test]
fn duplicate_capability_machine_form_member_refuses() {
    let manifest = eclipse_instance_candidate_fixture();
    let encoded = serde_json::to_string_pretty(&manifest).unwrap();
    let needle = "    \"kernel.attention.retention\",";
    assert!(encoded.contains(needle));
    let duplicated = encoded.replacen(needle, &format!("{needle}\n{needle}"), 1);
    let error =
        cantor_instance_contract::parse_instance_manifest(duplicated.as_bytes()).unwrap_err();
    assert_eq!(error.code, ContractFaultCode::MachineForm);
}

#[test]
fn replay_refuses_tampered_compatibility_receipt() {
    let kernel = published_kernel_fixture();
    let manifest = eclipse_instance_candidate_fixture();
    let mut result = compile_compatibility(&kernel, &manifest).unwrap();
    result
        .missing_capabilities
        .insert("kernel.forged".to_owned());
    assert_eq!(
        validate_compatibility_result(&kernel, &manifest, &result)
            .unwrap_err()
            .code,
        ContractFaultCode::DigestMismatch
    );
}
