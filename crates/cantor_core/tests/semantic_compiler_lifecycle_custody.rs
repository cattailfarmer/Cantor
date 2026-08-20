use cantor_core::{
    NATIVE_LIFECYCLE_CUSTODY_MAX_ENTRIES, NativeLifecycleValidationOutcome, SemanticId,
    compile_native_lifecycle_custody_handle, new_native_lifecycle_custody_registry,
    register_native_lifecycle_custody, resolve_native_lifecycle_custody,
    validate_native_lifecycle_custody_registry, validate_native_lifecycle_from_custody,
    validate_native_lifecycle_request,
};
use serde_json::json;

#[path = "semantic_compiler_native_artifact_backend.rs"]
mod native_lifecycle_fixture;

fn request(name: &str) -> cantor_core::NativeLifecycleValidationRequest {
    let mut request = native_lifecycle_fixture::exported_artifact_validation_request();
    request.request_id = SemanticId::new(format!("request:custody:{name}")).expect("request id");
    request
}

#[test]
fn compact_handle_resolves_exact_request_and_preserves_direct_validation() {
    let request = request("valid");
    let direct = validate_native_lifecycle_request(&request);
    assert_eq!(
        direct.outcome,
        NativeLifecycleValidationOutcome::ArtifactValid
    );
    let empty = new_native_lifecycle_custody_registry().expect("empty registry");
    let (registry, handle) =
        register_native_lifecycle_custody(&empty, &request).expect("register request");
    assert_eq!(
        resolve_native_lifecycle_custody(&registry, &handle),
        Ok(request.clone())
    );
    assert_eq!(
        validate_native_lifecycle_from_custody(&registry, &handle),
        Ok(direct)
    );
    assert!(
        serde_json::to_vec(&handle).expect("handle bytes").len() * 4
            < serde_json::to_vec(&request).expect("request bytes").len(),
        "fixture handle must be at least four times smaller"
    );
    assert_eq!(
        register_native_lifecycle_custody(&empty, &request),
        register_native_lifecycle_custody(&empty, &request)
    );
}

#[test]
fn refused_request_is_retained_without_reclassifying_its_outcome() {
    let mut request = request("refused");
    request.protocol.push_str(".unsupported");
    let direct = validate_native_lifecycle_request(&request);
    assert_eq!(
        direct.outcome,
        NativeLifecycleValidationOutcome::LifecycleRefused
    );
    let (registry, handle) = register_native_lifecycle_custody(
        &new_native_lifecycle_custody_registry().expect("empty registry"),
        &request,
    )
    .expect("refused request may be retained");
    assert_eq!(
        validate_native_lifecycle_from_custody(&registry, &handle),
        Ok(direct)
    );
}

#[test]
fn duplicate_missing_cross_registry_and_handle_substitution_refuse() {
    let retained_request = request("one");
    let empty = new_native_lifecycle_custody_registry().expect("empty registry");
    let (registry, handle) =
        register_native_lifecycle_custody(&empty, &retained_request).expect("register request");
    assert!(register_native_lifecycle_custody(&registry, &retained_request).is_err());
    assert!(resolve_native_lifecycle_custody(&empty, &handle).is_err());

    let other = request("other");
    let other_handle = compile_native_lifecycle_custody_handle(&other).expect("other handle");
    assert!(resolve_native_lifecycle_custody(&registry, &other_handle).is_err());

    let mut substituted = handle;
    substituted.request_id = SemanticId::new("request:custody:substituted").expect("request id");
    assert!(resolve_native_lifecycle_custody(&registry, &substituted).is_err());
}

#[test]
fn registry_entry_account_and_root_substitutions_fail_closed() {
    let request = request("tamper");
    let (registry, handle) = register_native_lifecycle_custody(
        &new_native_lifecycle_custody_registry().expect("empty registry"),
        &request,
    )
    .expect("register request");

    let mut count = registry.clone();
    count.entry_count += 1;
    assert!(validate_native_lifecycle_custody_registry(&count).is_err());

    let mut byte_account = registry.clone();
    byte_account.retained_request_bytes += 1;
    assert!(validate_native_lifecycle_custody_registry(&byte_account).is_err());

    let mut root = registry.clone();
    root.root_digest.value.replace_range(0..1, "0");
    if root.root_digest == registry.root_digest {
        root.root_digest.value.replace_range(0..1, "1");
    }
    assert!(validate_native_lifecycle_custody_registry(&root).is_err());

    let mut entry = registry.clone();
    entry
        .entries
        .get_mut(&handle.request_digest.value)
        .expect("entry")
        .request
        .protocol
        .push('x');
    assert!(validate_native_lifecycle_custody_registry(&entry).is_err());

    let mut claims = registry;
    claims.persistence_claimed = true;
    assert!(validate_native_lifecycle_custody_registry(&claims).is_err());
}

#[test]
fn entry_bound_order_independence_oversize_and_unknown_fields_are_closed() {
    let empty = new_native_lifecycle_custody_registry().expect("empty registry");
    let first = request("a");
    let second = request("b");
    let (ab, _) = register_native_lifecycle_custody(&empty, &first).expect("a");
    let (ab, _) = register_native_lifecycle_custody(&ab, &second).expect("b");
    let (ba, _) = register_native_lifecycle_custody(&empty, &second).expect("b");
    let (ba, _) = register_native_lifecycle_custody(&ba, &first).expect("a");
    assert_eq!(ab, ba);

    let mut full = empty;
    for index in 0..NATIVE_LIFECYCLE_CUSTODY_MAX_ENTRIES {
        let (next, _) = register_native_lifecycle_custody(&full, &request(&index.to_string()))
            .expect("bounded entry");
        full = next;
    }
    assert!(register_native_lifecycle_custody(&full, &request("overflow")).is_err());

    let mut oversized = request("oversized");
    oversized.protocol = "x".repeat(cantor_core::NATIVE_LIFECYCLE_MAX_INPUT_BYTES);
    assert!(compile_native_lifecycle_custody_handle(&oversized).is_err());

    let mut value = serde_json::to_value(&ab).expect("registry JSON");
    value
        .as_object_mut()
        .expect("registry object")
        .insert("authority".to_owned(), json!(true));
    assert!(serde_json::from_value::<cantor_core::NativeLifecycleCustodyRegistry>(value).is_err());
}
