use cantor_compact_reflection_loop::{
    CheckpointCustodyRegistry, compile_dispatch_checkpoint_handle,
    generate_scripted_checkpoint_custody_registry, generate_scripted_dispatch_resume_corpus,
    new_checkpoint_custody_registry, pretty_checkpoint_custody_registry_bytes,
    register_checkpoint_custody, resolve_checkpoint_custody,
    resume_iteration_from_checkpoint_custody, resume_terminal_from_checkpoint_custody,
    validate_checkpoint_custody_registry, validate_scripted_checkpoint_custody_registry,
};
use serde_json::Value;

#[test]
fn immutable_registration_and_digest_lookup_preserve_exact_custody() {
    let corpus = generate_scripted_dispatch_resume_corpus().expect("corpus");
    let empty = new_checkpoint_custody_registry().expect("empty");
    assert_eq!(empty.entry_count, 0);
    assert!(empty.entries.is_empty());
    validate_checkpoint_custody_registry(&empty).expect("valid empty");

    let case = &corpus.cases[0];
    let handle = compile_dispatch_checkpoint_handle(
        &case.checkpoint,
        case.transport_position,
        case.terminal_reflection,
    )
    .expect("handle");
    let one = register_checkpoint_custody(&empty, &handle, &case.checkpoint).expect("register");
    assert_eq!(empty.entry_count, 0);
    assert_eq!(one.entry_count, 1);
    assert_ne!(one.root_digest, empty.root_digest);
    assert_eq!(
        resolve_checkpoint_custody(&one, &handle).expect("resolve"),
        case.checkpoint
    );
    assert!(register_checkpoint_custody(&one, &handle, &case.checkpoint).is_err());
}

#[test]
fn all_twelve_handles_resolve_and_resume_to_uninterrupted_traces() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    validate_scripted_checkpoint_custody_registry(&registry).expect("scripted registry");
    assert_eq!(registry.entry_count, 12);
    assert_eq!(registry.entries.len(), 12);
    assert!(registry.in_memory_only);
    assert!(!registry.persistence_claimed);
    assert!(!registry.provider_execution_claimed);
    assert!(!registry.external_effect_claimed);

    let corpus = generate_scripted_dispatch_resume_corpus().expect("corpus");
    let source = &corpus.source_run.source_envelopes.source_projection;
    for case in &corpus.cases {
        let handle = compile_dispatch_checkpoint_handle(
            &case.checkpoint,
            case.transport_position,
            case.terminal_reflection,
        )
        .expect("handle");
        let resolved = resolve_checkpoint_custody(&registry, &handle).expect("resolved");
        assert_eq!(resolved, case.checkpoint);
        let resumed = if case.terminal_reflection {
            resume_terminal_from_checkpoint_custody(
                &registry,
                &handle,
                &source.terminal_reflection_transport,
            )
            .expect("terminal resume")
        } else {
            resume_iteration_from_checkpoint_custody(
                &registry,
                &handle,
                &source.iteration_transports[case.transport_position as usize],
            )
            .expect("iteration resume")
        };
        assert_eq!(resumed, case.uninterrupted_trace);
    }
}

#[test]
fn registry_is_deterministic_strict_and_normalized() {
    let first = generate_scripted_checkpoint_custody_registry().expect("first");
    let second = generate_scripted_checkpoint_custody_registry().expect("second");
    assert_eq!(first, second);
    let bytes = pretty_checkpoint_custody_registry_bytes(&first).expect("pretty");
    assert_eq!(bytes.last(), Some(&b'\n'));
    let decoded: CheckpointCustodyRegistry = serde_json::from_slice(&bytes).expect("strict JSON");
    assert_eq!(decoded, first);

    let mut unknown = serde_json::to_value(&first).expect("value");
    unknown["database"] = Value::Null;
    assert!(serde_json::from_value::<CheckpointCustodyRegistry>(unknown).is_err());
}

#[test]
fn missing_mismatched_cross_kind_and_registry_mutations_fail_closed() {
    let registry = generate_scripted_checkpoint_custody_registry().expect("registry");
    let corpus = generate_scripted_dispatch_resume_corpus().expect("corpus");
    let first = &corpus.cases[0];
    let wrong_position =
        compile_dispatch_checkpoint_handle(&first.checkpoint, 99, false).expect("wrong position");
    assert!(resolve_checkpoint_custody(&registry, &wrong_position).is_err());

    let terminal = corpus
        .cases
        .iter()
        .find(|case| case.terminal_reflection)
        .expect("terminal case");
    let terminal_handle =
        compile_dispatch_checkpoint_handle(&terminal.checkpoint, terminal.transport_position, true)
            .expect("terminal handle");
    let source = &corpus.source_run.source_envelopes.source_projection;
    assert!(
        resume_iteration_from_checkpoint_custody(
            &registry,
            &terminal_handle,
            &source.iteration_transports[0]
        )
        .is_err()
    );

    let mut count = registry.clone();
    count.entry_count += 1;
    assert!(validate_checkpoint_custody_registry(&count).is_err());

    let mut root = registry.clone();
    root.root_digest.value.push('0');
    assert!(validate_checkpoint_custody_registry(&root).is_err());

    let mut key = registry.clone();
    let original_key = key.entries.keys().next().expect("key").clone();
    let entry = key.entries.remove(&original_key).expect("entry");
    let replacement = if original_key.starts_with('0') {
        '1'
    } else {
        '0'
    };
    key.entries
        .insert(format!("{replacement}{}", &original_key[1..]), entry);
    assert!(validate_checkpoint_custody_registry(&key).is_err());

    let mut entry_digest = registry.clone();
    entry_digest
        .entries
        .values_mut()
        .next()
        .expect("entry")
        .entry_digest
        .value
        .push('0');
    assert!(validate_checkpoint_custody_registry(&entry_digest).is_err());

    let mut claim = registry.clone();
    claim.persistence_claimed = true;
    assert!(validate_checkpoint_custody_registry(&claim).is_err());

    let mut corpus_mismatch = registry;
    corpus_mismatch.entries.pop_first();
    corpus_mismatch.entry_count -= 1;
    assert!(validate_scripted_checkpoint_custody_registry(&corpus_mismatch).is_err());
}
