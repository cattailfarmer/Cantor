const LIB: &str = include_str!("../src/lib.rs");

#[test]
fn contract_core_has_no_process_network_provider_or_ambient_input() {
    for forbidden in [
        "std::process",
        "std::net",
        "std::env",
        "Command::",
        "reqwest",
        "rmcp",
        "tokio",
        "unsafe ",
        "thread::spawn",
        "loop {",
        "while ",
    ] {
        assert!(
            !LIB.contains(forbidden),
            "contract core gained forbidden surface: {forbidden}"
        );
    }
}

#[test]
fn role_and_non_authority_guards_remain_explicit() {
    for required in [
        "KernelCandidate",
        "InstanceAdapter",
        "Package",
        "Evidence",
        "kernel_candidate_requires_separate_promotion",
        "instance cannot request authority",
        "evidence cannot provide capabilities",
        "non-kernel component cannot occupy a kernel slot",
        "Structural compatibility only.",
    ] {
        assert!(
            LIB.contains(required),
            "contract guard disappeared: {required}"
        );
    }
}
