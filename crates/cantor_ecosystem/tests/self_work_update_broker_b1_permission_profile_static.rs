#[test]
fn verifier_and_cli_have_no_producer_or_effect_surface() {
    let verifier = include_str!("../src/self_work_update_broker_b1_permission_profile.rs");
    let cli = include_str!("../src/bin/cantor-self-work-update-broker-b1-permission-profile.rs");
    for forbidden in [
        "std::process",
        "Command::new",
        "TcpStream",
        "UdpSocket",
        "reqwest",
        "fs::write",
        "OpenOptions",
        "create_dir",
        "remove_file",
        "remove_dir",
        "rename(",
        "set_var",
        "git2",
    ] {
        assert!(
            !verifier.contains(forbidden),
            "verifier unexpectedly contains effect token {forbidden}"
        );
    }
    for forbidden in ["Command::new", "TcpStream", "fs::write", "OpenOptions"] {
        assert!(
            !cli.contains(forbidden),
            "CLI unexpectedly contains effect token {forbidden}"
        );
    }
    assert!(verifier.contains("fs::read"));
    assert!(cli.contains("println!"));
}
