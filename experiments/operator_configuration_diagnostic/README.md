# Cantor operator configuration diagnostic P0

This experiment retains one checked `ready` report, one sanitized `refused`
report, and one provider-free evidence receipt for the exact
`cantord --check-config` contract.

The fixture is generated from public test signing material in
`crates/cantor_cli/examples/generate_demo.rs`, uses a fixed public fixture-only
authentication value, and is deleted before evidence publication. The
diagnostic never binds a listener or enters the service loop. Retained reports
contain no fixture paths, authentication material, artifact content, or raw
validator messages.

Run the producer, independent verifier, and adversarial gates from the
repository root:

```powershell
.\scripts\build_cantor_operator_configuration_diagnostic_evidence.ps1
.\scripts\verify_cantor_operator_configuration_diagnostic_evidence.ps1
.\scripts\test_cantor_operator_configuration_diagnostic_evidence.ps1
```

This evidence does not create production authority or prove service
availability, provider execution, operator acceptance, or production
readiness.
