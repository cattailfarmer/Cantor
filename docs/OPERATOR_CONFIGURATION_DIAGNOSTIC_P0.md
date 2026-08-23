# Cantor operator configuration diagnostic P0

`cantord --check-config <absolute-service-config>` is a deterministic,
no-listener preflight over the exact validators used immediately before normal
resident-service binding.

It validates, in order:

1. the strict service configuration and loopback/resource/path rules;
2. the existing authentication-token file in memory;
3. the activation descriptor, environment containment and digest, signed
   environment, and prepared runtime.

The command stops at the first refusal. It writes exactly one compact JSON
object and newline to stdout. A ready result contains a safe schema,
loopback/listener-limit, active-binding, prepared-runtime-metric, and package
count summary. A refused result contains exactly one public code, stage,
subject, and closed guidance string. Neither form records authority paths,
token content or hash, config/activation/environment content, or the raw
validator message.

Exit codes are:

- `0`: the exact existing pre-bind validators accepted the artifacts;
- `3`: one domain validator refused the artifacts;
- `2`: the invocation was invalid;
- `70`: stdout serialization failed.

Checked provider-free evidence is retained under
`experiments/operator_configuration_diagnostic/artifacts`. Produce and verify
it with:

```powershell
.\scripts\build_cantor_operator_configuration_diagnostic_evidence.ps1
.\scripts\verify_cantor_operator_configuration_diagnostic_evidence.ps1
.\scripts\test_cantor_operator_configuration_diagnostic_evidence.ps1
```

The producer requires the published `codex/self-hosted-corpus` HEAD and a
clean tracked tree, builds locked and offline, uses only public fixture test
material, and deletes its validated disposable fixture before publishing. The
independent verifier never starts `cantord`; it verifies retained bytes,
strict schemas, redaction, current binary identity, source ancestry, cleanup
claims, and capability denials.

A ready result is not a service-availability probe. This profile does not
generate configuration, provision production secrets, repair or migrate
artifacts, bind a listener, start a service, contact a provider, execute an
external effect, establish hostile-host isolation, or grant operator-product
or production authority.
