# Cantor operator bootstrap transaction P0

`initialize_cantor_service_transaction.ps1` creates one new local resident
service artifact set without changing the legacy initializer. It is
initial-create-only: the final runtime directory must not exist, and there is
no replace, merge, repair, migration, or overwrite mode.

```powershell
.\scripts\initialize_cantor_service_transaction.ps1 `
  -EnvironmentPath C:\Project\Cantor\.local\cantor-self-hosted\environment.json `
  -RuntimeDirectory C:\Project\Cantor\.local\cantor-service `
  -CantordPath C:\Project\Cantor\target\release\cantord.exe `
  -AllowedEnvironmentRoot C:\Project\Cantor\.local `
  -ListenAddress 127.0.0.1:39841
```

The transaction validates physical inputs and an absent final root, creates a
random 256-bit hexadecimal bearer capability only inside one random sibling
staging directory, and writes strict activation and configuration artifacts.
The exact supplied `cantord --check-config` must accept the staged candidate.
The candidate-only file is removed, the remaining inventory is closed to
`cantord.token`, `activation.json`, and `service.json`, and the entire staging
directory is renamed to the final absent runtime path in one operation. The
exact final config must then pass the same no-listener diagnostic.

Success emits one compact `cantor-operator-bootstrap-transaction/0.1` JSON
receipt. It includes the service config, activation, environment, and listen
identities needed by the operator, but no token path, token bytes, token hash,
raw diagnostic, environment content, or signing material.

Before publication, a refusal removes only the transaction’s exact random
staging leaf. After publication, automatic rollback is allowed only if the
final directory still contains exactly the three files and byte identities
published by that transaction. Any external change preserves the residual for
operator review rather than recursively deleting changed data.

This is a local bootstrap mechanic, not production secret lifecycle. It does
not define file-permission policy, rotation, revocation, backup, replacement,
repair, migration, installation, supported delivery, service startup, provider
execution, or operator-product acceptance.

Focused and checked evidence commands are:

```powershell
.\scripts\test_cantor_operator_bootstrap_transaction.ps1
.\scripts\build_cantor_operator_bootstrap_transaction_evidence.ps1
.\scripts\verify_cantor_operator_bootstrap_transaction_evidence.ps1
.\scripts\test_cantor_operator_bootstrap_transaction_evidence.ps1
```
