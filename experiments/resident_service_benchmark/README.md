# Resident service benchmark

This isolated benchmark measures the bounded `cantord` slice over an already
compiled, operator-activated environment.

It records:

- startup bind plus complete activation/preflight;
- repeated activation/restart preparation;
- in-process resident dispatch;
- authenticated loopback status round trips;
- authenticated loopback query round trips;
- exact response-equivalence mismatches.

The benchmark creates a temporary configuration with an ephemeral loopback
port. It reads the operator token but never records or prints it.

```powershell
cargo run --release --locked --offline `
  --manifest-path experiments\resident_service_benchmark\Cargo.toml -- `
  --config C:\Project\Cantor\.local\cantor-service\service.json `
  --request C:\Project\Cantor\.local\cantor-self-hosted\build\query-cantor.json `
  --iterations 30 `
  --output experiments\resident_service_benchmark\artifacts\run.json
```
