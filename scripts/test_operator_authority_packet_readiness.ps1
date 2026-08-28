param(
    [string]$EvidenceDirectory = "experiments/self_work_update_broker_b1_cdrive_production_preparation_operator_authority_packet_readiness_p0/implementation_provider_free_evidence"
)

$ErrorActionPreference = "Stop"
$env:CARGO_INCREMENTAL = "0"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not [System.IO.Path]::IsPathRooted($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repositoryRoot $EvidenceDirectory
}

cargo test -p cantor_ecosystem --test operator_authority_packet_readiness --locked --offline
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cargo test -p cantor_ecosystem --test operator_authority_packet_readiness --release --locked --offline
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not (Test-Path -LiteralPath $EvidenceDirectory)) {
    $env:CANTOR_B1OAPR_EVIDENCE_DIR = $EvidenceDirectory
    cargo test -p cantor_ecosystem --test operator_authority_packet_readiness --locked --offline write_owned_b1oapr_evidence -- --ignored --exact
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$first = cargo run --quiet -p cantor_ecosystem --bin cantor-b1-operator-authority-packet-evidence-verify --locked --offline -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$second = cargo run --quiet -p cantor_ecosystem --bin cantor-b1-operator-authority-packet-evidence-verify --locked --offline -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($first -ne $second) {
    throw "independent evidence verification replay differs"
}

$first
