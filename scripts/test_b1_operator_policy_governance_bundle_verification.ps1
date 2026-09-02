param(
    [string]$EvidenceDirectory = "experiments/b1_operator_policy_governance_bundle_verification_p0/implementation_provider_free_evidence"
)

$ErrorActionPreference = "Stop"
$env:CARGO_INCREMENTAL = "0"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not [System.IO.Path]::IsPathRooted($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repositoryRoot $EvidenceDirectory
}

cargo test --locked --offline -p cantor_ecosystem --test b1_operator_policy_governance_bundle_verification -- --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$priorRustFlags = $env:RUSTFLAGS
try {
    $env:RUSTFLAGS = "-C overflow-checks=on"
    cargo test --release --locked --offline -p cantor_ecosystem --test b1_operator_policy_governance_bundle_verification -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
}

if (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
    $env:CANTOR_BPV_EVIDENCE_OUTPUT = $EvidenceDirectory
    try {
        cargo test --locked --offline -p cantor_ecosystem --test b1_operator_policy_governance_bundle_verification produce_retained_bpv_fixture_evidence -- --ignored --exact --nocapture --test-threads=1
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    finally {
        Remove-Item Env:CANTOR_BPV_EVIDENCE_OUTPUT -ErrorAction SilentlyContinue
    }
}

$receiptPath = Join-Path $EvidenceDirectory "receipt.json"
$receiptBytes = [System.IO.File]::ReadAllBytes($receiptPath)
if ($receiptBytes.Length -lt 2 -or $receiptBytes[-1] -ne 10 -or $receiptBytes -contains 13) {
    throw "retained receipt framing differs"
}
$retainedReceipt = [System.Text.Encoding]::UTF8.GetString($receiptBytes, 0, $receiptBytes.Length - 1)

$evidenceFirst = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-operator-policy-governance-evidence-verify -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$evidenceSecond = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-operator-policy-governance-evidence-verify -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$coreReceipt = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-operator-policy-governance-bundle-verify -- `
    (Join-Path $EvidenceDirectory "predecessor_request.json") `
    (Join-Path $EvidenceDirectory "predecessor_packet.json") `
    (Join-Path $EvidenceDirectory "predecessor_verification.json") `
    (Join-Path $EvidenceDirectory "policy_envelope.json") `
    (Join-Path $EvidenceDirectory "verification_request.json")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($evidenceFirst -cne $evidenceSecond -or
    $evidenceFirst -cne $coreReceipt -or
    $evidenceFirst -cne $retainedReceipt) {
    throw "core evidence or retained receipt replay differs"
}

$receipt = $evidenceFirst | ConvertFrom-Json
$manifest = Get-Content -LiteralPath (Join-Path $EvidenceDirectory "evidence_manifest.json") -Raw | ConvertFrom-Json
if ($receipt.status -ne "policy_bundle_signature_correspondence_verified_all_governance_and_execution_authority_unresolved" -or
    $receipt.authority -ne "policy_bundle_correspondence_only" -or
    -not $receipt.candidate_bytes_matched -or
    -not $receipt.descriptor_correspondence_verified -or
    -not $receipt.payload_structure_verified -or
    -not $receipt.scope_and_denials_verified -or
    -not $receipt.signature_correspondence_verified -or
    $receipt.production_authority_claimed -or
    $receipt.policy_governance_proved -or
    $receipt.execution_authorized -or
    $manifest.effect_count -ne 0) {
    throw "receipt correspondence or nonauthority account differs"
}

Write-Output "b1_operator_policy_governance_bundle_verification_passed active_tests=16 ignored_producer=1 artifacts=$($manifest.artifact_count) artifact_bytes=$($manifest.total_artifact_bytes) replay=$($manifest.deterministic_replay_count) fixture_only=$($manifest.fixture_only) authority=$($receipt.authority) execution_authorized=$($receipt.execution_authorized) effects=$($manifest.effect_count)"
