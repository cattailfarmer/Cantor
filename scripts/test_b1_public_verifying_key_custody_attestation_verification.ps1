param(
    [string]$EvidenceDirectory = "experiments/b1_public_verifying_key_custody_attestation_verification_p0/implementation_provider_free_evidence"
)

$ErrorActionPreference = "Stop"
$env:CARGO_INCREMENTAL = "0"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not [System.IO.Path]::IsPathRooted($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repositoryRoot $EvidenceDirectory
}

cargo test --locked --offline -p cantor_ecosystem --test b1_public_verifying_key_custody_attestation_verification -- --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$priorRustFlags = $env:RUSTFLAGS
try {
    $env:RUSTFLAGS = "-C overflow-checks=on"
    cargo test --release --locked --offline -p cantor_ecosystem --test b1_public_verifying_key_custody_attestation_verification -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
}

if (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
    $env:CANTOR_KCV_EVIDENCE_OUTPUT = $EvidenceDirectory
    try {
        cargo test --locked --offline -p cantor_ecosystem --test b1_public_verifying_key_custody_attestation_verification produce_retained_kcv_fixture_evidence -- --ignored --exact --nocapture --test-threads=1
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    finally {
        Remove-Item Env:CANTOR_KCV_EVIDENCE_OUTPUT -ErrorAction SilentlyContinue
    }
}

$expectedFiles = @(
    "predecessor_request.json",
    "predecessor_packet.json",
    "predecessor_verification.json",
    "a1_policy_envelope.json",
    "a1_verification_request.json",
    "a1_receipt.json",
    "custody_attestation.json",
    "verification_request.json",
    "receipt.json",
    "evidence_manifest.json"
)
$observedFiles = @(Get-ChildItem -LiteralPath $EvidenceDirectory -Force | Sort-Object Name)
if ($observedFiles.Count -ne $expectedFiles.Count) {
    throw "retained evidence membership count differs"
}
for ($index = 0; $index -lt $expectedFiles.Count; $index++) {
    if ($observedFiles[$index].Name -cne ($expectedFiles | Sort-Object)[$index] -or
        $observedFiles[$index].PSIsContainer) {
        throw "retained evidence membership differs"
    }
}

$receiptPath = Join-Path $EvidenceDirectory "receipt.json"
$receiptBytes = [System.IO.File]::ReadAllBytes($receiptPath)
if ($receiptBytes.Length -lt 2 -or $receiptBytes[-1] -ne 10 -or $receiptBytes -contains 13) {
    throw "retained receipt framing differs"
}
$retainedReceipt = [System.Text.Encoding]::UTF8.GetString($receiptBytes, 0, $receiptBytes.Length - 1)

$payloadPaths = @(
    (Join-Path $EvidenceDirectory "predecessor_request.json"),
    (Join-Path $EvidenceDirectory "predecessor_packet.json"),
    (Join-Path $EvidenceDirectory "predecessor_verification.json"),
    (Join-Path $EvidenceDirectory "a1_policy_envelope.json"),
    (Join-Path $EvidenceDirectory "a1_verification_request.json"),
    (Join-Path $EvidenceDirectory "a1_receipt.json"),
    (Join-Path $EvidenceDirectory "custody_attestation.json"),
    (Join-Path $EvidenceDirectory "verification_request.json")
)

$debugEvidenceFirst = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-custody-evidence-verify -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$debugEvidenceSecond = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-custody-evidence-verify -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$debugCore = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-custody-attestation-verify -- $payloadPaths
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

try {
    $env:RUSTFLAGS = "-C overflow-checks=on"
    $releaseEvidenceFirst = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-custody-evidence-verify -- $EvidenceDirectory
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $releaseEvidenceSecond = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-custody-evidence-verify -- $EvidenceDirectory
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $releaseCore = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-custody-attestation-verify -- $payloadPaths
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
}

foreach ($observed in @(
    $debugEvidenceFirst,
    $debugEvidenceSecond,
    $debugCore,
    $releaseEvidenceFirst,
    $releaseEvidenceSecond,
    $releaseCore
)) {
    if ($observed -cne $retainedReceipt) {
        throw "debug release core evidence retained or fresh-process replay differs"
    }
}

$receipt = $debugEvidenceFirst | ConvertFrom-Json
$manifest = Get-Content -LiteralPath (Join-Path $EvidenceDirectory "evidence_manifest.json") -Raw | ConvertFrom-Json
$positiveFields = @(
    "packet_replayed",
    "a1_correspondence_receipt_verified",
    "a2_candidate_bytes_matched",
    "descriptor_correspondence_verified",
    "policy_key_correspondence_verified",
    "challenge_structure_verified",
    "possession_signature_correspondence_verified"
)
$falseFields = @(
    "challenge_freshness_proved",
    "replay_prevention_proved",
    "custodian_identity_proved",
    "protected_storage_proved",
    "private_key_nonexportability_proved",
    "exclusive_control_proved",
    "current_possession_proved",
    "policy_governance_proved",
    "key_custody_proved",
    "revocation_truth_proved",
    "current_nonexpired",
    "live_authorization_admitted",
    "fresh_observation_proved",
    "private_execution_permit_present",
    "production_broker_projection_present",
    "physical_preparation_authorized",
    "ready_for_physical_execution",
    "execution_authorized"
)
if ($receipt.status -ne "custody_proof_signature_correspondence_verified_live_custody_and_all_execution_authority_unresolved" -or
    $receipt.authority -ne "key_custody_proof_correspondence_only" -or
    $receipt.production_authority_claimed -or
    $manifest.artifact_count -ne 9 -or
    $manifest.deterministic_replay_count -ne 2 -or
    $manifest.required_fresh_process_replay_count -ne 2 -or
    $manifest.effect_count -ne 0) {
    throw "receipt identity or evidence account differs"
}
foreach ($field in $positiveFields) {
    if (-not $receipt.$field) { throw "positive correspondence field differs: $field" }
}
foreach ($field in $falseFields) {
    if ($receipt.$field) { throw "false authority field promoted: $field" }
}
$effectTotal = 0
foreach ($property in $receipt.effect_account.PSObject.Properties) {
    if ($property.Value -is [bool]) {
        if ($property.Value) { throw "boolean effect promoted: $($property.Name)" }
    }
    else {
        $effectTotal += [int]$property.Value
    }
}
if ($effectTotal -ne 0) { throw "numeric effect account differs" }

Write-Output "b1_public_verifying_key_custody_attestation_verification_passed active_tests=22 ignored_producer=1 files=10 artifacts=$($manifest.artifact_count) artifact_bytes=$($manifest.total_artifact_bytes) replay=$($manifest.deterministic_replay_count) fresh_process_replay=$($manifest.required_fresh_process_replay_count) positive=7 false_authority=18 fixture_only=$($manifest.fixture_only) authority=$($receipt.authority) execution_authorized=$($receipt.execution_authorized) effects=$($manifest.effect_count)"
