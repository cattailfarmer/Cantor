param(
    [string]$EvidenceDirectory = "experiments/b1_public_verifying_key_revocation_snapshot_verification_p0/implementation_provider_free_evidence"
)

$ErrorActionPreference = "Stop"
$env:CARGO_INCREMENTAL = "0"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not [System.IO.Path]::IsPathRooted($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repositoryRoot $EvidenceDirectory
}

cargo test --locked --offline -p cantor_ecosystem --test b1_public_verifying_key_revocation_snapshot_verification -- --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$priorRustFlags = $env:RUSTFLAGS
try {
    $env:RUSTFLAGS = "-C overflow-checks=on"
    cargo test --release --locked --offline -p cantor_ecosystem --test b1_public_verifying_key_revocation_snapshot_verification -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
}

if (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
    $env:CANTOR_KRV_EVIDENCE_OUTPUT = $EvidenceDirectory
    try {
        cargo test --locked --offline -p cantor_ecosystem --test b1_public_verifying_key_revocation_snapshot_verification produce_retained_krv_fixture_evidence -- --ignored --exact --nocapture --test-threads=1
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    finally {
        Remove-Item Env:CANTOR_KRV_EVIDENCE_OUTPUT -ErrorAction SilentlyContinue
    }
}

$expectedFiles = @(
    "predecessor_request.json", "predecessor_packet.json", "predecessor_verification.json",
    "a1_policy_envelope.json", "a1_verification_request.json", "a1_receipt.json",
    "custody_attestation.json", "a2_verification_request.json", "a2_receipt.json",
    "revocation_snapshot.json", "verification_request.json", "receipt.json",
    "evidence_manifest.json"
)
$observedFiles = @(Get-ChildItem -LiteralPath $EvidenceDirectory -Force | Sort-Object Name)
if ($observedFiles.Count -ne $expectedFiles.Count) { throw "retained evidence membership count differs" }
for ($index = 0; $index -lt $expectedFiles.Count; $index++) {
    if ($observedFiles[$index].Name -cne ($expectedFiles | Sort-Object)[$index] -or
        $observedFiles[$index].PSIsContainer -or $observedFiles[$index].LinkType) {
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
    "predecessor_request.json", "predecessor_packet.json", "predecessor_verification.json",
    "a1_policy_envelope.json", "a1_verification_request.json", "a1_receipt.json",
    "custody_attestation.json", "a2_verification_request.json", "a2_receipt.json",
    "revocation_snapshot.json", "verification_request.json"
) | ForEach-Object { Join-Path $EvidenceDirectory $_ }

$debugEvidenceFirst = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-revocation-evidence-verify -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$debugEvidenceSecond = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-revocation-evidence-verify -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$debugCore = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-revocation-snapshot-verify -- $payloadPaths
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

try {
    $env:RUSTFLAGS = "-C overflow-checks=on"
    $releaseEvidenceFirst = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-revocation-evidence-verify -- $EvidenceDirectory
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $releaseEvidenceSecond = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-revocation-evidence-verify -- $EvidenceDirectory
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $releaseCore = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-public-verifying-key-revocation-snapshot-verify -- $payloadPaths
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
}

foreach ($observed in @($debugEvidenceFirst, $debugEvidenceSecond, $debugCore,
        $releaseEvidenceFirst, $releaseEvidenceSecond, $releaseCore)) {
    if ($observed -cne $retainedReceipt) {
        throw "debug release core evidence retained or fresh-process replay differs"
    }
}

$receipt = $debugEvidenceFirst | ConvertFrom-Json
$manifest = Get-Content -LiteralPath (Join-Path $EvidenceDirectory "evidence_manifest.json") -Raw | ConvertFrom-Json
$positiveFields = @(
    "packet_replayed", "a1_correspondence_receipt_verified",
    "a2_correspondence_receipt_verified", "a3_candidate_bytes_matched",
    "descriptor_correspondence_verified", "target_policy_key_correspondence_verified",
    "snapshot_structure_verified", "interval_structure_verified",
    "responder_signature_correspondence_verified"
)
$falseFields = @(
    "challenge_freshness_proved", "replay_prevention_proved", "custodian_identity_proved",
    "protected_storage_proved", "private_key_nonexportability_proved", "exclusive_control_proved",
    "current_possession_proved", "responder_identity_proved", "responder_authority_proved",
    "source_completeness_proved", "monotonic_history_proved", "snapshot_freshness_proved",
    "current_time_compared", "policy_governance_proved", "key_custody_proved",
    "revocation_truth_proved", "current_nonexpired", "live_authorization_admitted",
    "fresh_observation_proved", "private_execution_permit_present",
    "production_broker_projection_present", "physical_preparation_authorized",
    "ready_for_physical_execution", "execution_authorized"
)
$statusFields = @("status_assertion_not_revoked", "status_assertion_revoked", "status_assertion_unknown")
if ($receipt.status -ne "revocation_snapshot_signature_correspondence_verified_current_revocation_truth_and_all_execution_authority_unresolved" -or
    $receipt.authority -ne "revocation_snapshot_signature_correspondence_only" -or
    $receipt.production_authority_claimed -or $manifest.artifact_count -ne 12 -or
    $manifest.deterministic_replay_count -ne 2 -or
    $manifest.required_fresh_process_replay_count -ne 2 -or $manifest.effect_count -ne 0) {
    throw "receipt identity or evidence account differs"
}
foreach ($field in $positiveFields) {
    if (-not $receipt.$field) { throw "positive correspondence field differs: $field" }
}
foreach ($field in $falseFields) {
    if ($receipt.$field) { throw "false authority field promoted: $field" }
}
$statusTotal = 0
foreach ($field in $statusFields) { if ($receipt.$field) { $statusTotal++ } }
if ($statusTotal -ne 1) { throw "status projection cardinality differs" }
$effectTotal = 0
foreach ($property in $receipt.effect_account.PSObject.Properties) {
    if ($property.Value -is [bool]) {
        if ($property.Value) { throw "boolean effect promoted: $($property.Name)" }
    }
    else { $effectTotal += [int]$property.Value }
}
if ($effectTotal -ne 0) { throw "numeric effect account differs" }

Write-Output "b1_public_verifying_key_revocation_snapshot_verification_passed active_tests=14 ignored_producer=1 files=13 artifacts=$($manifest.artifact_count) artifact_bytes=$($manifest.total_artifact_bytes) statuses=3 replay=$($manifest.deterministic_replay_count) fresh_process_replay=$($manifest.required_fresh_process_replay_count) positive=9 false_authority=24 fixture_only=$($manifest.fixture_only) authority=$($receipt.authority) execution_authorized=$($receipt.execution_authorized) effects=$($manifest.effect_count)"
