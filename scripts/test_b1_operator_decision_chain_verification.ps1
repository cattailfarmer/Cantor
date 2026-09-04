param(
    [string]$EvidenceDirectory = "experiments/b1_operator_decision_chain_verification_p0/implementation_provider_free_evidence"
)

$ErrorActionPreference = "Stop"
$env:CARGO_INCREMENTAL = "0"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not [System.IO.Path]::IsPathRooted($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repositoryRoot $EvidenceDirectory
}

cargo test --locked --offline -p cantor_ecosystem --test b1_operator_decision_chain_verification -- --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$priorRustFlags = $env:RUSTFLAGS
try {
    $env:RUSTFLAGS = "-C overflow-checks=on"
    cargo test --release --locked --offline -p cantor_ecosystem --test b1_operator_decision_chain_verification -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
}

if (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
    $env:CANTOR_ODCV_EVIDENCE_OUTPUT_DIR = $EvidenceDirectory
    try {
        cargo test --locked --offline -p cantor_ecosystem --test b1_operator_decision_chain_verification produce_provider_free_evidence -- --ignored --exact --nocapture --test-threads=1
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    finally {
        Remove-Item Env:CANTOR_ODCV_EVIDENCE_OUTPUT_DIR -ErrorAction SilentlyContinue
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
    "a2_verification_request.json",
    "a2_receipt.json",
    "revocation_snapshot.json",
    "a3_verification_request.json",
    "a3_receipt.json",
    "time_witness_receipt.json",
    "a4_verification_request.json",
    "a4_receipt.json",
    "operator_decision_policy.json",
    "operator_decision_request.json",
    "operator_decision_envelope.json",
    "verification_request.json",
    "receipt.json",
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
    "predecessor_request.json",
    "predecessor_packet.json",
    "predecessor_verification.json",
    "a1_policy_envelope.json",
    "a1_verification_request.json",
    "a1_receipt.json",
    "custody_attestation.json",
    "a2_verification_request.json",
    "a2_receipt.json",
    "revocation_snapshot.json",
    "a3_verification_request.json",
    "a3_receipt.json",
    "time_witness_receipt.json",
    "a4_verification_request.json",
    "a4_receipt.json",
    "operator_decision_policy.json",
    "operator_decision_request.json",
    "operator_decision_envelope.json",
    "verification_request.json"
) | ForEach-Object { Join-Path $EvidenceDirectory $_ }

$debugEvidenceFirst = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-operator-decision-chain-evidence-verify -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$debugEvidenceSecond = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-operator-decision-chain-evidence-verify -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$debugCore = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-operator-decision-chain-verify -- $payloadPaths
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

try {
    $env:RUSTFLAGS = "-C overflow-checks=on"
    $releaseEvidenceFirst = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-operator-decision-chain-evidence-verify -- $EvidenceDirectory
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $releaseEvidenceSecond = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-operator-decision-chain-evidence-verify -- $EvidenceDirectory
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $releaseCore = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-operator-decision-chain-verify -- $payloadPaths
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
$positiveFields = @("packet_replayed", "a1_correspondence_receipt_verified", "a2_correspondence_receipt_verified", "a3_correspondence_receipt_verified", "a4_correspondence_receipt_verified", "a5_candidate_bytes_matched", "descriptor_correspondence_verified", "subject_lineage_correspondence_verified", "decision_policy_key_correspondence_verified", "decision_policy_artifact_bindings_verified", "decision_request_correspondence_verified", "decision_structure_verified", "decision_signature_correspondence_verified", "decision_expectations_verified", "supplied_decision_interval_comparison_verified")
$falseFields = @("production_authority_claimed", "challenge_freshness_proved", "replay_prevention_proved", "custodian_identity_proved", "protected_storage_proved", "private_key_nonexportability_proved", "exclusive_control_proved", "current_possession_proved", "responder_identity_proved", "responder_authority_proved", "source_completeness_proved", "monotonic_history_proved", "snapshot_freshness_proved", "current_time_compared", "policy_governance_proved", "key_custody_proved", "revocation_truth_proved", "current_nonexpired", "live_authorization_admitted", "fresh_observation_proved", "private_execution_permit_present", "production_broker_projection_present", "physical_preparation_authorized", "ready_for_physical_execution", "execution_authorized", "witness_identity_proved", "witness_authority_proved", "witness_freshness_proved", "trusted_current_time_proved", "decision_signer_identity_proved", "decision_authority_proved", "decision_freshness_proved", "decision_signature_binds_a4_lineage")
if ($receipt.status -cne "operator_decision_chain_and_supplied_interval_correspondence_verified_live_authorization_and_execution_unresolved" -or
    $receipt.authority -cne "supplied_operator_decision_chain_correspondence_only" -or
    $manifest.artifact_count -ne 20 -or $manifest.deterministic_replay_count -ne 2 -or
    $manifest.required_fresh_process_replay_count -ne 2 -or $manifest.effect_count -ne 0) {
    throw "receipt identity or evidence account differs"
}
foreach ($field in $positiveFields) {
    if ($receipt.$field -isnot [bool] -or $receipt.$field -ne $true) { throw "positive field differs: $field" }
}
foreach ($field in $falseFields) {
    if ($receipt.$field -isnot [bool] -or $receipt.$field -ne $false) { throw "authority field differs: $field" }
}
$effectProperties = @($receipt.effect_account.PSObject.Properties)
if ($effectProperties.Count -ne 22) { throw "effect field cardinality differs" }
foreach ($property in $effectProperties) {
    if ($property.Name -ceq "physical_contact") {
        if ($property.Value -isnot [bool] -or $property.Value -ne $false) { throw "physical contact differs" }
    }
    elseif (($property.Value -isnot [long] -and $property.Value -isnot [int]) -or $property.Value -ne 0) {
        throw "effect counter differs: $($property.Name)"
    }
}
if ($receipt.comparison_outcome -cne "within_decision_interval" -or
    $receipt.observed_unix_ms -lt $receipt.issued_at_unix_millis -or
    $receipt.observed_unix_ms -ge $receipt.expires_at_unix_millis -or
    $receipt.maximum_attempts -ne 1 -or $receipt.automatic_retry_count -ne 0 -or
    $receipt.automatic_cleanup_count -ne 0) { throw "comparison or attempt account differs" }
Write-Output "b1_operator_decision_chain_verification_passed files=21 artifacts=$($manifest.artifact_count) artifact_bytes=$($manifest.total_artifact_bytes) outcomes=3 replay=2 fresh_process_replay=2 positive=15 false_authority=33 effect_fields=22 fixture_only=$($manifest.fixture_only) authority=$($receipt.authority) execution_authorized=$($receipt.execution_authorized) effects=$($manifest.effect_count)"
