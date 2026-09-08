param(
    [string]$EvidenceDirectory = "experiments/b1_production_broker_projection_correspondence_p0/implementation_provider_free_evidence"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$env:CARGO_INCREMENTAL = "0"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not [System.IO.Path]::IsPathRooted($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path $repositoryRoot $EvidenceDirectory
}

cargo test --locked --offline -p cantor_ecosystem --all-features --lib b1_production_broker_projection_correspondence -- --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test --locked --offline -p cantor_ecosystem --all-features --test b1_production_broker_projection_correspondence -- --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$priorRustFlags = $env:RUSTFLAGS
try {
    $env:RUSTFLAGS = "-C overflow-checks=on"
    cargo test --release --locked --offline -p cantor_ecosystem --all-features --lib b1_production_broker_projection_correspondence -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    cargo test --release --locked --offline -p cantor_ecosystem --all-features --test b1_production_broker_projection_correspondence -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
}

$expectedFiles = @(
    "predecessor_request.json", "predecessor_packet.json", "predecessor_verification.json",
    "a1_policy_envelope.json", "a1_verification_request.json", "a1_receipt.json",
    "custody_attestation.json", "a2_verification_request.json", "a2_receipt.json",
    "revocation_snapshot.json", "a3_verification_request.json", "a3_receipt.json",
    "time_witness_receipt.json", "a4_verification_request.json", "a4_receipt.json",
    "operator_decision_policy.json", "operator_decision_request.json", "operator_decision_envelope.json",
    "a5_verification_request.json", "a5_receipt.json", "preparation_plan_request.json",
    "preparation_plan.json", "observation_bundle.json", "a6_verification_request.json",
    "a6_receipt.json", "a6_evidence_manifest.json", "permit_reference_envelope.json",
    "a7_verification_request.json", "a7_receipt.json", "a7_evidence_manifest.json",
    "broker_projection_declaration.json", "verification_request.json", "receipt.json",
    "evidence_manifest.json"
)
$observedFiles = @(Get-ChildItem -LiteralPath $EvidenceDirectory -Force | Sort-Object Name)
$sortedExpected = @($expectedFiles | Sort-Object)
if ($observedFiles.Count -ne 34) { throw "A8 retained evidence count differs" }
for ($index = 0; $index -lt $observedFiles.Count; $index++) {
    if ($observedFiles[$index].Name -cne $sortedExpected[$index] -or
        $observedFiles[$index].PSIsContainer -or $observedFiles[$index].LinkType) {
        throw "A8 retained evidence membership differs"
    }
}

$payloadNames = @($expectedFiles[0..24]) + @(
    "permit_reference_envelope.json", "a7_verification_request.json", "a7_receipt.json",
    "broker_projection_declaration.json", "verification_request.json"
)
$payloadPaths = @($payloadNames | ForEach-Object { Join-Path $EvidenceDirectory $_ })
$receiptBytes = [IO.File]::ReadAllBytes((Join-Path $EvidenceDirectory "receipt.json"))
if ($receiptBytes.Length -lt 2 -or $receiptBytes[-1] -ne 10 -or $receiptBytes -contains 13) {
    throw "A8 retained receipt framing differs"
}
$retainedReceipt = [Text.Encoding]::UTF8.GetString($receiptBytes, 0, $receiptBytes.Length - 1)

$debugEvidenceFirst = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-production-broker-projection-evidence-verify -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$debugEvidenceSecond = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-production-broker-projection-evidence-verify -- $EvidenceDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$debugCore = cargo run --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-production-broker-projection-verify -- $payloadPaths
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
try {
    $env:RUSTFLAGS = "-C overflow-checks=on"
    $releaseEvidenceFirst = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-production-broker-projection-evidence-verify -- $EvidenceDirectory
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $releaseEvidenceSecond = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-production-broker-projection-evidence-verify -- $EvidenceDirectory
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $releaseCore = cargo run --release --quiet --locked --offline -p cantor_ecosystem --bin cantor-b1-production-broker-projection-verify -- $payloadPaths
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    $env:RUSTFLAGS = $priorRustFlags
}
foreach ($observed in @($debugEvidenceFirst, $debugEvidenceSecond, $debugCore,
        $releaseEvidenceFirst, $releaseEvidenceSecond, $releaseCore)) {
    if ($observed -cne $retainedReceipt) { throw "A8 fresh-process replay differs" }
}

$receipt = $debugEvidenceFirst | ConvertFrom-Json
$manifest = Get-Content -LiteralPath (Join-Path $EvidenceDirectory "evidence_manifest.json") -Raw | ConvertFrom-Json
$falseFields = @(
    "production_authority_claimed", "private_execution_permit_present", "permit_material_authenticated",
    "permit_dependency_satisfied", "broker_endpoint_resolved", "broker_reachable",
    "broker_identity_proved", "broker_authority_proved", "broker_session_authenticated",
    "broker_activation_authorized", "production_broker_projection_present", "live_authorization_admitted",
    "physical_preparation_authorized", "ready_for_physical_execution", "execution_authorized"
)
if ($receipt.status -cne "supplied_production_broker_projection_correspondence_matched_execution_unresolved" -or
    $receipt.authority -cne "supplied_production_broker_projection_correspondence_only" -or
    $manifest.artifact_count -ne 33 -or $manifest.deterministic_replay_count -ne 2 -or
    $manifest.required_fresh_process_replay_count -ne 2 -or $manifest.effect_count -ne 0 -or
    -not $receipt.production_broker_projection_correspondence_proved) {
    throw "A8 receipt identity or evidence account differs"
}
foreach ($field in $falseFields) {
    if ($receipt.$field -isnot [bool] -or $receipt.$field -ne $false) {
        throw "A8 authority field differs: $field"
    }
}
$effectProperties = @($receipt.effect_account.PSObject.Properties)
if ($effectProperties.Count -ne 22) { throw "A8 effect field count differs" }
foreach ($property in $effectProperties) {
    if ($property.Name -ceq "physical_contact") {
        if ($property.Value -isnot [bool] -or $property.Value) { throw "A8 physical contact differs" }
    }
    elseif ($property.Value -ne 0) { throw "A8 effect counter differs: $($property.Name)" }
}
Write-Output "b1_production_broker_projection_correspondence_passed files=34 artifacts=33 explicit=30 comparisons=26 replay=2 fresh_process_replay=2 false_authority=15 effects=0 execution_authorized=false"
