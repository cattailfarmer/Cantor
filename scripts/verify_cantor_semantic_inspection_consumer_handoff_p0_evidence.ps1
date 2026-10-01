param([switch]$SkipCompletion)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$selectedRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_consumer_handoff_p0_formation.ps1")
$experiment = "experiments/cantor_semantic_inspection_consumer_handoff_p0"

function Assert-Artifact($Artifact) {
    $relative = [string]$Artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') { throw "nonportable consumer artifact" }
    $path = Join-Path $selectedRoot $relative
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -ne [int64]$Artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$Artifact.sha256) { throw "consumer artifact differs: $relative" }
}

$manifest = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/implementation_evidence_manifest.json") -Raw | ConvertFrom-Json
if ($manifest.profile -cne "cantor-semantic-inspection-consumer-handoff-p0-evidence/0.1" -or $manifest.evidence_manifest_uuid -cne "650a77db-6bd3-4fb0-ad7e-4d344d9cf179" -or $manifest.specification_uuid -cne "6abf0365-921b-4d9c-a794-a65ae187ffae" -or $manifest.formation_bookend -cne "ceee406e6ff4f5f4a34c6b56f8116a3fc4778b86") { throw "consumer manifest identity differs" }
$expectedArtifacts = @("$experiment/semantic_inspection_consumer_component.json", "$experiment/formation_evidence_manifest.json", "$experiment/focused_debug_summary.json", "$experiment/focused_release_summary.json", "$experiment/workspace_debug_summary.json", "$experiment/workspace_release_summary.json", "docs/SEMANTIC_INSPECTION_CONSUMER_HANDOFF_P0.md")
if (@($manifest.artifacts).Count -ne $expectedArtifacts.Count) { throw "consumer artifact cardinality differs" }
for ($index = 0; $index -lt $expectedArtifacts.Count; $index++) {
    $artifact = @($manifest.artifacts)[$index]
    if ($artifact.path -cne $expectedArtifacts[$index]) { throw "consumer artifact membership differs" }
    Assert-Artifact $artifact
}

$component = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/semantic_inspection_consumer_component.json") -Raw | ConvertFrom-Json
$expectedFiles = @("crates/cantor_sop_inspect_consumer/Cargo.toml", "crates/cantor_sop_inspect_consumer/src/lib.rs", "crates/cantor_sop_inspect_consumer/examples/export_consumer_fixtures.rs", "crates/cantor_sop_inspect_consumer/tests/support/mod.rs", "crates/cantor_sop_inspect_consumer/tests/consumer_adversarial.rs", "crates/cantor_sop_inspect_consumer/tests/consumer_static.rs", "crates/cantor_sop_inspect_consumer/tests/fixture_replay.rs", "fixtures/semantic_inspection_consumer_handoff_p0/fixtures.json")
if ($component.profile -cne "cantor-semantic-inspection-consumer-component/0.1" -or [int]$component.file_count -ne 8 -or @($component.files).Count -ne 8 -or $component.specification_uuid -cne $manifest.specification_uuid -or $component.formation_bookend -cne $manifest.formation_bookend) { throw "consumer component identity differs" }
for ($index = 0; $index -lt $expectedFiles.Count; $index++) {
    $artifact = @($component.files)[$index]
    if ($artifact.path -cne $expectedFiles[$index]) { throw "consumer component membership differs" }
    Assert-Artifact $artifact
}
foreach ($field in @("consumer_library_io_effects", "production_process_launches", "installed_application_acceptances")) { if ([int]$component.$field -ne 0) { throw "unexpected component effect: $field" } }

$formation = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/formation_evidence_manifest.json") -Raw | ConvertFrom-Json
if ($formation.profile -cne "cantor-semantic-inspection-consumer-formation-evidence/0.1" -or $formation.specification_uuid -cne $manifest.specification_uuid -or $formation.satisfaction_signature_uuid -cne "3a2306de-7074-4e99-b72d-37f2e911302d" -or $formation.immediate_bookend_commit -cne $manifest.formation_bookend -or [int]$formation.binding_count -ne 12 -or [int]$formation.requirement_count -ne 24 -or [int]$formation.acceptance_count -ne 6 -or -not $formation.powershell_7_replay_passed -or -not $formation.windows_powershell_5_1_replay_passed -or [int]$formation.product_effects -ne 0 -or [int]$formation.installed_application_acceptances -ne 0) { throw "consumer formation evidence differs" }

foreach ($cargoProfile in @("debug", "release")) {
    $focused = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/focused_${cargoProfile}_summary.json") -Raw | ConvertFrom-Json
    $workspace = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/workspace_${cargoProfile}_summary.json") -Raw | ConvertFrom-Json
    foreach ($summary in @($focused, $workspace)) {
        if ($summary.cargo_profile -cne $cargoProfile -or -not $summary.locked -or -not $summary.offline -or -not $summary.all_features -or -not $summary.all_targets -or [int]$summary.serialized_test_threads -ne 1 -or [bool]$summary.overflow_checks -ne ($cargoProfile -ceq "release") -or [int]$summary.tests_failed -ne 0) { throw "consumer gate coordinates differ" }
    }
    if ($focused.profile -cne "cantor-semantic-inspection-consumer-focused-test-summary/0.1" -or [int]$focused.result_groups -ne 5 -or [int]$focused.tests_passed -ne 22 -or [int]$focused.tests_ignored -ne 0 -or [int]$focused.fixture_cases -ne 8 -or [int]$focused.fixture_bytes -ne 36282 -or $focused.fixture_sha256 -cne "6ba11d93f80d8c9819be33624550809d94e5e2ac2106a6559fbcf62c8d803162") { throw "focused consumer counts differ" }
    if ($workspace.profile -cne "cantor-semantic-inspection-consumer-workspace-test-summary/0.1" -or [int]$workspace.result_groups -ne 361 -or [int]$workspace.tests_passed -ne 2090 -or [int]$workspace.tests_ignored -ne 22) { throw "complete workspace counts differ" }
    if ([int]$workspace.component_fixture_cases -ne 8 -or [int]$workspace.component_development_host_process_trials -ne 9 -or [int]$workspace.component_complete_wire_responses -ne 5 -or [int]$workspace.component_public_host_faults -ne 3 -or [int]$workspace.component_stalled_children_killed_and_reaped -ne 1) { throw "workspace component effect account differs" }
    foreach ($field in @("consumer_library_io_effects", "component_production_process_launches", "component_product_filesystem_effects", "component_network_effects", "component_service_effects", "component_provider_requests", "component_model_requests", "component_remote_calls", "installed_application_acceptances")) { if ([int]$workspace.$field -ne 0) { throw "unexpected workspace component effect: $field" } }
    if ([int]$focused.development_host_process_trials -ne 9 -or [int]$focused.development_completed_eof_requests -ne 8 -or [int]$focused.development_complete_wire_responses -ne 5 -or [int]$focused.development_public_host_faults -ne 3 -or [int]$focused.development_stalled_children_killed_and_reaped -ne 1) { throw "development fixture effect account differs" }
    foreach ($field in @("consumer_library_io_effects", "production_process_launches", "product_filesystem_effects", "network_effects", "service_effects", "provider_requests", "model_requests", "remote_calls", "installed_application_acceptances", "synthetic_provider_trials")) { if ([int]$focused.$field -ne 0) { throw "unexpected consumer effect: $field" } }
}

$verification = $manifest.verification
if ([int]$verification.artifact_count -ne 7 -or [int]$verification.component_files -ne 8 -or [int]$verification.focused_tests_per_profile -ne 22 -or [int]$verification.workspace_result_groups_per_profile -ne 361 -or [int]$verification.workspace_passed_per_profile -ne 2090 -or [int]$verification.workspace_failed_per_profile -ne 0 -or [int]$verification.workspace_ignored_per_profile -ne 22 -or [int]$verification.installed_application_acceptances -ne 0) { throw "consumer verification summary differs" }
if ([int]$verification.development_process_trials_per_focused_profile -ne 9 -or [int]$verification.complete_wire_responses_per_focused_profile -ne 5 -or [int]$verification.public_host_faults_per_focused_profile -ne 3 -or [int]$verification.stalled_children_killed_and_reaped_per_focused_profile -ne 1 -or [int]$verification.consumer_library_io_effects -ne 0 -or [int]$verification.production_process_launches -ne 0) { throw "consumer manifest effect account differs" }

if (-not $SkipCompletion) {
    $signature = Get-Content -LiteralPath (Join-Path $selectedRoot "narrative/registries/Cantor_Semantic_Inspection_Consumer_Handoff_P0_Completion_Satisfaction_Signature.sop") -Raw
    if ($signature -notmatch [regex]::Escape("@ [completion_signature_uuid] baebe81f-af10-4c56-bf12-c46e6af009f1") -or $signature -notmatch [regex]::Escape("@ [satisfaction_signature_protocol_uuid] ad10f10f-d506-48ef-a805-f8b0a133766c")) { throw "consumer completion signature identity differs" }
    $bindings = [regex]::Matches($signature, '(?m)^  \+ \[artifact_binding\] (\S+) bytes([0-9]+) SHA256 ([0-9A-F]{64})$')
    $expectedCompletionPaths = @("$experiment/semantic_inspection_consumer_component.json", "$experiment/implementation_evidence_manifest.json", "proofs/Cantor_Semantic_Inspection_Consumer_Handoff_P0_Implementation_Proof.sop", "feature_support/Cantor_Semantic_Inspection_Consumer_Handoff_P0_Completion_Matrix.sop", "narrative/reviews/Cantor_Semantic_Inspection_Consumer_Handoff_P0_Completion_Review.sop", "docs/SEMANTIC_INSPECTION_CONSUMER_HANDOFF_P0.md", "narrative/reentry/Cantor_Semantic_Inspection_Consumer_Handoff_P0_Reentry.sop", "scripts/test_cantor_semantic_inspection_consumer_handoff_p0.ps1", "scripts/test_cantor_semantic_inspection_consumer_workspace.ps1", "scripts/verify_cantor_semantic_inspection_consumer_handoff_p0_evidence.ps1")
    if ($bindings.Count -ne $expectedCompletionPaths.Count) { throw "consumer completion binding cardinality differs" }
    for ($index = 0; $index -lt $expectedCompletionPaths.Count; $index++) {
        $binding = $bindings[$index]
        if ($binding.Groups[1].Value -cne $expectedCompletionPaths[$index]) { throw "consumer completion binding membership differs" }
        Assert-Artifact ([pscustomobject]@{path=$binding.Groups[1].Value;bytes=[int64]$binding.Groups[2].Value;sha256=$binding.Groups[3].Value.ToLowerInvariant()})
    }
}
Write-Output ("cantor_consumer_handoff_evidence_verified=true artifacts=7 component_files=8 focused=22 workspace_groups=361 workspace_passed=2090 workspace_failed=0 workspace_ignored=22 completion_checked={0} product_effects=0 installed_application_acceptances=0" -f (-not $SkipCompletion))
