param([switch]$SkipCompletion)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$selectedRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_mcp_adapter_p0_formation.ps1")
$experiment = "experiments/cantor_semantic_inspection_mcp_adapter_p0"
function Assert-Artifact($Artifact) {
    $relative = [string]$Artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') { throw "nonportable artifact" }
    $path = Join-Path $selectedRoot $relative
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    # Existing transitive rehash stores SHA256 strings uppercase while fresh
    # component records use lowercase. Validate exact hex length and compare
    # the represented digest, not its presentation case; paths stay ordinal.
    $expectedHash = [string]$Artifact.sha256
    if ($expectedHash -cnotmatch '^[0-9A-Fa-f]{64}$' -or $item.PSIsContainer -or $item.Length -ne [int64]$Artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $expectedHash.ToUpperInvariant()) { throw "artifact differs: $relative" }
}
function Assert-Membership($Actual, $Expected) {
    if (@($Actual).Count -ne @($Expected).Count) { throw "artifact cardinality differs" }
    for ($index=0; $index -lt @($Expected).Count; $index++) {
        if (@($Actual)[$index].path -cne @($Expected)[$index]) { throw "artifact membership differs" }
        Assert-Artifact @($Actual)[$index]
    }
}
$manifest = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/implementation_evidence_manifest.json") -Raw | ConvertFrom-Json
if ($manifest.profile -cne "cantor-semantic-inspection-mcp-adapter-p0-evidence/0.1" -or $manifest.specification_uuid -cne "6a7d89c1-ba64-45d3-9e55-f7fca4c657ae" -or $manifest.formation_bookend -cne "2702ff94c298a49967a6c719f01584905aaa5b0d") { throw "manifest identity differs" }
$expectedArtifacts = @(
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/semantic_inspection_mcp_component.json",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/formation_evidence_manifest.json",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/focused_debug_summary.json",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/focused_release_summary.json",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/workspace_debug_summary.json",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/workspace_release_summary.json",
    "docs/SEMANTIC_INSPECTION_MCP_ADAPTER_P0.md"
)
Assert-Membership $manifest.artifacts $expectedArtifacts
foreach ($field in @("focused_debug_passed","focused_release_passed","workspace_debug_passed","workspace_release_passed","warnings_denied_workspace_clippy_passed","format_passed")) {
    if ($manifest.$field -cne $true) { throw "missing actual gate: $field" }
}
$component = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/semantic_inspection_mcp_component.json") -Raw | ConvertFrom-Json
if ($component.profile -cne "cantor-semantic-inspection-mcp-component/0.1" -or [int]$component.file_count -ne 9 -or $component.specification_uuid -cne $manifest.specification_uuid -or $component.formation_bookend -cne $manifest.formation_bookend -or $component.product_stdio_transport_enabled -cne $true) { throw "component coordinates differ" }
$expectedFiles = @(
    "crates/cantor_sop_inspect_mcp/Cargo.toml",
    "crates/cantor_sop_inspect_mcp/src/lib.rs",
    "crates/cantor_sop_inspect_mcp/src/transport.rs",
    "crates/cantor_sop_inspect_mcp/src/main.rs",
    "crates/cantor_sop_inspect_mcp/tests/support/mod.rs",
    "crates/cantor_sop_inspect_mcp/tests/adapter_adversarial.rs",
    "crates/cantor_sop_inspect_mcp/tests/sdk_protocol.rs",
    "crates/cantor_sop_inspect_mcp/tests/native_process.rs",
    "crates/cantor_sop_inspect_mcp/tests/static_boundary.rs"
)
Assert-Membership $component.files $expectedFiles
foreach ($field in @("pathname_acquisitions","subprocess_launches","network_effects","provider_requests","model_requests","service_installs","durable_custody_effects","remote_calls","installed_application_acceptances")) {
    if ([int]$component.$field -ne 0) { throw "unexpected component effect: $field" }
}
foreach ($pair in @(
    @("decoded_wire_request_bytes",262144), @("wire_response_bytes",1048576),
    @("input_frame_bytes",2097152), @("output_frame_bytes",4194304),
    @("aggregate_input_bytes",8388608), @("aggregate_reserved_output_bytes",8388608),
    @("decoded_message_ceiling",32), @("session_seconds",60), @("runtime_shutdown_milliseconds",250)
)) { if ([int]$component.$($pair[0]) -ne [int]$pair[1]) { throw "component bound differs" } }
$formation = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/formation_evidence_manifest.json") -Raw | ConvertFrom-Json
if ($formation.profile -cne "cantor-semantic-inspection-mcp-formation-evidence/0.1" -or $formation.specification_uuid -cne $manifest.specification_uuid -or $formation.signature_uuid -cne "7a3007f1-4ecd-4586-a7f3-fad8e3ecda8f" -or [int]$formation.requirements -ne 24 -or [int]$formation.acceptance -ne 6 -or @($formation.artifacts).Count -ne 14) { throw "formation evidence differs" }
$expectedFormation = @(
    "source_documents/2026-10-01_cantor_semantic_inspection_mcp_adapter_p0/User_Request_Lineage.sop",
    "source_documents/2026-10-01_cantor_semantic_inspection_mcp_adapter_p0/Derived_MCP_Adapter_Source.sop",
    "specifications/Cantor_Semantic_Inspection_MCP_Adapter_P0.sop",
    "justifications/Cantor_Semantic_Inspection_MCP_Adapter_P0_Justification.sop",
    "plans/Cantor_Semantic_Inspection_MCP_Adapter_P0_Plan.sop",
    "solutions/Cantor_Semantic_Inspection_MCP_Adapter_P0_Solution.sop",
    "feature_support/Cantor_Semantic_Inspection_MCP_Adapter_P0_Requirement_Matrix.sop",
    "proofs/Cantor_Semantic_Inspection_MCP_Adapter_P0_Artifact_Phase_Lock_Proof.sop",
    "scripts/verify_cantor_semantic_inspection_mcp_adapter_p0_formation.ps1",
    "crates/cantor_sop_inspect_wire/src/lib.rs",
    "crates/cantor_sop_inspect_wire/src/bin/cantor-sop-inspect-stdio.rs",
    "crates/cantor_sop_inspect/src/lib.rs",
    "crates/cantor_sop_inspect_consumer/src/lib.rs",
    "fixtures/semantic_inspection_consumer_handoff_p0/fixtures.json"
)
for ($index=0; $index -lt $expectedFormation.Count; $index++) {
    $artifact = @($formation.artifacts)[$index]
    if ($artifact.path -cne $expectedFormation[$index]) { throw "formation evidence membership differs" }
    # Frozen formation stores uppercase hashes; compare to physical identity
    # without modifying the already signed file or its digest representation.
    $path = Join-Path $selectedRoot ([string]$artifact.path)
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne [string]$artifact.sha256) { throw "formation evidence artifact differs" }
}
foreach ($cargoProfile in @("debug","release")) {
    $focused = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/focused_${cargoProfile}_summary.json") -Raw | ConvertFrom-Json
    $workspace = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/workspace_${cargoProfile}_summary.json") -Raw | ConvertFrom-Json
    foreach ($summary in @($focused,$workspace)) {
        if ($summary.cargo_profile -cne $cargoProfile -or -not $summary.locked -or -not $summary.offline -or -not $summary.all_features -or -not $summary.all_targets -or [int]$summary.serialized_test_threads -ne 1 -or [bool]$summary.overflow_checks -ne ($cargoProfile -ceq "release") -or [int]$summary.tests_failed -ne 0) { throw "gate coordinates differ" }
    }
    if ($focused.profile -cne "cantor-semantic-inspection-mcp-focused-test-summary/0.1" -or [int]$focused.result_groups -ne 6 -or [int]$focused.tests_passed -ne 27 -or [int]$focused.tests_ignored -ne 0 -or [int]$focused.golden_cases -ne 8 -or [int]$focused.golden_bytes -ne 36282 -or $focused.golden_sha256 -cne "6ba11d93f80d8c9819be33624550809d94e5e2ac2106a6559fbcf62c8d803162") { throw "focused evidence differs" }
    foreach ($pair in @(
        @("direct_golden_complete_wire_responses",5), @("direct_golden_adapter_refusals",3),
        @("native_process_trials",9), @("native_initialized_fixture_sessions",2),
        @("native_fixture_calls",16), @("native_fixture_complete_wire_responses",10),
        @("native_fixture_adapter_refusals",6), @("native_unknown_tool_protocol_refusals",2),
        @("native_cli_refusals",1), @("native_invalid_input_refusals",4),
        @("native_closed_output_refusals",1), @("native_stalled_io_deadline_exits",1),
        @("native_stalled_session_seconds",60), @("native_runtime_shutdown_milliseconds",250),
        @("successful_native_children_killed_by_harness",0), @("sdk_duplex_fixture_sessions",1), @("sdk_duplex_fixture_calls",8)
    )) { if ([int]$focused.$($pair[0]) -ne [int]$pair[1]) { throw "focused physical trial account differs" } }
    foreach ($field in @("product_pathname_acquisitions","product_subprocess_launches","network_effects","service_installs","durable_custody_effects","provider_requests","model_requests","remote_calls","synthetic_provider_trials","installed_application_acceptances")) {
        if ([int]$focused.$field -ne 0) { throw "unexpected focused effect: $field" }
    }
    if ($focused.product_stdio_transport_enabled -cne $true -or $workspace.profile -cne "cantor-semantic-inspection-mcp-workspace-test-summary/0.1" -or [int]$workspace.result_groups -ne 367 -or [int]$workspace.tests_passed -ne 2117 -or [int]$workspace.tests_ignored -ne 22 -or $workspace.component_product_stdio_transport_enabled -cne $true) { throw "workspace evidence differs" }
    foreach ($pair in @(@("component_fixture_cases",8),@("component_development_host_process_trials",9),@("component_native_fixture_calls",16),@("component_native_complete_wire_responses",10),@("component_native_adapter_refusals",6),@("component_native_stalled_io_deadline_exits",1),@("component_session_seconds",60),@("component_shutdown_milliseconds",250))) {
        if ([int]$workspace.$($pair[0]) -ne [int]$pair[1]) { throw "workspace component account differs" }
    }
    foreach ($field in @("component_production_process_launches","component_product_pathname_acquisitions","component_network_effects","component_service_effects","component_provider_requests","component_model_requests","component_remote_calls","installed_application_acceptances")) {
        if ([int]$workspace.$field -ne 0) { throw "unexpected workspace component effect" }
    }
}
if (-not $SkipCompletion) {
    $signature = Get-Content -LiteralPath (Join-Path $selectedRoot "narrative/registries/Cantor_Semantic_Inspection_MCP_Adapter_P0_Completion_Satisfaction_Signature.sop") -Raw
    foreach ($identity in @(
        "@ [completion_signature_uuid] 3b409008-0da1-4cda-8eab-9a75e05bc115",
        "@ [satisfaction_signature_protocol_uuid] ad10f10f-d506-48ef-a805-f8b0a133766c",
        "@ [specification_uuid] 6a7d89c1-ba64-45d3-9e55-f7fca4c657ae",
        "@ [formation_signature_uuid] 7a3007f1-4ecd-4586-a7f3-fad8e3ecda8f"
    )) { if ($signature -notmatch [regex]::Escape($identity)) { throw "completion identity differs" } }
    $expected = @(
        "experiments/cantor_semantic_inspection_mcp_adapter_p0/semantic_inspection_mcp_component.json",
        "experiments/cantor_semantic_inspection_mcp_adapter_p0/implementation_evidence_manifest.json",
        "proofs/Cantor_Semantic_Inspection_MCP_Adapter_P0_Implementation_Proof.sop",
        "feature_support/Cantor_Semantic_Inspection_MCP_Adapter_P0_Completion_Matrix.sop",
        "narrative/reviews/Cantor_Semantic_Inspection_MCP_Adapter_P0_Completion_Review.sop",
        "docs/SEMANTIC_INSPECTION_MCP_ADAPTER_P0.md",
        "narrative/reentry/Cantor_Semantic_Inspection_MCP_Adapter_P0_Reentry.sop",
        "scripts/test_cantor_semantic_inspection_mcp_adapter_p0.ps1",
        "scripts/test_cantor_semantic_inspection_mcp_workspace.ps1",
        "scripts/verify_cantor_semantic_inspection_mcp_adapter_p0_evidence.ps1",
        "scripts/test_cantor_semantic_inspection_mcp_evidence_adversaries.ps1",
        "experiments/cantor_semantic_inspection_mcp_adapter_p0/evidence_adversaries_summary.json"
    )
    $bindings = [regex]::Matches($signature,'(?m)^  \+ \[artifact_binding\] (\S+) bytes([0-9]+) SHA256 ([0-9A-F]{64})$')
    if ($bindings.Count -ne 12) { throw "completion binding count differs" }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($binding in $bindings) {
        $relative = $binding.Groups[1].Value
        if ($relative -cnotin $expected -or -not $seen.Add($relative)) { throw "unexpected completion binding" }
        $path = Join-Path $selectedRoot $relative
        if ((Get-Item -LiteralPath $path).Length -ne [int64]$binding.Groups[2].Value -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $binding.Groups[3].Value) { throw "completion artifact differs" }
    }
    $adversaries = Get-Content -LiteralPath (Join-Path $selectedRoot "$experiment/evidence_adversaries_summary.json") -Raw | ConvertFrom-Json
    if ($adversaries.profile -cne "cantor-semantic-inspection-mcp-evidence-adversaries/0.1" -or $adversaries.baseline_partial_evidence_replay_passed -cne $true -or $adversaries.completion_signature_mode -cne "explicitly_skipped_for_pre_signature_metadata_mutations" -or [int]$adversaries.adversarial_cases -ne 8 -or @($adversaries.cases).Count -ne 8 -or $adversaries.all_refused -cne $true -or $adversaries.test_copies_retained -cne $true) { throw "evidence adversary coordinates differ" }
    foreach ($field in @("repository_files_mutated","protected_foreign_files_mutated","native_process_trials","provider_requests","model_requests","synthetic_provider_trials","installed_application_acceptances")) {
        if ([int]$adversaries.$field -ne 0) { throw "unexpected evidence adversary effect" }
    }
    $expectedCases = @("focused-count","native-trials","scope-model","session-limit","component-membership","artifact-membership","formation-profile","pinned-wire-bytes")
    for ($index=0; $index -lt $expectedCases.Count; $index++) {
        $case = @($adversaries.cases)[$index]
        if ($case.case -cne $expectedCases[$index] -or $case.refused -cne $true -or [string]::IsNullOrWhiteSpace($case.reason)) { throw "evidence adversary refusal differs" }
        if ([bool]$case.outer_hash_refreshed -ne ($case.case -notin @("artifact-membership","pinned-wire-bytes"))) { throw "evidence adversary rehash witness differs" }
    }
}
Write-Output ("cantor_mcp_adapter_evidence_verified=true formation=14 artifacts=7 component_files=9 focused=27 workspace=2117 native_trials=9 deadline_exits=1 completion_checked=" + (-not $SkipCompletion))
