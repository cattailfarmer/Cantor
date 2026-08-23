[CmdletBinding()]
param(
    [string]$MatrixPath = 'experiments/nested_cantor_host_gap_audit/artifacts/nested_cantor_host_gap_matrix_v1.json',
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$defaultRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$root = if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $defaultRoot } else { [IO.Path]::GetFullPath($RepositoryRoot) }
$matrixFullPath = if ([IO.Path]::IsPathRooted($MatrixPath)) { [IO.Path]::GetFullPath($MatrixPath) } else { [IO.Path]::GetFullPath((Join-Path $root $MatrixPath)) }
$profile = 'cantor-nested-llm-host-gap-audit/0.1'

function Assert-Audit([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Properties([object]$Value, [string[]]$Expected, [string]$Label) {
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    Assert-Audit (($actual -join ',') -ceq ($wanted -join ',')) "$Label properties differ"
}

function Get-TrackedPhysicalFile([string]$RelativePath, [string]$Label) {
    Assert-Audit (-not [string]::IsNullOrWhiteSpace($RelativePath) -and $RelativePath -cmatch '^[A-Za-z0-9_.\-/]+$') "$Label path shape differs"
    Assert-Audit (-not [IO.Path]::IsPathRooted($RelativePath) -and ($RelativePath -split '/') -notcontains '..' -and -not $RelativePath.Contains('\')) "$Label path is not conservative relative form"
    $full = [IO.Path]::GetFullPath((Join-Path $root $RelativePath))
    $prefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    Assert-Audit ($full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) "$Label escapes repository root"
    $item = Get-Item -LiteralPath $full -Force
    Assert-Audit (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Length -gt 0 -and $item.Length -le 4MB) "$Label is not one bounded physical file"
    $tracked = @(& git -C $root ls-files --error-unmatch -- $RelativePath 2>$null)
    Assert-Audit ($LASTEXITCODE -eq 0 -and $tracked.Count -eq 1 -and $tracked[0].Replace('\', '/') -ceq $RelativePath) "$Label is not one exact tracked file"
    $item
}

$expectedRows = @(
    'NHG-001|outer_cantor_process_identity|proved_reusable|not_integrated|outer_host_identity_session_p0|DE92742A5092B5886D8224C2891711741CA195405D1686CF843C77AA4E2C22D2|specifications/Cantor_Supervised_Local_Lifecycle.sop,proofs/Cantor_Supervised_Local_Lifecycle_Proof.sop',
    'NHG-002|outer_needle_model_identity|historical_only|not_integrated|outer_model_identity_admission_p0|56561B4D32D2B503A1E995D1D67817CF0D53CC104A29682906CCEC789864B67B|specifications/Cantor_EVO_X2_Needle2_SOP_Attention_Runtime.sop,proofs/Cantor_EVO_X2_Needle2_SOP_Attention_Runtime_Proof.sop',
    'NHG-003|inner_cantor_process_identity|candidate_only|missing_contract|inner_cantor_process_identity_p0|6AA5DB567A5BEA186E674A8D3F15340BC9A87AC9BDCC1E31615760EEF4488D26|crates/cantor_core/src/semantic_compiler/inference_host_backend.rs,proofs/Cantor_Seeded_Compiler_Slice4_External_Inference_Host_Proof.sop',
    'NHG-004|inner_model_identity_and_admission|candidate_only|missing_contract|inner_model_identity_admission_p0|B6DDD569800BF934315827B4CDB532FC66F16E93FCC0F219E087CEC52018C539|crates/cantor_core/src/semantic_compiler/inference_host_backend.rs,proofs/Cantor_Seeded_Compiler_Slice4_External_Inference_Host_Proof.sop',
    'NHG-005|inner_launch_authority|candidate_only|missing_contract|inner_launch_plan_authority_p0|73E081694DCF8324ABC550CE26BE689C422B6C760ADD29FB36C92FD856734E8C|specifications/Cantor_Supervised_Local_Lifecycle.sop,proofs/Cantor_Seeded_Compiler_Slice4_External_Inference_Host_Proof.sop',
    'NHG-006|model_loading_and_custody_authority|absent|missing_contract|model_load_custody_authority_p0|D402A6D2B7B46EF28FC26D6E0956651FB183EF765045BB7F54035ABFCECC34F4|specifications/Cantor_EVO_X2_Needle2_SOP_Attention_Runtime.sop,experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe_verification.json',
    'NHG-007|sop_contract_execution|proved_reusable|not_integrated|nested_sop_execution_authority_p0|09635B1E3CA8EF4E96A052E65BEF8BA44A20875FC1ECEA0C0F90A9025FE81AD2|proofs/Cantor_EVO_X2_Needle2_SOP_Attention_Runtime_Proof.sop,proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice4C_Proof.sop',
    'NHG-008|negotiated_shared_attention_frame|proved_reusable|not_integrated|negotiated_shared_attention_window_p0|BEBFEC61636C68C7E35DEA7A54A5C914C4AA3C06A1A165F30642F955C3731810|specifications/Cantor_Shared_Attention_Imagination_Runtime_P0.sop,proofs/Cantor_Shared_Attention_Imagination_Runtime_P0_Proof.sop,proofs/Cantor_Shared_Attention_Tool_Adapter_P0_Proof.sop',
    'NHG-009|shared_inference_perspective_exchange|candidate_only|missing_contract|shared_inference_exchange_p0|87192E76738A006BB51819CCB88C59832ABC0047086EFCCF26DC038D698FE199|specifications/Cantor_Shared_Attention_Tool_Adapter_P0.sop,proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6C_Proof.sop',
    'NHG-010|bounded_attention_and_lifecycle_custody|proved_reusable|not_integrated|nested_session_custody_p0|643EA423D50C4F4C63B71756661202FB0C29BD12D32A72437E76AD710B15D1A6|proofs/Cantor_Shared_Attention_Imagination_Runtime_P0_Proof.sop,proofs/Cantor_Seeded_Compiler_Slice10_Volatile_Custody_MCP_Proof.sop',
    'NHG-011|fault_restart_and_recovery|proved_reusable|not_integrated|nested_fault_recovery_p0|7C65744B7ACEBF91A2654E7B59229DD1315A3D97A86F7E46B86C891F55AE7DB1|proofs/Cantor_Supervised_Local_Lifecycle_Proof.sop,proofs/Cantor_Seeded_Compiler_Slice10_Volatile_Custody_MCP_Proof.sop,proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice4B_Proof.sop',
    'NHG-012|provider_inference_checkpoint_bridge|proved_reusable|not_integrated|nested_provider_bridge_p0|591D3782F0BF29BA0D107BC4CAE83B07EA292D92E70F4EEA734021F1083E016E|specifications/Cantor_Live_Lifecycle_Tool_Loop_Measurement_P0.sop,proofs/Cantor_Seeded_Compiler_Slice11_Live_Tool_Loop_Measurement_Proof.sop',
    'NHG-013|current_live_two_model_execution|historical_only|blocked_current_provider|exact_local_two_model_experiment_p0|0322887F7D372FA38E5821839778593C0A10CA1511846D94952D3AF3D8E546C3|proofs/Cantor_EVO_X2_Needle2_SOP_Attention_Runtime_Proof.sop,experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe.json,experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe_verification.json',
    'NHG-014|resource_and_context_isolation|absent|missing_contract|nested_resource_isolation_p0|6267B36406D939E31820EE0A3F3AAEF1B9C96DFFAE2BAACDC7065EFBBD6C6B9F|specifications/Cantor_Supervised_Local_Lifecycle.sop,specifications/Cantor_Shared_Attention_Imagination_Runtime_P0.sop',
    'NHG-015|operator_security_and_trust|candidate_only|deferred_operator_product|nested_operator_trust_p0|D146CC77D1320E25386493BD57824F86B614AD481F8052098B047E0F498BDFCA|specifications/Cantor_Supervised_Local_Lifecycle.sop,docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'NHG-016|nested_agent_product_delivery|candidate_only|deferred_operator_product|nested_agent_product_acceptance_p0|FB14A88B81190414AD77D7882159F47C7FF340EDCC93B8E071A4729C7FB5A581|docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md,docs/CANTOR_PRODUCT_READINESS_2026-08-23.md'
)

$requiredMarkers = [ordered]@{
    'specifications/Cantor_Supervised_Local_Lifecycle.sop' = '[effect_authority] is only one explicitly selected local cantord process'
    'proofs/Cantor_Supervised_Local_Lifecycle_Proof.sop' = 'Cantor now has a proved PID-reuse-safe authenticated Windows operator lifecycle for one explicitly selected cantord process'
    'specifications/Cantor_EVO_X2_Needle2_SOP_Attention_Runtime.sop' = 'never: represent a sidecar checkpoint loop as one literal shared transformer forward pass'
    'proofs/Cantor_EVO_X2_Needle2_SOP_Attention_Runtime_Proof.sop' = '[result] is passed_with_calibrated_routing_residual'
    'crates/cantor_core/src/semantic_compiler/inference_host_backend.rs' = 'no process, calls no model, and grants none of the runtime requirements'
    'proofs/Cantor_Seeded_Compiler_Slice4_External_Inference_Host_Proof.sop' = '[status] SeededCompilerSlice4ExternalInferenceHost_implemented_verified_and_closed'
    'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe_verification.json' = '"status": "provider_unavailable_verified"'
    'proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice4C_Proof.sop' = '[status] Slice4CProviderFreeTerminalReflectionPending_implemented_and_verified'
    'specifications/Cantor_Shared_Attention_Imagination_Runtime_P0.sop' = 'excludes network transport llama.cpp modification model calls'
    'proofs/Cantor_Shared_Attention_Imagination_Runtime_P0_Proof.sop' = '[Conclusion] is pure_shared_attention_and_imagination_runtime_P0_verified'
    'proofs/Cantor_Shared_Attention_Tool_Adapter_P0_Proof.sop' = '[Conclusion] is stateless_shared_attention_MCP_tool_P0_verified'
    'specifications/Cantor_Shared_Attention_Tool_Adapter_P0.sop' = 'a host may supply the structured successor to a later model pass'
    'proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice6C_Proof.sop' = '[status] Slice6CProviderFreeDualTranscriptProjection_implemented_and_verified'
    'proofs/Cantor_Seeded_Compiler_Slice10_Volatile_Custody_MCP_Proof.sop' = '[status] SeededCompilerSlice10VolatileCustodyMCP_implemented_verified_and_closed'
    'proofs/Cantor_Iterative_Attention_Procedure_Loop_P1_Slice4B_Proof.sop' = '[status] Slice4BProviderFreeReadyStoppedOrchestration_implemented_and_verified'
    'specifications/Cantor_Live_Lifecycle_Tool_Loop_Measurement_P0.sop' = 'provider installation remote fallback model download and host-policy changes are not authorized'
    'proofs/Cantor_Seeded_Compiler_Slice11_Live_Tool_Loop_Measurement_Proof.sop' = '[status] Slice11_provider_independent_executable_experiment_implemented_verified_and_published_ready'
    'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe.json' = '"status": "provider_unavailable"'
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md' = '| Operator product | Not satisfied;'
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md' = '## Nested Cantor LLM-host objective'
}

Assert-Audit ([IO.Directory]::Exists($root) -and $expectedRows.Count -eq 16) 'repository root or expected matrix differs'
$matrixItem = Get-Item -LiteralPath $matrixFullPath -Force
Assert-Audit (-not $matrixItem.PSIsContainer -and ($matrixItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $matrixItem.Length -gt 0 -and $matrixItem.Length -le 256KB) 'matrix is not one bounded physical file'
$matrix = Get-Content -LiteralPath $matrixItem.FullName -Raw | ConvertFrom-Json
Assert-Properties $matrix @('profile', 'source_uuid', 'base_commit', 'entry_count', 'entries', 'substrate_counts', 'nested_state_counts', 'non_authority_statement') 'matrix'
Assert-Audit ($matrix.profile -ceq $profile -and $matrix.source_uuid -ceq '6fa07b14-4a49-495c-834f-be2b7dd0f7ea' -and $matrix.base_commit -ceq '1aa37e33919bc885ca06b43970b16c067b51ae5a' -and [int]$matrix.entry_count -eq 16 -and @($matrix.entries).Count -eq 16) 'matrix identity or count differs'
Assert-Properties $matrix.substrate_counts @('proved_reusable', 'candidate_only', 'historical_only', 'absent') 'substrate counts'
Assert-Properties $matrix.nested_state_counts @('not_integrated', 'missing_contract', 'blocked_current_provider', 'deferred_operator_product') 'nested state counts'
Assert-Audit ($matrix.non_authority_statement -ceq 'This gap audit classifies existing tracked evidence against the preserved nested-host vision. It authorizes no process launch, model loading, provider call, persistence, remote action, effect, FPGA, or Minecraft work.') 'non-authority statement differs'

$coordinates = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$evidenceSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$canonicalRows = [Collections.Generic.List[string]]::new()
$derivedSubstrate = @{ proved_reusable = 0; candidate_only = 0; historical_only = 0; absent = 0 }
$derivedNested = @{ not_integrated = 0; missing_contract = 0; blocked_current_provider = 0; deferred_operator_product = 0 }
for ($index = 0; $index -lt $expectedRows.Count; $index++) {
    $parts = @($expectedRows[$index] -split '\|', 7)
    Assert-Audit ($parts.Count -eq 7) 'internal expected row differs'
    $entry = $matrix.entries[$index]
    Assert-Properties $entry @('coordinate', 'vision_need', 'substrate_state', 'nested_system_state', 'evidence_paths', 'gap', 'next_contract', 'effect_authority') "entry $index"
    $actualPaths = @($entry.evidence_paths | ForEach-Object { [string]$_ })
    $actual = @([string]$entry.coordinate, [string]$entry.vision_need, [string]$entry.substrate_state, [string]$entry.nested_system_state, [string]$entry.next_contract, [string]$entry.gap, ($actualPaths -join ','))
    for ($field = 0; $field -lt 5; $field++) {
        Assert-Audit ($actual[$field] -ceq $parts[$field]) "entry $index field $field differs"
    }
    $gapBytes = [Text.Encoding]::UTF8.GetBytes($actual[5])
    $gapHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($gapBytes))
    Assert-Audit ($gapBytes.Length -ge 32 -and $gapBytes.Length -le 768 -and $gapHash -ceq $parts[5]) "entry $index gap differs"
    Assert-Audit ($actual[6] -ceq $parts[6] -and $actualPaths.Count -ge 2 -and $actualPaths.Count -le 3) "entry $index evidence mapping differs"
    Assert-Audit ([string]$entry.effect_authority -ceq 'none') "entry $index effect authority differs"
    Assert-Audit ($coordinates.Add($actual[0])) "duplicate coordinate: $($actual[0])"
    $derivedSubstrate[$actual[2]]++
    $derivedNested[$actual[3]]++
    foreach ($path in $actualPaths) {
        [void](Get-TrackedPhysicalFile $path "entry $index evidence")
        [void]$evidenceSet.Add($path)
    }
    $canonicalRows.Add(($actual[0..4] + @($gapHash, $actual[6], 'none') -join "`0"))
}

foreach ($name in $derivedSubstrate.Keys) {
    Assert-Audit ([int]$matrix.substrate_counts.$name -eq $derivedSubstrate[$name]) "substrate count differs: $name"
}
foreach ($name in $derivedNested.Keys) {
    Assert-Audit ([int]$matrix.nested_state_counts.$name -eq $derivedNested[$name]) "nested state count differs: $name"
}

foreach ($pair in $requiredMarkers.GetEnumerator()) {
    Assert-Audit ($evidenceSet.Contains([string]$pair.Key)) "required evidence was not mapped: $($pair.Key)"
    $item = Get-TrackedPhysicalFile ([string]$pair.Key) 'required evidence'
    $content = [IO.File]::ReadAllText($item.FullName)
    Assert-Audit ($content.Contains([string]$pair.Value, [StringComparison]::Ordinal)) "required evidence marker differs: $($pair.Key)"
}

$providerUnavailable = Get-Content -LiteralPath (Join-Path $root 'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe.json') -Raw | ConvertFrom-Json
$providerVerification = Get-Content -LiteralPath (Join-Path $root 'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe_verification.json') -Raw | ConvertFrom-Json
Assert-Audit ($providerUnavailable.status -ceq 'provider_unavailable' -and @($providerUnavailable.trials).Count -eq 0 -and $null -eq $providerUnavailable.preflight) 'provider-unavailable source boundary differs'
Assert-Audit ($providerVerification.status -ceq 'provider_unavailable_verified' -and -not [bool]$providerVerification.provider_contacted -and [int]$providerVerification.registration_count -eq 0 -and [int]$providerVerification.trial_count -eq 0) 'provider-unavailable verification boundary differs'

$canonicalBytes = [Text.Encoding]::UTF8.GetBytes(($canonicalRows -join "`n"))
$mappingDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($canonicalBytes))
$receipt = [ordered]@{
    profile = $profile
    status = 'passed'
    entry_count = [uint32]$matrix.entries.Count
    evidence_file_count = [uint32]$evidenceSet.Count
    mapping_sha256 = $mappingDigest
    proved_reusable = [uint32]$derivedSubstrate.proved_reusable
    missing_contracts = [uint32]$derivedNested.missing_contract
    absent_substrate = [uint32]$derivedSubstrate.absent
    current_live_provider_available = $false
    implementation_authority_granted = $false
}
Write-Output ($receipt | ConvertTo-Json -Compress)
