param()
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$selectedRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$base = "D:\CantorBuilds\cantor-semantic-inspection-mcp"
$baseItem = Get-Item -LiteralPath $base
if (-not $baseItem.PSIsContainer -or ($baseItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "test parent differs" }
$testRoot = Join-Path $base ("evidence-adversaries-" + [guid]::NewGuid().ToString("N"))
if (Test-Path -LiteralPath $testRoot) { throw "test root must be absent" }
New-Item -ItemType Directory -Path $testRoot | Out-Null
$files = @(
    "source_documents/2026-10-01_cantor_semantic_inspection_mcp_adapter_p0/User_Request_Lineage.sop",
    "source_documents/2026-10-01_cantor_semantic_inspection_mcp_adapter_p0/Derived_MCP_Adapter_Source.sop",
    "specifications/Cantor_Semantic_Inspection_MCP_Adapter_P0.sop",
    "justifications/Cantor_Semantic_Inspection_MCP_Adapter_P0_Justification.sop",
    "plans/Cantor_Semantic_Inspection_MCP_Adapter_P0_Plan.sop",
    "solutions/Cantor_Semantic_Inspection_MCP_Adapter_P0_Solution.sop",
    "feature_support/Cantor_Semantic_Inspection_MCP_Adapter_P0_Requirement_Matrix.sop",
    "proofs/Cantor_Semantic_Inspection_MCP_Adapter_P0_Artifact_Phase_Lock_Proof.sop",
    "scripts/verify_cantor_semantic_inspection_mcp_adapter_p0_formation.ps1",
    "narrative/registries/Cantor_Semantic_Inspection_MCP_Adapter_P0_Satisfaction_Signature.sop",
    "crates/cantor_sop_inspect_wire/src/lib.rs",
    "crates/cantor_sop_inspect_wire/src/bin/cantor-sop-inspect-stdio.rs",
    "crates/cantor_sop_inspect/src/lib.rs",
    "crates/cantor_sop_inspect_consumer/src/lib.rs",
    "fixtures/semantic_inspection_consumer_handoff_p0/fixtures.json",
    "crates/cantor_sop_inspect_mcp/Cargo.toml",
    "crates/cantor_sop_inspect_mcp/src/lib.rs",
    "crates/cantor_sop_inspect_mcp/src/transport.rs",
    "crates/cantor_sop_inspect_mcp/src/main.rs",
    "crates/cantor_sop_inspect_mcp/tests/support/mod.rs",
    "crates/cantor_sop_inspect_mcp/tests/adapter_adversarial.rs",
    "crates/cantor_sop_inspect_mcp/tests/sdk_protocol.rs",
    "crates/cantor_sop_inspect_mcp/tests/native_process.rs",
    "crates/cantor_sop_inspect_mcp/tests/static_boundary.rs",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/semantic_inspection_mcp_component.json",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/formation_evidence_manifest.json",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/focused_debug_summary.json",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/focused_release_summary.json",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/workspace_debug_summary.json",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/workspace_release_summary.json",
    "docs/SEMANTIC_INSPECTION_MCP_ADAPTER_P0.md",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/implementation_evidence_manifest.json",
    "scripts/verify_cantor_semantic_inspection_mcp_adapter_p0_evidence.ps1"
)
if ($files.Count -gt 64) { throw "copy inventory bound" }
function New-Case([string]$Name) {
    if ($Name -cnotmatch '^[a-z-]+$') { throw "test leaf differs" }
    $directory = Join-Path $testRoot $Name
    New-Item -ItemType Directory -Path $directory | Out-Null
    foreach ($relative in $files) {
        $source = Join-Path $selectedRoot $relative
        $item = Get-Item -LiteralPath $source
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0 -or $item.Length -gt 2097152) { throw "fixture source bound" }
        $target = Join-Path $directory $relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
        Copy-Item -LiteralPath $source -Destination $target
    }
    return $directory
}
function Write-JsonFixture([string]$Path,$Value) {
    $text = (($Value | ConvertTo-Json -Depth 100).Replace("`r`n","`n"))+"`n"
    [IO.File]::WriteAllText($Path,$text,(New-Object Text.UTF8Encoding($false)))
}
function Refresh-OuterIdentity([string]$Directory,[string]$Relative) {
    $path = Join-Path $Directory $Relative
    $manifestPath = Join-Path $Directory "experiments/cantor_semantic_inspection_mcp_adapter_p0/implementation_evidence_manifest.json"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $matchingArtifacts = @($manifest.artifacts | Where-Object {$_.path -ceq $Relative})
    if ($matchingArtifacts.Count -ne 1) { throw "mutation target membership" }
    $matchingArtifacts[0].bytes = (Get-Item -LiteralPath $path).Length
    $matchingArtifacts[0].sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-JsonFixture $manifestPath $manifest
}
$baseline = New-Case "baseline"
& (Join-Path $baseline "scripts/verify_cantor_semantic_inspection_mcp_adapter_p0_evidence.ps1") -SkipCompletion | Out-Null
$cases = @(
    @("focused-count","focused_debug_summary.json","tests_passed",28),
    @("native-trials","focused_debug_summary.json","native_process_trials",8),
    @("scope-model","focused_debug_summary.json","model_requests",1),
    @("session-limit","semantic_inspection_mcp_component.json","session_seconds",59),
    @("component-membership","semantic_inspection_mcp_component.json","component_membership",0),
    @("artifact-membership","implementation_evidence_manifest.json","artifact_membership",0),
    @("formation-profile","formation_evidence_manifest.json","profile","foreign"),
    @("pinned-wire-bytes","","wire_bytes",0)
)
$results = @()
foreach ($case in $cases) {
    $directory = New-Case ([string]$case[0])
    if ($case[2] -ceq "wire_bytes") {
        $path = Join-Path $directory "crates/cantor_sop_inspect_wire/src/lib.rs"
        [IO.File]::AppendAllText($path,"`n",(New-Object Text.UTF8Encoding($false)))
    } else {
        $relative = "experiments/cantor_semantic_inspection_mcp_adapter_p0/" + $case[1]
        $path = Join-Path $directory $relative
        $value = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($case[2] -ceq "component_membership") { $value.files[0].path = $value.files[1].path }
        elseif ($case[2] -ceq "artifact_membership") { $value.artifacts[0].path = $value.artifacts[1].path }
        else { $value.$($case[2]) = $case[3] }
        Write-JsonFixture $path $value
        if ($case[2] -cne "artifact_membership") { Refresh-OuterIdentity $directory $relative }
    }
    $refused = $false
    $reason = ""
    try { & (Join-Path $directory "scripts/verify_cantor_semantic_inspection_mcp_adapter_p0_evidence.ps1") -SkipCompletion | Out-Null }
    catch { $refused = $true; $reason = $_.Exception.Message }
    if (-not $refused) { throw ("evidence adversary admitted: " + $case[0]) }
    $results += [ordered]@{case=[string]$case[0];refused=$true;reason=$reason;outer_hash_refreshed=($case[2] -notin @("wire_bytes","artifact_membership"))}
}
$report = [ordered]@{
    profile="cantor-semantic-inspection-mcp-evidence-adversaries/0.1"
    baseline_partial_evidence_replay_passed=$true
    completion_signature_mode="explicitly_skipped_for_pre_signature_metadata_mutations"
    adversarial_cases=8; cases=$results; all_refused=$true
    repository_files_mutated=0; protected_foreign_files_mutated=0
    native_process_trials=0; provider_requests=0; model_requests=0; synthetic_provider_trials=0
    installed_application_acceptances=0; test_copies_retained=$true
}
$reportPath = Join-Path $testRoot "summary.json"
Write-JsonFixture $reportPath $report
Write-Output ("cantor_mcp_evidence_adversaries_passed=true cases=8 copies_retained=" + $testRoot + " summary=" + $reportPath)
