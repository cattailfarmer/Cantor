param()
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$selectedRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$signature = Get-Content -Raw -LiteralPath (Join-Path $selectedRoot "narrative/registries/Cantor_Inspection_Runtime_Seed_P0_Satisfaction_Signature.sop")
foreach ($identity in @(
    "@ [signature_uuid] f1b12f90-974d-4e0f-b110-5cb1f5ca9409",
    "@ [satisfaction_signature_protocol_uuid] ad10f10f-d506-48ef-a805-f8b0a133766c",
    "@ [specification_uuid] e3e7a424-c013-492a-a913-044ea17dc66d",
    "@ [source_snapshot_uuid] 6ea51dc3-5fb2-4a0c-b378-3615ac285430"
)) { if ($signature -notmatch [regex]::Escape($identity)) { throw "seed formation identity differs" } }
$expected = @(
    "source_documents/2026-10-01_cantor_inspection_runtime_seed_p0/User_Request_Lineage.sop",
    "source_documents/2026-10-01_cantor_inspection_runtime_seed_p0/Derived_Inspection_Seed_Source.sop",
    "specifications/Cantor_Inspection_Runtime_Seed_P0.sop",
    "justifications/Cantor_Inspection_Runtime_Seed_P0_Justification.sop",
    "plans/Cantor_Inspection_Runtime_Seed_P0_Plan.sop",
    "solutions/Cantor_Inspection_Runtime_Seed_P0_Solution.sop",
    "feature_support/Cantor_Inspection_Runtime_Seed_P0_Requirement_Matrix.sop",
    "proofs/Cantor_Inspection_Runtime_Seed_P0_Artifact_Phase_Lock_Proof.sop",
    "scripts/verify_cantor_inspection_runtime_seed_p0_formation.ps1",
    "experiments/cantor_semantic_inspection_mcp_adapter_p0/semantic_inspection_mcp_component.json",
    "narrative/registries/Cantor_Semantic_Inspection_MCP_Adapter_P0_Completion_Satisfaction_Signature.sop",
    "Cargo.lock",
    "Cargo.toml",
    "docs/SEMANTIC_INSPECTION_MCP_ADAPTER_P0.md"
)
$bindings = [regex]::Matches($signature,'(?m)^  \+ \[artifact_binding\] (\S+) bytes([0-9]+) SHA256 ([0-9A-F]{64})$')
if ($bindings.Count -ne 14) { throw "seed formation binding cardinality differs" }
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($binding in $bindings) {
    $relative = $binding.Groups[1].Value
    if ($relative -cnotin $expected -or -not $seen.Add($relative)) { throw "seed formation membership differs" }
    $path = Join-Path $selectedRoot $relative
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$binding.Groups[2].Value -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $binding.Groups[3].Value) { throw "seed formation artifact differs" }
}
$specification = Get-Content -Raw -LiteralPath (Join-Path $selectedRoot "specifications/Cantor_Inspection_Runtime_Seed_P0.sop")
$requirements = @([regex]::Matches($specification,'\[CIRS-[0-9]{3}\]') | ForEach-Object {$_.Value})
$acceptance = @([regex]::Matches($specification,'\[CIRS-A[0-9]{2}\]') | ForEach-Object {$_.Value})
if ($requirements.Count -ne 24 -or $acceptance.Count -ne 6) { throw "seed formation requirement count differs" }
for ($index=1;$index -le 24;$index++) { if (('[CIRS-{0:D3}]' -f $index) -cnotin $requirements) { throw "seed formation requirement missing" } }
for ($index=1;$index -le 6;$index++) { if (('[CIRS-A{0:D2}]' -f $index) -cnotin $acceptance) { throw "seed formation acceptance missing" } }
$protected = 'C:\Project\Cantor\narrative\turns\1786911720465_minecraftgenie_scope_handoff_negotiation.sop'
if ((Get-Item -LiteralPath $protected).Length -ne 1805 -or (Get-FileHash -LiteralPath $protected -Algorithm SHA256).Hash -cne '5B806E8D078C03D189021D0BB458EA42ADE3508E04677387D9AB9966DADC6F07') { throw "protected source differs" }
Write-Output "cantor_inspection_seed_formation_verified=true artifacts=14 requirements=24 acceptance=6 implementation_claims=0"
