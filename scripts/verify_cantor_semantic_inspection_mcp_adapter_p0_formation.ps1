param([string]$RepositoryRoot = "")
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Join-Path $PSScriptRoot ".." }
$selectedRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$signature = Get-Content -LiteralPath (Join-Path $selectedRoot "narrative/registries/Cantor_Semantic_Inspection_MCP_Adapter_P0_Satisfaction_Signature.sop") -Raw
foreach ($identity in @(
    "@ [signature_uuid] 7a3007f1-4ecd-4586-a7f3-fad8e3ecda8f",
    "@ [satisfaction_signature_protocol_uuid] ad10f10f-d506-48ef-a805-f8b0a133766c",
    "@ [specification_uuid] 6a7d89c1-ba64-45d3-9e55-f7fca4c657ae",
    "@ [source_snapshot_uuid] 592d9fad-a7fc-4845-aa3e-abcd087c606d"
)) { if ($signature -notmatch [regex]::Escape($identity)) { throw "formation identity differs" } }
$expected = @(
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
$bindings = [regex]::Matches($signature, '(?m)^  \+ \[artifact_binding\] (\S+) bytes([0-9]+) SHA256 ([0-9A-F]{64})$')
if ($bindings.Count -ne 14) { throw "expected fourteen formation bindings" }
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($binding in $bindings) {
    $relative = $binding.Groups[1].Value
    if ($relative -cnotin $expected -or -not $seen.Add($relative)) { throw "unexpected or duplicate formation binding" }
    $path = Join-Path $selectedRoot $relative
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$binding.Groups[2].Value -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $binding.Groups[3].Value) { throw "formation artifact differs: $relative" }
}
$specification = Get-Content -LiteralPath (Join-Path $selectedRoot "specifications/Cantor_Semantic_Inspection_MCP_Adapter_P0.sop") -Raw
$requirements = @([regex]::Matches($specification, '\[CIMA-[0-9]{3}\]') | ForEach-Object { $_.Value })
$acceptance = @([regex]::Matches($specification, '\[CIMA-A[0-9]{2}\]') | ForEach-Object { $_.Value })
if ($requirements.Count -ne 24 -or $acceptance.Count -ne 6) { throw "formation cardinality differs" }
for ($index = 1; $index -le 24; $index++) { if (('[CIMA-{0:D3}]' -f $index) -cnotin $requirements) { throw "missing requirement" } }
for ($index = 1; $index -le 6; $index++) { if (('[CIMA-A{0:D2}]' -f $index) -cnotin $acceptance) { throw "missing acceptance" } }
$protected = 'C:\Project\Cantor\narrative\turns\1786911720465_minecraftgenie_scope_handoff_negotiation.sop'
if ((Get-Item -LiteralPath $protected).Length -ne 1805 -or (Get-FileHash -LiteralPath $protected -Algorithm SHA256).Hash -cne '5B806E8D078C03D189021D0BB458EA42ADE3508E04677387D9AB9966DADC6F07') { throw "protected source differs" }
Write-Output "cantor_mcp_adapter_formation_verified=true artifacts=14 requirements=24 acceptance=6 implementation_claims=0"

