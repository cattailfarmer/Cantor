[CmdletBinding()]
param(
    [string]$ManifestPath = 'experiments/objective_work_plan_admission_p0/artifacts/objective_work_plan_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fullPath = if ([IO.Path]::IsPathRooted($ManifestPath)) { [IO.Path]::GetFullPath($ManifestPath) } else { [IO.Path]::GetFullPath((Join-Path $root $ManifestPath)) }
$manifest = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json
if ($manifest.profile -ne 'cantor-objective-work-plan-evidence-manifest/0.1' -or
    $manifest.evidence_manifest_uuid -ne '8c261188-25b4-407a-ba96-ca5b0992043a' -or
    $manifest.canonical_uuid -ne 'b8679e1a-8f98-448b-9a31-3eb24e31698e' -or
    $manifest.source_uuid -ne '521e430b-1371-44ad-8364-f1420fd43c25' -or
    $manifest.source_commit -notmatch '^[0-9a-f]{40}$') { throw 'manifest identity differs' }
$required = @(
    'crates/cantor_core/src/objective_work_plan.rs',
    'crates/cantor_core/tests/objective_work_plan.rs',
    'specifications/Cantor_Objective_Work_Plan_Admission_P0.sop',
    'proofs/Cantor_Objective_Work_Plan_Admission_P0_Proof.sop',
    'source_documents/2026-08-23_sop_bootable_self_working_cantor_current_thread/Cantor_SOP_Bootable_Self_Working_Agent_Target_Source.sop'
)
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$verified = 0
foreach ($artifact in @($manifest.artifacts)) {
    $relativePath = [string]$artifact.path
    if (-not $seen.Add($relativePath) -or [IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|/)\.\.(/|$)') { throw "duplicate or nonportable path: $relativePath" }
    $item = Get-Item -LiteralPath (Join-Path $root $relativePath) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "not one physical file: $relativePath" }
    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    if ([uint64]$artifact.bytes -ne [uint64]$item.Length -or ([string]$artifact.sha256).ToUpperInvariant() -ne $hash) { throw "artifact identity differs: $relativePath" }
    $verified++
}
foreach ($path in $required) { if (-not $seen.Contains($path)) { throw "required path absent: $path" } }
if ($manifest.non_authority_statement -notmatch 'no workspace admission' -or $manifest.non_authority_statement -notmatch 'capability grant') { throw 'non-authority differs' }
Write-Output "objective_work_plan_evidence_verified artifacts=$verified"
