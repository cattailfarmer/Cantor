[CmdletBinding()]
param([switch]$VerifyOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$manifestPath = Join-Path $root 'crates/cantor_ecosystem/evidence/sjs_commit_placement_acquisition_p3_evidence_manifest.json'
$artifactPaths = @(
    'source_documents/2026-08-24_cantor_sjs_commit_placement_acquisition_p3/Cantor_SJS_Commit_Placement_Acquisition_P3_Source.sop'
    'specifications/Cantor_SJS_Commit_Placement_Acquisition_P3.sop'
    'narrative/registries/Cantor_SJS_Commit_Placement_Acquisition_P3_Satisfaction_Signature.sop'
    'crates/cantor_ecosystem/src/sjs_commit_placement_acquisition.rs'
    'crates/cantor_ecosystem/src/lib.rs'
    'crates/cantor_ecosystem/src/bin/cantor-sjs-commit-placement-acquire.rs'
    'crates/cantor_ecosystem/tests/sjs_commit_placement_acquisition_physical.rs'
    'scripts/test_sjs_commit_placement_acquisition_p3.ps1'
    'scripts/build_sjs_commit_placement_acquisition_p3_evidence_manifest.ps1'
    'experiments/sjs_commit_placement_acquisition_p3/artifacts/controlled_physical_evidence.json'
    'experiments/sjs_commit_placement_acquisition_p3/artifacts/current_local_machine_record_unavailable.json'
)
$artifacts = @($artifactPaths | ForEach-Object {
    $item = Get-Item -LiteralPath (Join-Path $root $_)
    [ordered]@{ path = $_; bytes = $item.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash }
})
$manifest = [ordered]@{
    schema = 'cantor-sjs-commit-placement-acquisition-p3-evidence-manifest/0.1'
    canonical_uuid = '7602b617-05c5-459a-8a78-23bcd638e164'
    signature_uuid = '29c32998-d592-40f7-9481-6cba19634581'
    authority = 'observation_only'
    physical_contact = $true
    p2_modified = $false
    cargo_dependency_delta = $false
    product_git_mutation_commands = 0
    controlled_successes = 3
    controlled_refusals = 5
    live_state = 'machine_p2_record_unavailable'
    synthetic_live_successes = 0
    artifacts = $artifacts
}
$json = ([string]::Join("`n", @($manifest | ConvertTo-Json -Depth 8))).Replace("`r", '')
if ($VerifyOnly) {
    $current = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $currentJson = ([string]::Join("`n", @($current | ConvertTo-Json -Depth 8))).Replace("`r", '')
    if ($currentJson -cne $json) { throw 'P3 evidence manifest differs' }
    Write-Output "sjs_commit_placement_acquisition_p3_evidence_verified=true artifacts=$($artifacts.Count)"
    return
}
[IO.Directory]::CreateDirectory((Split-Path -Parent $manifestPath)) | Out-Null
[IO.File]::WriteAllText($manifestPath, ($json + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "sjs_commit_placement_acquisition_p3_evidence_written=$manifestPath artifacts=$($artifacts.Count)"
