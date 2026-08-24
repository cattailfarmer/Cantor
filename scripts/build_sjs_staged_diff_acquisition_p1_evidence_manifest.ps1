[CmdletBinding()]
param([switch]$VerifyOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$manifestPath = Join-Path $root 'crates\cantor_ecosystem\evidence\sjs_staged_diff_acquisition_p1_evidence_manifest.json'
$controlledPath = Join-Path $root 'experiments\sjs_staged_diff_acquisition_p1\artifacts\controlled_capture_evidence.json'
$emptyPath = Join-Path $root 'experiments\sjs_staged_diff_acquisition_p1\artifacts\current_local_empty_index_evidence.json'

$controlled = Get-Content -LiteralPath $controlledPath -Raw | ConvertFrom-Json
if ($controlled.diff_entry_count -ne 5 -or
    $controlled.cli_successes -ne 3 -or
    $controlled.cli_refusals -ne 3 -or
    -not $controlled.deterministic_replay -or
    -not $controlled.index_stable -or
    $controlled.authority -ne 'observation_only' -or
    -not $controlled.physical_contact -or
    $controlled.mutation_authority -or
    $controlled.commit_envelope_authority) {
    throw 'controlled acquisition evidence semantic account differs'
}
$expectedStatuses = @('added', 'deleted', 'generated_refresh', 'modified', 'renamed')
if ((@($controlled.statuses) -join ',') -ne ($expectedStatuses -join ',')) {
    throw 'controlled acquisition evidence status set differs'
}

$empty = Get-Content -LiteralPath $emptyPath -Raw | ConvertFrom-Json
if ($empty.staged_entry_count -ne 0 -or
    $empty.outcome -ne 'refused' -or
    $empty.fault_code -ne 'inventory' -or
    $empty.synthetic_inventory -or
    $empty.authority -ne 'observation_only' -or
    -not $empty.physical_contact -or
    $empty.mutation_authority -or
    $empty.commit_envelope_authority) {
    throw 'local empty-index evidence semantic account differs'
}

$artifactPaths = @(
    'source_documents/2026-08-24_cantor_sjs_staged_diff_acquisition_p1/Cantor_SJS_Staged_Diff_Acquisition_P1_Source.sop',
    'specifications/Cantor_SJS_Staged_Diff_Acquisition_P1.sop',
    'narrative/registries/Cantor_SJS_Staged_Diff_Acquisition_P1_Satisfaction_Signature.sop',
    'crates/cantor_ecosystem/src/staged_diff_acquisition.rs',
    'crates/cantor_ecosystem/src/lib.rs',
    'crates/cantor_ecosystem/src/bin/cantor-sjs-staged-diff-acquire.rs',
    'crates/cantor_ecosystem/tests/staged_diff_acquisition_static.rs',
    'experiments/sjs_staged_diff_acquisition_p1/requests/current_local_empty_index_request.json',
    'experiments/sjs_staged_diff_acquisition_p1/artifacts/controlled_capture_evidence.json',
    'experiments/sjs_staged_diff_acquisition_p1/artifacts/current_local_empty_index_evidence.json',
    'scripts/test_sjs_staged_diff_acquisition_p1.ps1',
    'scripts/build_sjs_staged_diff_acquisition_p1_evidence_manifest.ps1'
)
$artifacts = @($artifactPaths | ForEach-Object {
    $item = Get-Item -LiteralPath (Join-Path $root $_)
    [ordered]@{
        path = $_
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
})
$manifest = [ordered]@{
    profile = 'cantor-sjs-staged-diff-acquisition-evidence/0.1'
    evidence_uuid = '2f4f1bf4-e7f8-4a4a-84f2-1fb4b7ae5a98'
    canonical_uuid = '8fd08ecd-72ba-495c-b172-e91d554a8224'
    signature_uuid = 'e2d19a2a-88cb-4f48-b5b0-896e1b743f54'
    git_executable_sha256 = 'CAB4C4EEA1D869CF9F7BE73868DC9A90AD2DF1B1B673E5F8C8714A576C25EA96'
    controlled_diff_entry_count = 5
    controlled_statuses = $expectedStatuses
    cli_successes = 3
    cli_refusals = 3
    current_local_staged_entry_count = 0
    current_local_outcome = 'refused'
    current_local_fault_code = 'inventory'
    deterministic_replay = $true
    index_stable = $true
    authority = 'observation_only'
    physical_contact = $true
    mutation_authority = $false
    commit_envelope_authority = $false
    cargo_dependency_delta = $false
    artifacts = $artifacts
}

$json = ([string]::Join("`n", @($manifest | ConvertTo-Json -Depth 6))).Replace("`r", "")
if ($VerifyOnly) {
    $current = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $currentJson = ([string]::Join("`n", @($current | ConvertTo-Json -Depth 6))).Replace("`r", "")
    if ($currentJson -ne $json) { throw 'staged acquisition evidence manifest differs' }
    Write-Output "sjs_staged_diff_acquisition_p1_evidence_verified=true artifacts=$($artifacts.Count)"
    return
}
$parent = Split-Path -Parent $manifestPath
New-Item -ItemType Directory -Path $parent -Force | Out-Null
[IO.File]::WriteAllText($manifestPath, ($json + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "sjs_staged_diff_acquisition_p1_evidence_written=$manifestPath artifacts=$($artifacts.Count)"
