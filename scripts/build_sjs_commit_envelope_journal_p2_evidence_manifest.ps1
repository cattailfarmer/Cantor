[CmdletBinding()]
param([switch]$VerifyOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$manifestPath = Join-Path $root 'crates\cantor_ecosystem\evidence\sjs_commit_envelope_journal_p2_evidence_manifest.json'
$controlledPath = Join-Path $root 'experiments\sjs_commit_envelope_journal_p2\artifacts\controlled_verification_evidence.json'
$controlled = Get-Content -LiteralPath $controlledPath -Raw | ConvertFrom-Json

if ($controlled.profile -cne 'cantor-sjs-commit-envelope-journal-p2-controlled-evidence/0.1' -or
    [int]$controlled.fixture_count -ne 2 -or
    [int]$controlled.one_link_count -ne 1 -or
    [int]$controlled.two_link_count -ne 2 -or
    [int]$controlled.one_open_tip_count -ne 1 -or
    [int]$controlled.two_open_tip_count -ne 1 -or
    [int]$controlled.cli_successes -ne 3 -or
    [int]$controlled.cli_refusals -ne 3 -or
    -not [bool]$controlled.deterministic_replay -or
    $controlled.authority -cne 'verification_only' -or
    $controlled.placement_authority -cne 'supplied_data' -or
    [bool]$controlled.physical_contact -or
    [int]$controlled.git_process_count -ne 0 -or
    [int]$controlled.mutation_count -ne 0) {
    throw 'controlled journal evidence differs'
}

$artifactPaths = @(
    'source_documents/2026-08-24_cantor_sjs_commit_envelope_journal_p2/Cantor_SJS_Commit_Envelope_Journal_P2_Source.sop',
    'specifications/Cantor_SJS_Commit_Envelope_Journal_P2.sop',
    'narrative/registries/Cantor_SJS_Commit_Envelope_Journal_P2_Satisfaction_Signature.sop',
    'crates/cantor_ecosystem/src/sjs_commit_envelope_journal.rs',
    'crates/cantor_ecosystem/src/lib.rs',
    'crates/cantor_ecosystem/src/bin/cantor-sjs-commit-envelope-journal-verify.rs',
    'crates/cantor_ecosystem/examples/build_sjs_commit_envelope_journal_p2_fixture.rs',
    'crates/cantor_ecosystem/tests/sjs_commit_envelope_journal_static.rs',
    'fixtures/sjs_commit_envelope_journal_p2/one_link.json',
    'fixtures/sjs_commit_envelope_journal_p2/two_link.json',
    'experiments/sjs_commit_envelope_journal_p2/artifacts/controlled_verification_evidence.json',
    'scripts/build_sjs_commit_envelope_journal_p2_fixtures.ps1',
    'scripts/test_sjs_commit_envelope_journal_p2.ps1',
    'scripts/build_sjs_commit_envelope_journal_p2_evidence_manifest.ps1'
)
$artifacts = @($artifactPaths | ForEach-Object {
    $item = Get-Item -LiteralPath (Join-Path $root $_)
    [ordered]@{ path = $_; bytes = [uint64]$item.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash }
})
$manifest = [ordered]@{
    schema = 'cantor-sjs-commit-envelope-journal-p2-evidence-manifest/0.1'
    canonical_uuid = '27ac629d-a885-49f1-85ca-14c52c2f3b0e'
    signature_uuid = '68b2e626-f5e1-4ce1-a631-1784e24caa15'
    authority = 'verification_only'
    physical_contact = $false
    placement_authority = 'supplied_data'
    one_head_lag = $true
    exact_open_tip_count = 1
    p0_modified = $false
    cargo_dependency_delta = $false
    artifacts = $artifacts
}
$json = ([string]::Join("`n", @($manifest | ConvertTo-Json -Depth 8))).Replace("`r", "")
if ($VerifyOnly) {
    $current = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $currentJson = ([string]::Join("`n", @($current | ConvertTo-Json -Depth 8))).Replace("`r", "")
    if ($currentJson -cne $json) { throw 'journal evidence manifest differs' }
    Write-Output "sjs_commit_envelope_journal_p2_evidence_verified=true artifacts=$($artifacts.Count)"
    return
}
[IO.Directory]::CreateDirectory((Split-Path -Parent $manifestPath)) | Out-Null
[IO.File]::WriteAllText($manifestPath, ($json + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "sjs_commit_envelope_journal_p2_evidence_written=$manifestPath artifacts=$($artifacts.Count)"
