[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$sourceRelative = 'source_documents\2026-08-18_field_attention_reproducible_windows_build\Field_Attention_Reproducible_Windows_Build_Source_Selection.sop'
$manifestRelative = 'source_documents\2026-08-18_field_attention_reproducible_windows_build\Source_Document_Manifest.sop'
$canonicalRelative = 'specifications\Cantor_Field_Attention_Reproducible_Windows_Build_P0.sop'
$implementationRelative = 'scripts\test_cantor_field_attention_reproducible_windows_build.ps1'
$receiptRelative = 'experiments\cantor_field_cycle_p0\reproducible_windows_build_v1.json'

$sourcePath = Join-Path $workspaceRoot $sourceRelative
$manifestPath = Join-Path $workspaceRoot $manifestRelative
$canonicalPath = Join-Path $workspaceRoot $canonicalRelative
$implementationPath = Join-Path $workspaceRoot $implementationRelative
$receiptPath = Join-Path $workspaceRoot $receiptRelative

$expectedSourceSha256 = 'd03e4473b8250aea7c672360cda7c61ce95ccd2e70723bbc37572d65340870e7'
$expectedSourceBytes = 3669
$expectedReceiptSha256 = 'a9f99e1ea4aa83a3db4a203c12044fa1ecfd8f8b4720b393a9c84046023f857d'
$expectedReceiptBytes = 2761
$expectedCommit = 'd0618d96cfe2a274f56d25e933e5990b360d24ae'
$expectedTree = '23a2464bfbcca1cf9b2042a69cf18e62c640cd6d'
$expectedArtifactSha256 = '983cbd21308456d9a920f1dde98359d08e1d434ef5fe0133b3e9159653ae838b'

$sourceSha256 = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
$sourceBytes = (Get-Item -LiteralPath $sourcePath).Length
if ($sourceSha256 -cne $expectedSourceSha256 -or $sourceBytes -ne $expectedSourceBytes) {
    throw 'Preserved reproducible-build source identity changed.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw
if (-not $manifest.Contains("[source_sha256] is $sourceSha256") -or
    -not $manifest.Contains("[source_bytes] is $sourceBytes")) {
    throw 'Reproducible-build source manifest disagrees with the preserved source.'
}

$canonical = Get-Content -LiteralPath $canonicalPath -Raw
foreach ($required in @(
    'cantor-field-attention-reproducible-windows-build/0.1',
    'ad10f10f-d506-48ef-a805-f8b0a133766c',
    '3a8fea18-7ba7-410e-8f5a-2122c79e5591',
    'valid_for_local_effect_free_build_proof_only'
)) {
    if (-not $canonical.Contains($required)) {
        throw "Canonical reproducible-build signature is incomplete: $required"
    }
}

$implementation = Get-Content -LiteralPath $implementationPath -Raw
foreach ($required in @(
    'SOURCE_DATE_EPOCH',
    'CARGO_INCREMENTAL',
    '-C link-arg=/Brepro',
    "'--locked'",
    "'--offline'",
    'Assert-SafeCampaignRoot',
    'ReparsePoint',
    'Test-FileBytesEqual',
    "@('contract')",
    "@('field-digest'",
    "@('verify'"
)) {
    if (-not $implementation.Contains($required)) {
        throw "Reproducible-build implementation omitted a required control: $required"
    }
}

$receiptSha256 = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
$receiptBytes = (Get-Item -LiteralPath $receiptPath).Length
if ($receiptSha256 -cne $expectedReceiptSha256 -or $receiptBytes -ne $expectedReceiptBytes) {
    throw 'Pinned reproducible-build receipt identity changed.'
}
$receiptRaw = Get-Content -LiteralPath $receiptPath -Raw
if ($receiptRaw.Contains('cantor-field-cycle-repro-') -or $receiptRaw.Contains($workspaceRoot)) {
    throw 'Pinned receipt exposes a temporary or workspace path.'
}
$receipt = $receiptRaw | ConvertFrom-Json
if ($receipt.profile -cne 'cantor-field-attention-reproducible-windows-build/0.1' -or
    $receipt.result -cne 'passed' -or
    $receipt.source.commit -cne $expectedCommit -or
    $receipt.source.tree -cne $expectedTree -or
    $receipt.source.source_root_count -ne 2 -or
    $receipt.build.command -cne 'cargo build --release -p cantor_field_cycle --locked --offline' -or
    $receipt.build.cargo_incremental -ne 0 -or
    $receipt.build.rustflags -cne '-C link-arg=/Brepro' -or
    $receipt.build.target_root_count -ne 2 -or
    $receipt.toolchain.rustc_version -cne 'rustc 1.96.0 (ac68faa20 2026-05-25)' -or
    $receipt.toolchain.rustc_commit_hash -cne 'ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96' -or
    $receipt.toolchain.rustc_commit_date -cne '2026-05-25' -or
    $receipt.toolchain.rustc_release -cne '1.96.0' -or
    $receipt.artifact.sha256 -cne $expectedArtifactSha256 -or
    $receipt.artifact.bytes -ne 2840576 -or
    $receipt.artifact.byte_equal -ne $true -or
    $receipt.behavior.field_digest -cne '136955ea1f1931de88c22cef392377f3a1fa4e6d4bd1de53450cb7e1f598c8e0' -or
    $receipt.behavior.verifier_invocations -ne 6 -or
    $receipt.behavior.provider_request_count -ne 0 -or
    $receipt.cleanup.artifacts_retained -ne $false -or
    $receipt.cleanup.temporary_paths_disclosed -ne $false) {
    throw 'Pinned reproducible-build receipt violates the canonical profile.'
}

$resolvedCommit = (& git.exe -C $workspaceRoot rev-parse "$expectedCommit^{commit}" 2>$null | Out-String).Trim()
$resolvedTree = (& git.exe -C $workspaceRoot rev-parse "$expectedCommit^{tree}" 2>$null | Out-String).Trim()
$resolvedEpoch = (& git.exe -C $workspaceRoot show -s '--format=%ct' $expectedCommit 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or
    $resolvedCommit -cne $expectedCommit -or
    $resolvedTree -cne $expectedTree -or
    $resolvedEpoch -cne ([string] $receipt.source.commit_timestamp)) {
    throw 'Pinned reproducible-build Git commit tree or epoch cannot be re-resolved exactly.'
}

$priorPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $diffArguments = @(
        '-C', $workspaceRoot, 'diff', '--quiet', $expectedCommit, '--',
        'Cargo.toml', 'Cargo.lock', '.cargo', 'rust-toolchain', 'rust-toolchain.toml',
        'crates/cantor_field_cycle',
        'scripts/test_cantor_field_attention_reproducible_windows_build.ps1'
    )
    $sourceDiff = & git.exe @diffArguments 2>&1
    $sourceDiffExit = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $priorPreference
}
if ($sourceDiffExit -ne 0) {
    $detail = ($sourceDiff -join [Environment]::NewLine).Trim()
    throw "Pinned reproducible-build input surface is stale relative to the tested commit. $detail"
}

$expectedReports = [ordered]@{
    'evox2_live_v5.json' = '7a2b934811beb4bff4917791f68ee5e2988574480443c212616cf950b133418e'
    'evox2_control_v5.json' = '2fa77676b688a7ee6893e56c9afec596a8fa5f197011c065bb645bb8a6bbb337'
    'evox2_hostile_boundary_v5.json' = 'e7109037bc3ad84d0c8e19501d6c234e858cd9d5d4599c13afd825306ac09b98'
}
if (@($receipt.behavior.reports).Count -ne $expectedReports.Count) {
    throw 'Pinned receipt report cardinality changed.'
}
foreach ($entry in $expectedReports.GetEnumerator()) {
    $record = @($receipt.behavior.reports | Where-Object report -CEQ $entry.Key)
    if ($record.Count -ne 1 -or $record[0].report_sha256 -cne $entry.Value) {
        throw "Pinned receipt report identity changed: $($entry.Key)"
    }
    $reportPath = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\$($entry.Key)"
    $actualReportSha256 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualReportSha256 -cne $entry.Value) {
        throw "Retained report bytes changed: $($entry.Key)"
    }
}

[ordered]@{
    profile = 'cantor-field-attention-reproducible-windows-build-audit/0.1'
    result = 'passed_with_declared_boundaries'
    checks = 12
    source_sha256 = $sourceSha256
    receipt_sha256 = $receiptSha256
    source_commit = $receipt.source.commit
    artifact_sha256 = $receipt.artifact.sha256
    report_count = @($receipt.behavior.reports).Count
    tested_tracked_input_surface_current = $true
    provider_request_count = 0
    external_effects = 'none'
    claim = 'repository and receipt consistency only; fresh rebuild and cross-host reproducibility are not implied'
} | ConvertTo-Json -Depth 4
