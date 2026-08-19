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
$expectedReceiptSha256 = 'f284a021919a597368e13bed14852997dfa424bd524db145535ece93a345c5b8'
$expectedReceiptBytes = 3154
$expectedCommit = 'b4532cff5876d94b116bf7ab44ee5017d70ce5ea'
$expectedTree = '61f271169e803ed730f02b99390ac0114d890f17'
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
    'requires PowerShell 7 or later',
    'CARGO_INCREMENTAL',
    '-C link-arg=/Brepro',
    "'--locked'",
    "'--offline'",
    "'--verify'",
    "'--end-of-options'",
    '-WorkingDirectory $sourceA',
    '-WorkingDirectory $sourceB',
    'Assert-SafeCampaignRoot',
    'ReparsePoint',
    'Test-FileBytesEqual',
    "@('contract')",
    "@('field-digest'",
    "@('verify'",
    'ExchangeCount',
    'VerifiedReportSha256'
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
    'evox2_live_v5.json' = [ordered]@{
        file_sha256 = '7a2b934811beb4bff4917791f68ee5e2988574480443c212616cf950b133418e'
        terminal_state = 'completed'
        latch_status = 'admitted_for_attention'
        assurance = 'stored_provider_replay'
        exchange_count = 5
        verified_report_sha256 = 'ac2a07ac0b25267e16eefa68b56eb76ea08afd502ac9a555cc311de8eb0d204c'
    }
    'evox2_control_v5.json' = [ordered]@{
        file_sha256 = '2fa77676b688a7ee6893e56c9afec596a8fa5f197011c065bb645bb8a6bbb337'
        terminal_state = 'control_completed'
        latch_status = $null
        assurance = 'stored_provider_replay'
        exchange_count = 1
        verified_report_sha256 = '83a8450d88147acd0b93db1a7952955084d6736e9aa04e3e7a1d51d1bcbff599'
    }
    'evox2_hostile_boundary_v5.json' = [ordered]@{
        file_sha256 = 'e7109037bc3ad84d0c8e19501d6c234e858cd9d5d4599c13afd825306ac09b98'
        terminal_state = 'rejected'
        latch_status = $null
        assurance = 'stored_provider_replay'
        exchange_count = 4
        verified_report_sha256 = '6d57cd6fd9a0366b9f69105e30bc97be3e504bbd4af15968af3a9b47b931907e'
    }
}
if (@($receipt.behavior.reports).Count -ne $expectedReports.Count) {
    throw 'Pinned receipt report cardinality changed.'
}
foreach ($entry in $expectedReports.GetEnumerator()) {
    $record = @($receipt.behavior.reports | Where-Object report -CEQ $entry.Key)
    $latchMatches = $record.Count -eq 1 -and (
        ($null -eq $entry.Value.latch_status -and $null -eq $record[0].latch_status) -or
        ($null -ne $entry.Value.latch_status -and $record[0].latch_status -ceq $entry.Value.latch_status)
    )
    if ($record.Count -ne 1 -or
        $record[0].report_sha256 -cne $entry.Value.file_sha256 -or
        $record[0].terminal_state -cne $entry.Value.terminal_state -or
        -not $latchMatches -or
        $record[0].assurance -cne $entry.Value.assurance -or
        $record[0].exchange_count -ne $entry.Value.exchange_count -or
        $record[0].verified_report_sha256 -cne $entry.Value.verified_report_sha256) {
        throw "Pinned receipt report identity changed: $($entry.Key)"
    }
    $reportPath = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\$($entry.Key)"
    $actualReportSha256 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualReportSha256 -cne $entry.Value.file_sha256) {
        throw "Retained report bytes changed: $($entry.Key)"
    }
}

$anchorRecords = @(
    [ordered]@{
        relative_path = 'proofs\Cantor_Field_Attention_Reproducible_Windows_Build_P0_Git_Anchor.sop'
        anchor_uuid = 'cfba4a76-73e9-40f2-8a3e-60606ed5db14'
        tested_commit = '7f4e283edcadfc93af7aa69e246aae89f6b64e04'
        tested_tree = 'e50ef5d6ac5b6d21bc65e774ca100802972a77d5'
        receipt_commit = 'c762c2df407c9863f8ab3fa06f03da1f445b1271'
        receipt_tree = 'd919534566b9308681d59302841cba1ba323a4b2'
        anchor_commit = 'f4163b78559c054b88613173da2516d12ee2dd9f'
        anchor_tree = '2c48c46005f61a6e8b418214b677942a47104a8e'
    },
    [ordered]@{
        relative_path = 'proofs\Cantor_Field_Attention_Reproducible_Windows_Build_P0_Behavior_Hardening_Git_Anchor.sop'
        anchor_uuid = '604d2c84-ffbd-4a9f-8e41-21bd05ffc44d'
        tested_commit = '42ae3f7206469038c649936946b874516459ff0d'
        tested_tree = '633f023140d7f554c3952ca1c7c663888731edd9'
        receipt_commit = '8a92e2e6c396e3915c0d991dc74acfa979d37e91'
        receipt_tree = 'a6f3b1195f8d3b23256fd52744e953819e435a45'
        anchor_commit = '74d63f1f7959ee292c25aba69bb66b19713585f3'
        anchor_tree = '51241d0f042f0c03b0e7f5c1cc084e868c92eded'
    },
    [ordered]@{
        relative_path = 'proofs\Cantor_Field_Attention_Reproducible_Windows_Build_P0_Cleanup_Hardening_Git_Anchor.sop'
        anchor_uuid = 'e46a9d45-eaf8-49d6-bb56-5a4d8ceb4b3b'
        tested_commit = '3bba173c63d56dab1038260948f509081fec79e5'
        tested_tree = '8aa003a8b17452caab0b718f03821499cd002b31'
        receipt_commit = '9a2f692ef62f73ce09013ac0535f74bbad53653c'
        receipt_tree = '5935e0b66d38787f7995e408e7f36d856a911771'
        anchor_commit = 'a2e8a2c815b0c640371c33a963cfbe3c284bc8f3'
        anchor_tree = 'cf3a847bea461c0c8b5b4b14a40deb1bc0b56c64'
    },
    [ordered]@{
        relative_path = 'proofs\Cantor_Field_Attention_Reproducible_Windows_Build_P0_Toolchain_Verifier_Hardening_Git_Anchor.sop'
        anchor_uuid = '7848d802-65fa-414e-8290-e9221b528aed'
        tested_commit = '43b2f51642087e14247fa535d7201123deaee597'
        tested_tree = 'bb0d70f5957523cca45d1f9e817bf98d5bb41011'
        receipt_commit = 'ef5519b7d142907a8dd7c22eff285ba4c1bd8e5a'
        receipt_tree = '8a915e19fcf8694c71f22158ba8fe85854257c81'
        anchor_commit = 'cfa8cc957476d51a1878e4486dd074e92acd7eed'
        anchor_tree = 'a36c360a11eae3ef62d3bbf96429605e5ab32fc7'
    },
    [ordered]@{
        relative_path = 'proofs\Cantor_Field_Attention_Reproducible_Windows_Build_P0_PowerShell_Boundary_Git_Anchor.sop'
        anchor_uuid = '678f97b5-fc4e-4c67-b4f0-89f9b1582408'
        tested_commit = 'b4532cff5876d94b116bf7ab44ee5017d70ce5ea'
        tested_tree = '61f271169e803ed730f02b99390ac0114d890f17'
        receipt_commit = '5980c8ea03119f43d185342fc3f31eae1e889fdc'
        receipt_tree = '84ca0d480eed984a769aeeb44033b6511b2b9023'
        anchor_commit = '835c13c62aed6c28ce97e676a454fae1f965599b'
        anchor_tree = '8034a8b3424252d20b07ee63e338c90317efe52c'
    }
)

$currentBranch = (& git.exe -C $workspaceRoot branch --show-current 2>$null | Out-String).Trim()
$currentHead = (& git.exe -C $workspaceRoot rev-parse 'HEAD^{commit}' 2>$null | Out-String).Trim()
$upstream = (& git.exe -C $workspaceRoot rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or
    $currentBranch -cne 'codex/self-hosted-corpus' -or
    $currentHead -notmatch '^[0-9a-f]{40}$' -or
    $upstream -cne 'origin/codex/self-hosted-corpus') {
    throw 'The reproducibility anchor audit requires branch codex/self-hosted-corpus with upstream origin/codex/self-hosted-corpus.'
}

$previousAnchorCommit = $null
foreach ($anchor in $anchorRecords) {
    $anchorPath = Join-Path $workspaceRoot $anchor.relative_path
    $anchorText = Get-Content -LiteralPath $anchorPath -Raw
    foreach ($required in @(
        "[anchor_uuid] $($anchor.anchor_uuid)",
        "[tested_build_input_commit] is $($anchor.tested_commit)",
        "[tested_build_input_tree] is $($anchor.tested_tree)",
        "[receipt_and_proof_commit] is $($anchor.receipt_commit)",
        "[receipt_and_proof_tree] is $($anchor.receipt_tree)",
        '[branch] is codex/self-hosted-corpus',
        '[upstream] is origin/codex/self-hosted-corpus'
    )) {
        if (-not $anchorText.Contains($required)) {
            throw "Reproducibility Git anchor content changed or is incomplete: $($anchor.relative_path): $required"
        }
    }

    $resolvedTestedCommit = (& git.exe -C $workspaceRoot rev-parse "$($anchor.tested_commit)^{commit}" 2>$null | Out-String).Trim()
    $resolvedTestedTree = (& git.exe -C $workspaceRoot rev-parse "$($anchor.tested_commit)^{tree}" 2>$null | Out-String).Trim()
    $resolvedReceiptCommit = (& git.exe -C $workspaceRoot rev-parse "$($anchor.receipt_commit)^{commit}" 2>$null | Out-String).Trim()
    $resolvedReceiptTree = (& git.exe -C $workspaceRoot rev-parse "$($anchor.receipt_commit)^{tree}" 2>$null | Out-String).Trim()
    $resolvedAnchorCommit = (& git.exe -C $workspaceRoot rev-parse "$($anchor.anchor_commit)^{commit}" 2>$null | Out-String).Trim()
    $resolvedAnchorTree = (& git.exe -C $workspaceRoot rev-parse "$($anchor.anchor_commit)^{tree}" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or
        $resolvedTestedCommit -cne $anchor.tested_commit -or
        $resolvedTestedTree -cne $anchor.tested_tree -or
        $resolvedReceiptCommit -cne $anchor.receipt_commit -or
        $resolvedReceiptTree -cne $anchor.receipt_tree -or
        $resolvedAnchorCommit -cne $anchor.anchor_commit -or
        $resolvedAnchorTree -cne $anchor.anchor_tree) {
        throw "Reproducibility Git anchor object identity cannot be re-resolved: $($anchor.relative_path)"
    }

    & git.exe -C $workspaceRoot merge-base --is-ancestor $anchor.tested_commit $anchor.receipt_commit
    if ($LASTEXITCODE -ne 0) {
        throw "Receipt commit does not descend from its tested input: $($anchor.relative_path)"
    }
    & git.exe -C $workspaceRoot merge-base --is-ancestor $anchor.receipt_commit $anchor.anchor_commit
    if ($LASTEXITCODE -ne 0) {
        throw "Anchor commit does not descend from its receipt commit: $($anchor.relative_path)"
    }
    if ($null -ne $previousAnchorCommit) {
        & git.exe -C $workspaceRoot merge-base --is-ancestor $previousAnchorCommit $anchor.tested_commit
        if ($LASTEXITCODE -ne 0) {
            throw "Reproducibility Git anchor histories do not form one successor chain: $($anchor.relative_path)"
        }
    }
    & git.exe -C $workspaceRoot merge-base --is-ancestor $anchor.anchor_commit $upstream
    if ($LASTEXITCODE -ne 0) {
        throw "Configured upstream does not contain the anchor commit: $($anchor.relative_path)"
    }

    $anchorGitPath = $anchor.relative_path.Replace('\', '/')
    & git.exe -C $workspaceRoot cat-file -e "$($anchor.anchor_commit):$anchorGitPath"
    if ($LASTEXITCODE -ne 0) {
        throw "Anchor file is absent from its declared containing commit: $($anchor.relative_path)"
    }
    & git.exe -C $workspaceRoot diff --quiet $anchor.anchor_commit -- $anchorGitPath
    if ($LASTEXITCODE -ne 0) {
        throw "Current anchor bytes differ from the committed anchor: $($anchor.relative_path)"
    }
    $previousAnchorCommit = $anchor.anchor_commit
}

& git.exe -C $workspaceRoot merge-base --is-ancestor $anchorRecords[-1].anchor_commit $currentHead
if ($LASTEXITCODE -ne 0) {
    throw 'Current HEAD does not descend from the latest reproducibility Git anchor.'
}

[ordered]@{
    profile = 'cantor-field-attention-reproducible-windows-build-audit/0.1'
    result = 'passed_with_declared_boundaries'
    checks = 19
    source_sha256 = $sourceSha256
    receipt_sha256 = $receiptSha256
    source_commit = $receipt.source.commit
    artifact_sha256 = $receipt.artifact.sha256
    report_count = @($receipt.behavior.reports).Count
    git_anchor_count = $anchorRecords.Count
    latest_git_anchor_commit = $anchorRecords[-1].anchor_commit
    current_branch = $currentBranch
    current_head = $currentHead
    head_contains_latest_git_anchor = $true
    upstream = $upstream
    upstream_contains_all_git_anchors = $true
    tested_tracked_input_surface_current = $true
    provider_request_count = 0
    external_effects = 'none'
    claim = 'repository and receipt consistency only; fresh rebuild and cross-host reproducibility are not implied'
} | ConvertTo-Json -Depth 4
