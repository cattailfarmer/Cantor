[CmdletBinding()]
param(
    [string]$EvidencePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$gitExe = 'C:\Program Files\Git\mingw64\bin\git.exe'
$expectedGitSha256 = 'CAB4C4EEA1D869CF9F7BE73868DC9A90AD2DF1B1B673E5F8C8714A576C25EA96'
if (-not (Test-Path -LiteralPath $gitExe -PathType Leaf)) {
    throw "pinned Git executable is absent: $gitExe"
}
if ((Get-FileHash -LiteralPath $gitExe -Algorithm SHA256).Hash -ne $expectedGitSha256) {
    throw 'pinned Git executable SHA256 differs'
}

$cargo = (Get-Command cargo -ErrorAction Stop).Source
& $cargo build --quiet --offline --locked -p cantor_ecosystem --bin cantor-sjs-staged-diff-acquire
if ($LASTEXITCODE -ne 0) { throw 'acquisition binary build failed' }
$binary = Join-Path $root 'target\debug\cantor-sjs-staged-diff-acquire.exe'
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    $binary = Join-Path $root 'target\debug\cantor-sjs-staged-diff-acquire'
}
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'acquisition binary is absent after build'
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path $tempBase ("cantor-sjs-stage-p1-" + [guid]::NewGuid().ToString('N'))))
if (-not $fixtureRoot.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'temporary fixture root escaped system temp'
}
$repository = Join-Path $fixtureRoot 'repository'
$requestPath = Join-Path $fixtureRoot 'request.json'
$tamperPath = Join-Path $fixtureRoot 'tamper.json'

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $output = @(& $gitExe -C $repository @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Git fixture command failed: $($Arguments -join ' ') :: $($output -join ' ')"
    }
    return $output
}

function Write-Request {
    param(
        [string]$Path,
        [string]$Head,
        [string]$GitSha256 = $expectedGitSha256,
        [string[]]$GeneratedPaths = @('generated.json')
    )
    $request = [ordered]@{
        profile = 'cantor-sjs-staged-diff-acquisition/0.1'
        repository_id = 'cattailfarmer/cantor-fixture'
        branch_ref = 'refs/heads/main'
        expected_head = $Head
        object_format = 'sha1'
        repository_root = $repository
        git_executable = $gitExe
        expected_git_sha256 = $GitSha256
        generated_refresh_paths = @($GeneratedPaths)
        limits = [ordered]@{
            max_command_stdout_bytes = 1048576
            max_command_stderr_bytes = 65536
            max_diff_entries = 32
            max_path_bytes = 512
            max_blob_bytes = 1048576
            max_total_blob_bytes = 8388608
            max_index_bytes = 8388608
            max_git_commands = 128
        }
    }
    [IO.File]::WriteAllText($Path, ($request | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
}

function Invoke-ExpectedRefusal {
    param(
        [string]$Path,
        [string]$ExpectedCode
    )
    $output = @(& $binary --request $Path 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 2) {
        throw "expected refusal exit 2, got $exitCode"
    }
    $fault = ($output -join "`n") | ConvertFrom-Json
    if ($fault.code -ne $ExpectedCode) {
        throw "expected refusal $ExpectedCode, got $($fault.code)"
    }
}

$successes = 0
$refusals = 0
try {
    New-Item -ItemType Directory -Path $repository -Force | Out-Null
    Invoke-Git init --initial-branch=main | Out-Null
    [IO.File]::WriteAllText((Join-Path $repository 'modified.txt'), "before-modified`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $repository 'deleted.txt'), "before-deleted`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $repository 'old-name.txt'), "rename-content`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $repository 'generated.json'), "{`"generation`":0}`n", [Text.UTF8Encoding]::new($false))
    Invoke-Git add -- modified.txt deleted.txt old-name.txt generated.json | Out-Null
    $env:GIT_AUTHOR_DATE = '2000-01-01T00:00:00Z'
    $env:GIT_COMMITTER_DATE = '2000-01-01T00:00:00Z'
    Invoke-Git -c user.name='Cantor Fixture' -c user.email='cantor-fixture@example.invalid' commit -m baseline | Out-Null
    Remove-Item Env:\GIT_AUTHOR_DATE, Env:\GIT_COMMITTER_DATE -ErrorAction SilentlyContinue
    $head = (@(Invoke-Git rev-parse HEAD)[0]).Trim()

    [IO.File]::WriteAllText((Join-Path $repository 'modified.txt'), "after-modified`n", [Text.UTF8Encoding]::new($false))
    Remove-Item -LiteralPath (Join-Path $repository 'deleted.txt')
    Invoke-Git mv -- old-name.txt new-name.txt | Out-Null
    [IO.File]::WriteAllText((Join-Path $repository 'generated.json'), "{`"generation`":1}`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $repository 'added.txt'), "added-content`n", [Text.UTF8Encoding]::new($false))
    Invoke-Git add --all | Out-Null

    Write-Request -Path $requestPath -Head $head
    $receiptText = @(& $binary --request $requestPath 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "valid acquisition failed: $($receiptText -join ' ')" }
    $receipt = ($receiptText -join "`n") | ConvertFrom-Json
    $statuses = @($receipt.inventory.entries | ForEach-Object { $_.status } | Sort-Object)
    $expectedStatuses = @('added', 'deleted', 'generated_refresh', 'modified', 'renamed') | Sort-Object
    if (($statuses -join ',') -ne ($expectedStatuses -join ',')) { throw 'acquired status set differs' }
    if ($receipt.inventory.entries.Count -ne 5 -or
        $receipt.authority -ne 'observation_only' -or
        -not $receipt.physical_contact -or
        $receipt.index_before_sha256 -ne $receipt.index_after_sha256) {
        throw 'valid receipt semantic account differs'
    }
    $successes++

    $receiptReplay = @(& $binary --request $requestPath 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($receiptReplay -join "`n") -ne ($receiptText -join "`n")) {
        throw 'receipt replay differs'
    }
    $successes++

    $inventoryText = @(& $binary --request $requestPath --inventory-only 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'inventory-only acquisition failed' }
    $inventory = ($inventoryText -join "`n") | ConvertFrom-Json
    if ($inventory.inventory_sha256 -ne $receipt.inventory.inventory_sha256 -or $inventory.entries.Count -ne 5) {
        throw 'inventory-only result differs from receipt'
    }
    $successes++

    Write-Request -Path $tamperPath -Head $head -GitSha256 ('A' * 64)
    Invoke-ExpectedRefusal -Path $tamperPath -ExpectedCode executable
    $refusals++

    Write-Request -Path $tamperPath -Head ('a' * 40)
    Invoke-ExpectedRefusal -Path $tamperPath -ExpectedCode identity
    $refusals++

    Write-Request -Path $tamperPath -Head $head -GeneratedPaths @('added.txt')
    Invoke-ExpectedRefusal -Path $tamperPath -ExpectedCode request
    $refusals++

    $summary = [ordered]@{
        profile = 'cantor-sjs-staged-diff-acquisition-controlled-evidence/0.1'
        git_sha256 = $expectedGitSha256
        object_format = 'sha1'
        diff_entry_count = 5
        statuses = $expectedStatuses
        cli_successes = $successes
        cli_refusals = $refusals
        deterministic_replay = $true
        index_stable = $true
        authority = 'observation_only'
        physical_contact = $true
        mutation_authority = $false
        commit_envelope_authority = $false
    }
    if ($EvidencePath) {
        $resolvedEvidence = [IO.Path]::GetFullPath((Join-Path $root $EvidencePath))
        $resolvedRoot = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
        if (-not $resolvedEvidence.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'evidence path escaped repository root'
        }
        $parent = Split-Path -Parent $resolvedEvidence
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        $summaryJson = ([string]::Join("`n", @($summary | ConvertTo-Json -Depth 5))).Replace("`r", "")
        [IO.File]::WriteAllText($resolvedEvidence, ($summaryJson + "`n"), [Text.UTF8Encoding]::new($false))
    }
    Write-Output "sjs_staged_diff_acquisition_p1_tests=passed cli_successes=$successes cli_refusals=$refusals"
} finally {
    Remove-Item Env:\GIT_AUTHOR_DATE, Env:\GIT_COMMITTER_DATE -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $fixtureRoot) {
        $resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
        if (-not $resolvedFixture.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'refusing cleanup outside system temp'
        }
        Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
    }
}
