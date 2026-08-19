[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Cantor reproducible-build boundary tests require Windows and PowerShell 7 or later.'
}
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Invoke-CapturedProcess {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [string[]] $ArgumentList,
        [Parameter(Mandatory)] [string] $WorkingDirectory
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        [void] $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Failed to start boundary-test process: $FilePath"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut = $stdoutTask.GetAwaiter().GetResult()
            StdErr = $stderrTask.GetAwaiter().GetResult()
        }
    }
    finally {
        $process.Dispose()
    }
}

function Get-CampaignRootCount {
    param([Parameter(Mandatory)] [string] $TargetRoot)

    if (-not (Test-Path -LiteralPath $TargetRoot)) {
        return 0
    }
    return @(Get-ChildItem -LiteralPath $TargetRoot -Directory -Filter 'cantor-field-cycle-repro-*').Count
}

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$targetRoot = Join-Path $workspaceRoot 'target'
$proofTool = Join-Path $PSScriptRoot 'test_cantor_field_attention_reproducible_windows_build.ps1'
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$powerShell7 = (Get-Command pwsh.exe -ErrorAction Stop).Source
if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
    throw 'Windows PowerShell 5.1 executable is unavailable for the governed refusal test.'
}

$initialCount = Get-CampaignRootCount -TargetRoot $targetRoot
$legacy = Invoke-CapturedProcess -FilePath $windowsPowerShell -WorkingDirectory $workspaceRoot -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $proofTool
)
$afterLegacyCount = Get-CampaignRootCount -TargetRoot $targetRoot
if ($legacy.ExitCode -eq 0 -or
    -not $legacy.StdErr.Contains('requires PowerShell 7 or later') -or
    $legacy.StdOut -match '"result"\s*:\s*"passed"' -or
    $afterLegacyCount -ne $initialCount) {
    throw 'Windows PowerShell 5.1 refusal boundary failed.'
}

$optionLike = Invoke-CapturedProcess -FilePath $powerShell7 -WorkingDirectory $workspaceRoot -ArgumentList @(
    '-NoProfile', '-File', $proofTool, '-SourceRevision', '--help'
)
$finalCount = Get-CampaignRootCount -TargetRoot $targetRoot
if ($optionLike.ExitCode -eq 0 -or
    -not $optionLike.StdErr.Contains('rev-parse --verify --end-of-options') -or
    -not $optionLike.StdErr.Contains('Needed a single revision') -or
    $optionLike.StdOut -match '"result"\s*:\s*"passed"' -or
    $finalCount -ne $initialCount) {
    throw 'Option-like Git revision refusal boundary failed.'
}

[ordered]@{
    profile = 'cantor-field-attention-reproducible-windows-build-boundary-tests/0.1'
    status = 'passed'
    windows_powershell_5_1 = [ordered]@{
        exit_nonzero = $true
        named_version_refusal = $true
        passed_receipt_emitted = $false
        campaign_root_delta = $afterLegacyCount - $initialCount
    }
    option_like_revision = [ordered]@{
        value = '--help'
        exit_nonzero = $true
        git_verify_end_of_options_visible = $true
        passed_receipt_emitted = $false
        campaign_root_delta = $finalCount - $afterLegacyCount
    }
    provider_request_count = 0
    external_effects = 'one validated temporary campaign root created and removed during option-like revision refusal'
    authority = 'negative local proof only; no fresh build inference remote deployment signing or P1 authority'
} | ConvertTo-Json -Depth 5
