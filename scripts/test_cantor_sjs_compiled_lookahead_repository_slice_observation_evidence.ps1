[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$GitExecutable = 'C:\Program Files\Git\cmd\git.exe',

    [string]$CargoTargetDirectory = 'D:\CantorBuilds\cantor-sjs-rso-p0-evidence',

    [switch]$Release,

    [switch]$VerifyExisting
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$gitPath = [IO.Path]::GetFullPath($GitExecutable)
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path $outputRoot '.fixture_repository'))
$utf8 = [Text.UTF8Encoding]::new($false)

function ConvertTo-ProcessArgument([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Remove-OneLineTerminator([string]$Value, [string]$Label) {
    if ($Value.EndsWith("`r`n", [StringComparison]::Ordinal)) {
        $body = $Value.Substring(0, $Value.Length - 2)
    }
    elseif ($Value.EndsWith("`n", [StringComparison]::Ordinal)) {
        $body = $Value.Substring(0, $Value.Length - 1)
    }
    else { throw "$Label lacks one CLI line terminator" }
    if ($body.Contains("`r") -or $body.Contains("`n")) {
        throw "$Label is not one compact JSON line"
    }
    return $body
}

function Invoke-CantorBinary(
    [string]$Binary,
    [string[]]$BinaryArguments,
    [AllowNull()][string]$InputText
) {
    $arguments = @('run', '--quiet', '--locked', '--offline', '-p', 'cantor_ecosystem', '--bin', $Binary)
    if ($Release) { $arguments += '--release' }
    if ($BinaryArguments.Count -gt 0) {
        $arguments += '--'
        $arguments += $BinaryArguments
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'cargo'
    $start.Arguments = (($arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' ')
    $start.WorkingDirectory = $repositoryRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($start.PSObject.Properties.Name -contains 'StandardInputEncoding') { $start.StandardInputEncoding = $utf8 }
    if ($start.PSObject.Properties.Name -contains 'StandardOutputEncoding') { $start.StandardOutputEncoding = $utf8 }
    if ($start.PSObject.Properties.Name -contains 'StandardErrorEncoding') { $start.StandardErrorEncoding = $utf8 }
    $start.EnvironmentVariables['CARGO_TARGET_DIR'] = [IO.Path]::GetFullPath($CargoTargetDirectory)
    if ($Release) { $start.EnvironmentVariables['CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS'] = 'true' }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw "failed to start $Binary" }
    if ($null -ne $InputText) { $process.StandardInput.Write($InputText) }
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "$Binary failed exit=$($process.ExitCode): $stderr"
    }
    return Remove-OneLineTerminator $stdout $Binary
}

$paths = [ordered]@{
    request_file = Join-Path $outputRoot 'request.json'
    receipt_file = Join-Path $outputRoot 'receipt.json'
    verification_file = Join-Path $outputRoot 'verification.json'
    manifest_file = Join-Path $outputRoot 'evidence_manifest.json'
}

if (-not $VerifyExisting) {
    [IO.Directory]::CreateDirectory($outputRoot) | Out-Null
    $expectedPrefix = $outputRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $fixtureRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($fixtureRoot) -cne '.fixture_repository') {
        throw 'fixture cleanup target escaped the output directory'
    }
    if (Test-Path -LiteralPath $fixtureRoot) {
        throw 'fixture repository already exists; refusing destructive reuse'
    }
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    try {
        $bundleJson = Invoke-CantorBinary `
            'cantor-sjs-compiled-lookahead-repository-slice-observation-fixture' `
            @('--repository-root', $fixtureRoot, '--git-executable', $gitPath) `
            $null
        $bundle = $bundleJson | ConvertFrom-Json
        foreach ($name in $paths.Keys) {
            $value = [string]$bundle.$name
            if (-not $value.EndsWith("`n", [StringComparison]::Ordinal) -or $value.Contains("`r")) {
                throw "$name framing differs"
            }
            [IO.File]::WriteAllText($paths[$name], $value, $utf8)
        }
    }
    finally {
        if (Test-Path -LiteralPath $fixtureRoot) {
            $resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
            if ($resolvedFixture -ne $fixtureRoot -or
                -not $resolvedFixture.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($resolvedFixture) -cne '.fixture_repository') {
                throw 'resolved fixture cleanup target differs'
            }
            Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
        }
    }
}

foreach ($name in $paths.Keys) {
    if (-not (Test-Path -LiteralPath $paths[$name] -PathType Leaf)) {
        throw "retained $name is absent"
    }
}
if ((Get-ChildItem -LiteralPath $outputRoot -Force | Measure-Object).Count -ne 4) {
    throw 'retained evidence directory does not contain exactly four files'
}

$retained = [ordered]@{}
foreach ($name in $paths.Keys) {
    $retained[$name] = [IO.File]::ReadAllText($paths[$name], $utf8)
}
$retainedBundleJson = $retained | ConvertTo-Json -Compress -Depth 100
$verificationJson = Invoke-CantorBinary `
    'cantor-sjs-compiled-lookahead-repository-slice-observation-verify' `
    @() `
    $retainedBundleJson
$verification = $verificationJson | ConvertFrom-Json
if ($verification.status -cne 'verified_exact_commit_tree_observation' -or
    [long]$verification.account_count -ne 8 -or
    [long]$verification.unique_blob_count -ne 8 -or
    [long]$verification.total_blob_bytes -ne 208 -or
    [long]$verification.command_count -ne 23 -or
    $verification.physical_contact -ne $true -or
    $verification.execution_authorized -ne $false) {
    throw 'verification account differs'
}
if ($verification.parent_verification.status -cne 'verified_provider_free_repository_candidate_compilation' -or
    [long]$verification.parent_verification.record_count -ne 8 -or
    [long]$verification.parent_verification.obligation_count -ne 6 -or
    [long]$verification.parent_verification.coverage_edge_count -ne 12 -or
    [long]$verification.parent_verification.admitted_subset_count -ne 92 -or
    [long]$verification.parent_verification.selected_count -ne 3 -or
    [long]$verification.parent_verification.rejected_count -ne 5 -or
    [long]$verification.parent_verification.dominated_count -ne 1 -or
    [long]$verification.parent_verification.uncovered_count -ne 0 -or
    $verification.parent_verification.execution_authorized -ne $false) {
    throw 'parent verification account differs'
}

$effects = $verification.effects
if ($effects.read_only_filesystem_observation -ne $true -or
    $effects.read_only_git_process_observation -ne $true) {
    throw 'read-only physical effects are absent'
}
$deniedEffectNames = @(
    'repository_write', 'index_write', 'worktree_write', 'network_contact', 'provider_contact',
    'model_inference', 'prompt_stitch', 'secret_access', 'permission_activation',
    'remote_hardware_contact', 'external_action'
)
foreach ($name in $deniedEffectNames) {
    if ($effects.$name -ne $false) { throw "denied effect is true: $name" }
}
$parentEffectValues = $verification.parent_verification.effects.PSObject.Properties.Value
if (@($parentEffectValues | Where-Object { [long]$_ -ne 0 }).Count -ne 0) {
    throw 'parent effect account is nonzero'
}

$manifest = [IO.File]::ReadAllText($paths.manifest_file, $utf8) | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-sjs-lookahead-repository-slice-observation-evidence/0.1' -or
    [long]$manifest.replay_count -ne 2 -or
    @($manifest.files.PSObject.Properties).Count -ne 3) {
    throw 'evidence manifest identity differs'
}

$mode = if ($VerifyExisting) { 'verify_existing' } else { 'generate_and_verify' }
$profile = if ($Release) { 'overflow_checked_release' } else { 'debug' }
Write-Output "sjs_compiled_lookahead_repository_slice_observation_evidence_passed mode=$mode profile=$profile files=4 physical_replay=2 accounts=8 unique_blobs=8 total_blob_bytes=208 commands=23 parent_subsets=92 selected=3 rejected=5 dominated=1 uncovered=0 execution_authorized=false output=$outputRoot"
