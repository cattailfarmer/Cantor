[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$CargoTargetDirectory = 'D:\CantorBuilds\cantor-sjs-rsp-p0-evidence',

    [switch]$Release,

    [switch]$VerifyExisting
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
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
    [AllowNull()][string]$InputText
) {
    $arguments = @('run', '--quiet', '--locked', '--offline', '-p', 'cantor_ecosystem', '--bin', $Binary)
    if ($Release) { $arguments += '--release' }
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
    envelope_file = Join-Path $outputRoot 'envelope.json'
    verification_file = Join-Path $outputRoot 'verification.json'
    manifest_file = Join-Path $outputRoot 'evidence_manifest.json'
}

if (-not $VerifyExisting) {
    if (Test-Path -LiteralPath $outputRoot) {
        if (-not (Test-Path -LiteralPath $outputRoot -PathType Container) -or
            (Get-ChildItem -LiteralPath $outputRoot -Force | Measure-Object).Count -ne 0) {
            throw 'output directory must be absent or empty'
        }
    }
    [IO.Directory]::CreateDirectory($outputRoot) | Out-Null
    $bundleJson = Invoke-CantorBinary `
        'cantor-sjs-compiled-lookahead-repository-stitch-projection-fixture' `
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
    $value = [IO.File]::ReadAllText($paths[$name], $utf8)
    if (-not $value.EndsWith("`n", [StringComparison]::Ordinal) -or $value.Contains("`r")) {
        throw "retained $name framing differs"
    }
    $retained[$name] = $value
}
$retainedBundleJson = $retained | ConvertTo-Json -Compress -Depth 100
$verificationJson = Invoke-CantorBinary `
    'cantor-sjs-compiled-lookahead-repository-stitch-projection-verify' `
    $retainedBundleJson
$verification = $verificationJson | ConvertFrom-Json
if ($verification.status -cne 'verified_repository_selection_projected_to_stitch_only' -or
    [long]$verification.selected_count -ne 3 -or
    [long]$verification.stitch_count -ne 3 -or
    [long]$verification.hint_count -ne 3 -or
    [long]$verification.source_binding_count -ne 3 -or
    [long]$verification.observation_count -ne 3 -or
    [long]$verification.coordinate_count -ne 1 -or
    [long]$verification.projection_count -ne 1 -or
    [long]$verification.projected_inclusion_count -ne 3 -or
    [long]$verification.physical_input_account_count -ne 8 -or
    $verification.historical_physical_contact -ne $true -or
    $verification.execution_authorized -ne $false) {
    throw 'verification account differs'
}
$effectValues = $verification.effects.PSObject.Properties.Value
if (@($effectValues | Where-Object { [long]$_ -ne 0 }).Count -ne 0) {
    throw 'current projection effect account is nonzero'
}
$manifest = [IO.File]::ReadAllText($paths.manifest_file, $utf8) | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-sjs-lookahead-repository-stitch-projection-evidence/0.1' -or
    [long]$manifest.replay_count -ne 2 -or
    @($manifest.files.PSObject.Properties).Count -ne 3 -or
    [long]$manifest.selected_count -ne 3 -or
    [long]$manifest.stitch_count -ne 3 -or
    [long]$manifest.physical_input_account_count -ne 8 -or
    $manifest.historical_physical_contact -ne $true -or
    $manifest.execution_authorized -ne $false) {
    throw 'evidence manifest identity or account differs'
}
$manifestEffectValues = $manifest.effects.PSObject.Properties.Value
if (@($manifestEffectValues | Where-Object { [long]$_ -ne 0 }).Count -ne 0) {
    throw 'manifest current effect account is nonzero'
}

$mode = if ($VerifyExisting) { 'verify_existing' } else { 'generate_and_verify' }
$profile = if ($Release) { 'overflow_checked_release' } else { 'debug' }
Write-Output "sjs_compiled_lookahead_repository_stitch_projection_evidence_passed mode=$mode profile=$profile files=4 upstream_accounts=8 selected=3 stitches=3 hints=3 sources=3 observations=3 coordinates=1 projections=1 historical_physical_contact=true current_effects=0 execution_authorized=false output=$outputRoot"
