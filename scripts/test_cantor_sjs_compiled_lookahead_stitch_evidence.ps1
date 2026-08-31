[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$CargoTargetDirectory = 'D:\CantorBuilds\cantor-lookahead-stitch-p0-focused-script',

    [switch]$Release,

    [switch]$VerifyExisting
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$utf8 = [Text.UTF8Encoding]::new($false)

function Remove-OneLineTerminator([string]$Value, [string]$Label) {
    if ($Value.EndsWith("`r`n", [StringComparison]::Ordinal)) {
        $body = $Value.Substring(0, $Value.Length - 2)
    }
    elseif ($Value.EndsWith("`n", [StringComparison]::Ordinal)) {
        $body = $Value.Substring(0, $Value.Length - 1)
    }
    else { throw "$Label lacks one CLI line terminator" }
    if ($body.Contains("`r") -or $body.Contains("`n")) { throw "$Label is not one compact JSON line" }
    return $body
}

function Invoke-CantorCargoBinary([string]$Binary, [string]$InputText) {
    $arguments = @('run', '--quiet', '--locked', '--offline', '-p', 'cantor_core', '--bin', $Binary)
    if ($Release) { $arguments += '--release' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = 'cargo'
    $start.Arguments = $arguments -join ' '
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
    $start.EnvironmentVariables['CARGO_BUILD_JOBS'] = '1'
    $start.EnvironmentVariables['RUST_MIN_STACK'] = '33554432'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw "failed to start $Binary" }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write($InputText)
    $process.StandardInput.Close()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw "$Binary refused with exit $($process.ExitCode): $($stderr.Trim())" }
    if (-not [String]::IsNullOrWhiteSpace($stderr)) { throw "$Binary emitted unexpected stderr: $($stderr.Trim())" }
    return $stdout
}

function Test-RetainedLasEvidence([string]$ArtifactDirectory) {
    $expectedNames = @('envelope.json', 'evidence_manifest.json', 'request.json', 'verification.json')
    $actualNames = @(Get-ChildItem -LiteralPath $ArtifactDirectory -File | ForEach-Object Name | Sort-Object)
    if (Compare-Object $expectedNames $actualNames) { throw 'retained artifact directory membership differs from the exact four-file set' }
    $retainedBundle = [ordered]@{
        request_file = [IO.File]::ReadAllText((Join-Path $ArtifactDirectory 'request.json'))
        envelope_file = [IO.File]::ReadAllText((Join-Path $ArtifactDirectory 'envelope.json'))
        verification_file = [IO.File]::ReadAllText((Join-Path $ArtifactDirectory 'verification.json'))
        manifest_file = [IO.File]::ReadAllText((Join-Path $ArtifactDirectory 'evidence_manifest.json'))
    }
    $retainedOutput = Invoke-CantorCargoBinary 'cantor-sjs-compiled-lookahead-stitch-verify' ($retainedBundle | ConvertTo-Json -Compress)
    $retainedBody = Remove-OneLineTerminator $retainedOutput 'retained verifier CLI output'
    if ([string]$retainedBundle.verification_file -cne "$retainedBody`n") { throw 'retained independent verifier output differs from retained verification file' }
    $verification = $retainedBody | ConvertFrom-Json
    if ($verification.status -cne 'verified_provider_free' -or
        $verification.input_class -cne 'synthetic_provider_free_fixture' -or
        $verification.stitch_count -ne 2 -or
        $verification.hint_count -ne 8 -or
        $verification.source_binding_count -ne 4 -or
        $verification.observation_count -ne 6 -or
        $verification.coordinate_count -ne 4 -or
        $verification.projection_count -ne 4 -or
        $verification.projected_inclusion_count -ne 5 -or
        $verification.activation_count -ne 2 -or
        $verification.fulfillment_count -ne 1 -or
        $verification.invalidation_count -ne 1 -or
        $verification.release_count -ne 0 -or
        $verification.refused_transition_count -ne 0 -or
        $verification.initial_boundary_count -ne 1 -or
        $verification.stop_boundary_count -ne 1 -or
        $verification.tool_result_boundary_count -ne 1 -or
        $verification.reentry_boundary_count -ne 1 -or
        $verification.maximum_projected_bytes -le 0 -or
        $verification.maximum_projected_bytes -gt 8192 -or
        $verification.execution_authorized -ne $false) { throw 'retained verification semantic account differs' }
    if (@($verification.effects.PSObject.Properties.Value | Where-Object { $_ -ne 0 }).Count -ne 0) { throw 'retained verification contains an effect' }
}

$outputFullPath = [IO.Path]::GetFullPath($OutputDirectory)
if ($VerifyExisting) {
    if (-not (Test-Path -LiteralPath $outputFullPath -PathType Container)) { throw "retained output directory is absent: $outputFullPath" }
    Test-RetainedLasEvidence $outputFullPath
    Write-Output "sjs_compiled_lookahead_stitch_evidence_passed mode=verify_existing files=4 replay=2 retained_replay=1 stitches=2 hints=8 sources=4 observations=6 coordinates=4 projections=4 inclusions=5 active=2 fulfilled=1 invalidated=1 refused=0 boundaries=1_each effects=0 output=$outputFullPath"
    return
}
if (Test-Path -LiteralPath $outputFullPath) { throw "output directory already exists; refusing overwrite: $outputFullPath" }
$outputParent = Split-Path -Parent $outputFullPath
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) { throw "output parent directory is absent: $outputParent" }

$bundleOutput = Invoke-CantorCargoBinary 'cantor-sjs-compiled-lookahead-stitch-fixture' ''
$bundleBody = Remove-OneLineTerminator $bundleOutput 'fixture CLI output'
$verificationOutput = Invoke-CantorCargoBinary 'cantor-sjs-compiled-lookahead-stitch-verify' $bundleOutput
$verificationBody = Remove-OneLineTerminator $verificationOutput 'verifier CLI output'
$bundle = $bundleBody | ConvertFrom-Json
$expectedProperties = @('request_file', 'envelope_file', 'verification_file', 'manifest_file')
$bundleProperties = @($bundle.PSObject.Properties.Name)
if ($bundleProperties.Count -ne 4 -or (Compare-Object ($bundleProperties | Sort-Object) ($expectedProperties | Sort-Object))) { throw 'fixture CLI evidence bundle properties differ' }
foreach ($name in $expectedProperties) {
    if ($bundle.$name -isnot [string] -or -not ([string]$bundle.$name).EndsWith("`n", [StringComparison]::Ordinal)) { throw "fixture evidence file is not one canonical LF-terminated string: $name" }
}
if ([string]$bundle.verification_file -cne "$verificationBody`n") { throw 'independent verifier output differs from retained verification file' }

$temporaryDirectory = Join-Path $outputParent ('.cantor-las-evidence-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
try {
    [IO.File]::WriteAllText((Join-Path $temporaryDirectory 'request.json'), [string]$bundle.request_file, $utf8)
    [IO.File]::WriteAllText((Join-Path $temporaryDirectory 'envelope.json'), [string]$bundle.envelope_file, $utf8)
    [IO.File]::WriteAllText((Join-Path $temporaryDirectory 'verification.json'), [string]$bundle.verification_file, $utf8)
    [IO.File]::WriteAllText((Join-Path $temporaryDirectory 'evidence_manifest.json'), [string]$bundle.manifest_file, $utf8)
    [IO.Directory]::Move($temporaryDirectory, $outputFullPath)
}
catch {
    if (Test-Path -LiteralPath $temporaryDirectory -PathType Container) { [IO.Directory]::Delete($temporaryDirectory, $true) }
    throw
}

Test-RetainedLasEvidence $outputFullPath
Write-Output "sjs_compiled_lookahead_stitch_evidence_passed mode=materialize files=4 replay=2 retained_replay=1 stitches=2 hints=8 sources=4 observations=6 coordinates=4 projections=4 inclusions=5 active=2 fulfilled=1 invalidated=1 refused=0 boundaries=1_each effects=0 output=$outputFullPath"
