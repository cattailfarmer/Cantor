[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$CargoTargetDirectory = 'D:\CantorBuilds\cantor-lookahead-repository-candidate-p0-evidence',

    [switch]$Release,

    [switch]$VerifyExisting
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
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

function Invoke-CantorBinary([string]$Binary, [AllowNull()][string]$InputText) {
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
    if ($Release) { $start.EnvironmentVariables['RUSTFLAGS'] = '-C overflow-checks=yes' }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw "failed to start $Binary" }
    if ($null -ne $InputText) { $process.StandardInput.Write($InputText) }
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "$Binary failed exit=$($process.ExitCode): $stderr" }
    return Remove-OneLineTerminator $stdout $Binary
}

$paths = [ordered]@{
    request_file = Join-Path $outputRoot 'request.json'
    envelope_file = Join-Path $outputRoot 'envelope.json'
    verification_file = Join-Path $outputRoot 'verification.json'
    manifest_file = Join-Path $outputRoot 'evidence_manifest.json'
}

if (-not $VerifyExisting) {
    [IO.Directory]::CreateDirectory($outputRoot) | Out-Null
    $bundleJson = Invoke-CantorBinary 'cantor-sjs-compiled-lookahead-repository-candidate-fixture' $null
    $bundle = $bundleJson | ConvertFrom-Json
    foreach ($name in $paths.Keys) {
        $value = [string]$bundle.$name
        if (-not $value.EndsWith("`n", [StringComparison]::Ordinal) -or $value.Contains("`r")) { throw "$name framing differs" }
        [IO.File]::WriteAllText($paths[$name], $value, $utf8)
    }
}

foreach ($name in $paths.Keys) {
    if (-not (Test-Path -LiteralPath $paths[$name] -PathType Leaf)) { throw "retained $name is absent" }
}

$retained = [ordered]@{}
foreach ($name in $paths.Keys) { $retained[$name] = [IO.File]::ReadAllText($paths[$name], $utf8) }
$retainedBundleJson = $retained | ConvertTo-Json -Compress -Depth 100
$verificationJson = Invoke-CantorBinary 'cantor-sjs-compiled-lookahead-repository-candidate-verify' $retainedBundleJson
$verification = $verificationJson | ConvertFrom-Json
if ($verification.status -cne 'verified_provider_free_repository_candidate_compilation' -or
    [long]$verification.record_count -ne 8 -or
    [long]$verification.obligation_count -ne 6 -or
    [long]$verification.coverage_edge_count -ne 12 -or
    [long]$verification.admitted_subset_count -ne 92 -or
    [long]$verification.selected_count -ne 3 -or
    [long]$verification.rejected_count -ne 5 -or
    [long]$verification.dominated_count -ne 1 -or
    [long]$verification.uncovered_count -ne 0 -or
    $verification.execution_authorized -ne $false) { throw 'verification account differs' }

$effectValues = $verification.effects.PSObject.Properties.Value
if (@($effectValues | Where-Object { [long]$_ -ne 0 }).Count -ne 0) { throw 'effect account is nonzero' }

$mode = if ($VerifyExisting) { 'verify_existing' } else { 'generate_and_verify' }
$profile = if ($Release) { 'overflow_checked_release' } else { 'debug' }
Write-Output "sjs_compiled_lookahead_repository_candidate_evidence_passed mode=$mode profile=$profile files=4 replay=2 records=8 obligations=6 edges=12 subsets=92 selected=3 rejected=5 dominated=1 uncovered=0 execution_authorized=false effects=0 output=$outputRoot"
