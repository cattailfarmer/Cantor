[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RequestPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$CargoTargetDirectory = 'D:\CantorBuilds\cantor-nhlp-p0-focused-script',

    [switch]$Release
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
    else {
        throw "$Label lacks one CLI line terminator"
    }
    if ($body.Contains("`r") -or $body.Contains("`n")) {
        throw "$Label is not one compact JSON line"
    }
    return $body
}

function Invoke-CantorCargoBinary([string]$Binary, [string]$InputText) {
    $arguments = @(
        'run', '--quiet', '--locked', '--offline',
        '-p', 'cantor_core', '--bin', $Binary
    )
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
    $start.StandardInputEncoding = $utf8
    $start.StandardOutputEncoding = $utf8
    $start.StandardErrorEncoding = $utf8
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
    if ($process.ExitCode -ne 0) {
        throw "$Binary refused with exit $($process.ExitCode): $($stderr.Trim())"
    }
    if (-not [String]::IsNullOrWhiteSpace($stderr)) {
        throw "$Binary emitted unexpected stderr: $($stderr.Trim())"
    }
    return $stdout
}

if (-not (Test-Path -LiteralPath $RequestPath -PathType Leaf)) {
    throw "supplied signed request fixture is absent: $RequestPath"
}
$requestFullPath = (Get-Item -LiteralPath $RequestPath).FullName
$requestBytes = (Get-Item -LiteralPath $requestFullPath).Length
if ($requestBytes -gt 1048578) {
    throw "supplied signed request fixture exceeds the bounded CLI input"
}
$outputFullPath = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputFullPath) {
    throw "output directory already exists; refusing overwrite: $outputFullPath"
}
$outputParent = Split-Path -Parent $outputFullPath
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    throw "output parent directory is absent: $outputParent"
}

$request = [IO.File]::ReadAllText($requestFullPath)
$bundleOutput = Invoke-CantorCargoBinary 'cantor-nested-inner-launch-plan-fixture' $request
$bundleBody = Remove-OneLineTerminator $bundleOutput 'fixture CLI output'
$verificationOutput = Invoke-CantorCargoBinary 'cantor-nested-inner-launch-plan-evidence-verify' $bundleOutput
$verificationBody = Remove-OneLineTerminator $verificationOutput 'verifier CLI output'

$bundle = $bundleBody | ConvertFrom-Json
$bundleProperties = @($bundle.PSObject.Properties.Name)
$expectedProperties = @('request_file', 'envelope_file', 'verification_file', 'manifest_file')
if ($bundleProperties.Count -ne 4 -or (Compare-Object ($bundleProperties | Sort-Object) ($expectedProperties | Sort-Object))) {
    throw 'fixture CLI evidence bundle properties differ'
}
foreach ($name in $expectedProperties) {
    if ($bundle.$name -isnot [string] -or -not ([string]$bundle.$name).EndsWith("`n", [StringComparison]::Ordinal)) {
        throw "fixture evidence file is not one canonical LF-terminated string: $name"
    }
}
if ([string]$bundle.verification_file -cne "$verificationBody`n") {
    throw 'independent verifier output differs from retained verification file'
}

$temporaryDirectory = Join-Path $outputParent (".cantor-nhlp-evidence-" + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
try {
    [IO.File]::WriteAllText((Join-Path $temporaryDirectory 'request.json'), [string]$bundle.request_file, $utf8)
    [IO.File]::WriteAllText((Join-Path $temporaryDirectory 'envelope.json'), [string]$bundle.envelope_file, $utf8)
    [IO.File]::WriteAllText((Join-Path $temporaryDirectory 'verification.json'), [string]$bundle.verification_file, $utf8)
    [IO.File]::WriteAllText((Join-Path $temporaryDirectory 'evidence_manifest.json'), [string]$bundle.manifest_file, $utf8)
    [IO.Directory]::Move($temporaryDirectory, $outputFullPath)
}
catch {
    if (Test-Path -LiteralPath $temporaryDirectory -PathType Container) {
        [IO.Directory]::Delete($temporaryDirectory, $true)
    }
    throw
}

Write-Output "nested_inner_launch_plan_evidence_passed files=4 replay=2 effects=0 output=$outputFullPath"
