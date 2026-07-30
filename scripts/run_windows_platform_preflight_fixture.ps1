param(
    [string]$OutputPath = "crates/cantor_windows_preflight/evidence/windows_platform_preflight_physical_observation.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$expectedRepositoryRoot = "C:\Project\Cantor"
$fixtureRelativePath = ".local\m2b-platform-preflight-fixture"
$fixtureNativePath = [IO.Path]::GetFullPath((Join-Path $repositoryRoot $fixtureRelativePath))
$expectedFixtureNativePath = "C:\Project\Cantor\.local\m2b-platform-preflight-fixture"
$expectedFixtureRoot = "\\?\C:\Project\Cantor\.local\m2b-platform-preflight-fixture"

if ($repositoryRoot -cne $expectedRepositoryRoot) {
    throw "physical runner repository root is not the signed root"
}
if ($fixtureNativePath -cne $expectedFixtureNativePath) {
    throw "physical runner fixture path is not the signed root"
}
if (@(git -C $repositoryRoot status --porcelain).Count -ne 0) {
    throw "physical runner requires a clean signed source tree"
}

$fixtureCreated = -not (Test-Path -LiteralPath $fixtureNativePath -PathType Container)
if ($fixtureCreated) {
    New-Item -ItemType Directory -Path $fixtureNativePath | Out-Null
}
$resolvedFixture = (Resolve-Path -LiteralPath $fixtureNativePath).Path
if ($resolvedFixture -cne $expectedFixtureNativePath) {
    throw "resolved fixture escaped the signed root"
}

$requestPath = Join-Path $fixtureNativePath "request.json"
$request = [ordered]@{
    request_profile = "cantor-windows-platform-preflight-request/0.1"
    result_profile = "cantor-windows-platform-preflight/0.2"
    target_triple = "x86_64-pc-windows-msvc"
    input_root = $expectedFixtureRoot
}
[IO.File]::WriteAllText(
    $requestPath,
    "$(($request | ConvertTo-Json -Depth 8).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)

Push-Location $repositoryRoot
try {
    $buildLines = @(
        cargo test -p cantor_windows_preflight --test runtime_contract --release --no-run `
            --locked --offline --message-format=json-render-diagnostics
    )
    if ($LASTEXITCODE -ne 0) {
        throw "physical probe test binary compilation failed"
    }
    $artifacts = foreach ($line in $buildLines) {
        try {
            $item = $line | ConvertFrom-Json -ErrorAction Stop
            if ($item.reason -eq "compiler-artifact" `
                -and $item.target.name -eq "runtime_contract" `
                -and $null -ne $item.executable) {
                $item
            }
        }
        catch {
            continue
        }
    }
    $artifact = @($artifacts) | Select-Object -Last 1
    if ($null -eq $artifact) {
        throw "physical probe executable was not reported"
    }
    $executablePath = [IO.Path]::GetFullPath([string]$artifact.executable)
    $targetRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot "target"))
    if (-not $executablePath.StartsWith("$targetRoot\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "physical probe executable escaped target"
    }

    $env:CANTOR_WINDOWS_PREFLIGHT_REQUEST_PATH = $requestPath
    $priorErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $probeLines = @(
            & $executablePath `
                --exact exact_windows_fixture_emits_one_complete_local_ntfs_observation `
                --ignored --nocapture 2>&1
        )
        $probeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $priorErrorActionPreference
        Remove-Item Env:CANTOR_WINDOWS_PREFLIGHT_REQUEST_PATH -ErrorAction SilentlyContinue
    }
}
finally {
    Pop-Location
}

$resultPrefix = "CANTOR_WINDOWS_PREFLIGHT_RESULT="
$resultLine = @($probeLines) |
    ForEach-Object { $_.ToString() } |
    Where-Object { $_.StartsWith($resultPrefix, [StringComparison]::Ordinal) } |
    Select-Object -Last 1
if ($null -eq $resultLine) {
    throw "physical probe emitted no exact result"
}
$resultJson = $resultLine.Substring($resultPrefix.Length)
$result = $resultJson | ConvertFrom-Json
$expectedResult = $false
if ($result.outcome -eq "complete") {
    $expectedResult = $result.profile -eq "cantor-windows-platform-preflight/0.2" `
        -and $result.target_triple -eq "x86_64-pc-windows-msvc" `
        -and $result.input_root -ceq $expectedFixtureRoot `
        -and $result.volume.file_system_name -eq "NTFS" `
        -and [uint32]$result.remote_protocol.protocol -eq 0 `
        -and $result.disposition -eq "eligible_local_ntfs"
}
$probePassed = $probeExitCode -eq 0 -and $expectedResult

$volume = Get-Volume -DriveLetter C
$rustcLines = rustc --version --verbose
$rustcHost = ($rustcLines | Where-Object { $_ -like "host:*" } | Select-Object -First 1)
$sourceCommit = (git -C $repositoryRoot rev-parse HEAD).Trim()
$boundPaths = @(
    "Cargo.toml",
    "Cargo.lock",
    "crates/cantor_windows_preflight/Cargo.toml",
    "crates/cantor_windows_preflight/src/lib.rs",
    "crates/cantor_windows_preflight/tests/runtime_contract.rs",
    "scripts/run_windows_platform_preflight_fixture.ps1",
    "specifications/Cantor_M2B_Windows_Platform_Preflight_Runtime.sop"
)
$sourceArtifacts = foreach ($path in $boundPaths) {
    $item = Get-Item -LiteralPath (Join-Path $repositoryRoot $path)
    [ordered]@{
        path = $path
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        bytes = $item.Length
    }
}

$observation = [ordered]@{
    schema = "cantor-windows-platform-preflight-physical-observation/0.1"
    observation_uuid = "5edea140-24ec-4777-bfa8-02a5e2b70137"
    captured_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical = "specifications/Cantor_M2B_Windows_Platform_Preflight_Runtime.sop"
        satisfaction_signature_uuid = "2fc69987-c7de-4538-9993-c5956f889584"
        source_commit = $sourceCommit
    }
    host = [ordered]@{
        operating_system = [Environment]::OSVersion.VersionString
        rustc_host = $rustcHost.Substring("host:".Length).Trim()
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        drive_letter = "C"
        drive_type = $volume.DriveType.ToString()
        file_system = [string]$volume.FileSystem
        health_status = $volume.HealthStatus.ToString()
        operational_status = @($volume.OperationalStatus | ForEach-Object { $_.ToString() })
    }
    fixture = [ordered]@{
        input_root = $expectedFixtureRoot
        native_path = $expectedFixtureNativePath
        created_by_runner = $fixtureCreated
        cleanup_performed = $false
    }
    executable = [ordered]@{
        file_name = [IO.Path]::GetFileName($executablePath)
        sha256 = (Get-FileHash -LiteralPath $executablePath -Algorithm SHA256).Hash
        bytes = (Get-Item -LiteralPath $executablePath).Length
    }
    request = $request
    result = $result
    probe = [ordered]@{
        test = "exact_windows_fixture_emits_one_complete_local_ntfs_observation"
        exit_code = $probeExitCode
        calls = "one root preflight"
        expected_relation = "complete local NTFS protocol zero and eligible"
        status = if ($probePassed) { "passed" } else { "blocked_unexpected_result" }
    }
    source_artifacts = @($sourceArtifacts)
    nonclaims = @(
        "no tree traversal",
        "no content read",
        "no scanner receipt",
        "no candidate admission",
        "no launch seal or promotion"
    )
}

$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))
}
$allowedEvidenceDirectory =
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot "crates\cantor_windows_preflight\evidence"))
if ([IO.Path]::GetDirectoryName($outputFullPath) -cne $allowedEvidenceDirectory) {
    throw "physical observation output escaped the signed evidence directory"
}
[IO.Directory]::CreateDirectory($allowedEvidenceDirectory) | Out-Null
[IO.File]::WriteAllText(
    $outputFullPath,
    "$(($observation | ConvertTo-Json -Depth 12).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)

Write-Output $outputFullPath
if (-not $probePassed) {
    throw "physical probe evidence was preserved but did not satisfy the signed expected relation"
}
