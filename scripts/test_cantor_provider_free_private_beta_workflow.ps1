[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$producer = Join-Path $PSScriptRoot 'invoke_cantor_provider_free_private_beta_workflow.ps1'
$verifier = Join-Path $PSScriptRoot 'verify_cantor_provider_free_private_beta_workflow.ps1'
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testDirectory = Join-Path $temporaryBase ("cantor-private-beta-tests-$([guid]::NewGuid().ToString('N'))")
$runRoot = Join-Path $temporaryBase ("cantor-private-beta-$([guid]::NewGuid().ToString('N'))")
$preexistingRoot = Join-Path $temporaryBase ("cantor-private-beta-$([guid]::NewGuid().ToString('N'))")
$goodReport = Join-Path $testDirectory 'good.json'
$priorCantordPids = @(Get-Process cantord -ErrorAction SilentlyContinue | ForEach-Object Id)

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Write-Json([object]$Value, [string]$Path) {
    [IO.File]::WriteAllText(
        $Path,
        "$(($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n",
        [Text.UTF8Encoding]::new($false)
    )
}

function Assert-VerifyRefused([string]$Name, [scriptblock]$Mutation) {
    $candidatePath = Join-Path $testDirectory "$Name.json"
    $candidate = Get-Content -LiteralPath $goodReport -Raw | ConvertFrom-Json
    & $Mutation $candidate
    Write-Json $candidate $candidatePath
    $refused = $false
    try { & $verifier -InputPath $candidatePath *> $null }
    catch { $refused = $true }
    Assert-Condition $refused "private-beta verifier admitted tamper: $Name"
}

function Assert-ProducerRefused([string]$Name, [hashtable]$Parameters) {
    $refused = $false
    try { & $producer @Parameters *> $null }
    catch { $refused = $true }
    Assert-Condition $refused "private-beta producer admitted unsafe case: $Name"
}

[IO.Directory]::CreateDirectory($testDirectory) | Out-Null
try {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    & $producer `
        -RunRoot $runRoot `
        -OutputPath $goodReport `
        -ListenAddress "127.0.0.1:$port" `
        -UsePrebuilt | Out-Null
    & $verifier -InputPath $goodReport | Out-Null
    $report = Get-Content -LiteralPath $goodReport -Raw | ConvertFrom-Json
    Assert-Condition ($report.status -ceq 'provider_free_private_beta_verified_with_declared_gaps') 'private-beta status differs'
    Assert-Condition (@($report.release_artifacts).Count -eq 4 -and @($report.steps).Count -eq 11) 'private-beta artifact or step account differs'
    Assert-Condition (-not (Test-Path -LiteralPath $runRoot)) 'successful workflow retained its disposable run root'

    Assert-ProducerRefused 'repository_root' @{
        RunRoot = $root
        OutputPath = (Join-Path $testDirectory 'unsafe-root.json')
        ListenAddress = "127.0.0.1:$port"
        UsePrebuilt = $true
    }
    Assert-ProducerRefused 'nonloopback' @{
        RunRoot = (Join-Path $temporaryBase ("cantor-private-beta-$([guid]::NewGuid().ToString('N'))"))
        OutputPath = (Join-Path $testDirectory 'nonloopback.json')
        ListenAddress = '0.0.0.0:39851'
        UsePrebuilt = $true
    }
    [IO.Directory]::CreateDirectory($preexistingRoot) | Out-Null
    [IO.File]::WriteAllText((Join-Path $preexistingRoot 'marker.txt'), 'preserve', [Text.UTF8Encoding]::new($false))
    Assert-ProducerRefused 'preexisting_root' @{
        RunRoot = $preexistingRoot
        OutputPath = (Join-Path $testDirectory 'preexisting.json')
        ListenAddress = "127.0.0.1:$port"
        UsePrebuilt = $true
    }
    Assert-Condition ((Get-Content -LiteralPath (Join-Path $preexistingRoot 'marker.txt') -Raw) -ceq 'preserve') 'preexisting root was mutated'

    Assert-VerifyRefused 'artifact_hash' {
        param($candidate)
        $candidate.release_artifacts[0].sha256 = [string]::new('0', 64)
    }
    Assert-VerifyRefused 'duplicate_artifact_identity' {
        param($candidate)
        $candidate.release_artifacts[1].sha256 = $candidate.release_artifacts[0].sha256
    }
    Assert-VerifyRefused 'step_status' {
        param($candidate)
        $candidate.steps[4].status = 'failed'
    }
    Assert-VerifyRefused 'response_digest' {
        param($candidate)
        $candidate.lifecycle.direct_protocol_response_sha256 = [string]::new('F', 64)
    }
    Assert-VerifyRefused 'rollback' {
        param($candidate)
        $candidate.rollback.fixture_keys_destroyed = $false
    }
    Assert-VerifyRefused 'provider_contact' {
        param($candidate)
        $candidate.provider_contacted = $true
    }
    Assert-VerifyRefused 'source_commit' {
        param($candidate)
        $candidate.source_commit = [string]::new('0', 40)
    }
    Assert-VerifyRefused 'run_root' {
        param($candidate)
        $candidate.run_root = $testDirectory
    }
    Assert-VerifyRefused 'unknown_field' {
        param($candidate)
        $candidate | Add-Member -NotePropertyName production_ready -NotePropertyValue $true
    }

    $newCantordPids = @(Get-Process cantord -ErrorAction SilentlyContinue | Where-Object { $priorCantordPids -notcontains $_.Id } | ForEach-Object Id)
    Assert-Condition ($newCantordPids.Count -eq 0) "workflow left cantord process residuals: $($newCantordPids -join ',')"
}
finally {
    if (Test-Path -LiteralPath $preexistingRoot) {
        Assert-Condition ($preexistingRoot.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($preexistingRoot) -cmatch '^cantor-private-beta-[a-f0-9]{32}$') 'preexisting test cleanup target differs'
        [IO.Directory]::Delete($preexistingRoot, $true)
    }
    if (Test-Path -LiteralPath $testDirectory) {
        Assert-Condition ($testDirectory.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($testDirectory) -cmatch '^cantor-private-beta-tests-[a-f0-9]{32}$') 'test output cleanup target differs'
        [IO.Directory]::Delete($testDirectory, $true)
    }
}

Write-Output 'private_beta_workflow_tests=passed producer_refusals=3 verifier_refusals=9'
