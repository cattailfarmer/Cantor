[CmdletBinding()]
param(
    [string]$InputDirectory = 'experiments/operator_configuration_diagnostic/artifacts'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$builder = Join-Path $PSScriptRoot 'build_cantor_operator_configuration_diagnostic_evidence.ps1'
$verifier = Join-Path $PSScriptRoot 'verify_cantor_operator_configuration_diagnostic_evidence.ps1'
$inputDirectoryPath = if ([IO.Path]::IsPathRooted($InputDirectory)) {
    [IO.Path]::GetFullPath($InputDirectory)
}
else {
    [IO.Path]::GetFullPath((Join-Path $root $InputDirectory))
}
$readyName = 'operator_configuration_ready_v1.json'
$refusedName = 'operator_configuration_refused_v1.json'
$evidenceName = 'operator_configuration_diagnostic_evidence_v1.json'
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $temporaryBase ('cantor-operator-diagnostic-tests-' + [guid]::NewGuid().ToString('N'))
$script:producerRefusals = 0
$script:verifierRefusals = 0

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Write-Json([string]$Path, [object]$Value, [switch]$Compress) {
    $text = if ($Compress) { $Value | ConvertTo-Json -Depth 100 -Compress } else { $Value | ConvertTo-Json -Depth 100 }
    [IO.File]::WriteAllText($Path, "$($text.Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
}

function Update-ReportIdentity([string]$CaseDirectory, [string]$ReportName) {
    $evidencePath = Join-Path $CaseDirectory $evidenceName
    $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
    $reportPath = Join-Path $CaseDirectory $ReportName
    $index = if ($ReportName -ceq $readyName) { 0 } else { 1 }
    $item = Get-Item -LiteralPath $reportPath
    $evidence.reports[$index].bytes = [uint64]$item.Length
    $evidence.reports[$index].sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    Write-Json $evidencePath $evidence
}

function Assert-VerifierRefused([string]$Label, [scriptblock]$Mutation) {
    $caseDirectory = Join-Path $testRoot ('case-' + $Label)
    [IO.Directory]::CreateDirectory($caseDirectory) | Out-Null
    foreach ($name in @($readyName, $refusedName, $evidenceName)) {
        Copy-Item -LiteralPath (Join-Path $inputDirectoryPath $name) -Destination (Join-Path $caseDirectory $name)
    }
    & $Mutation $caseDirectory
    $refused = $false
    try { & $verifier -InputDirectory $caseDirectory *> $null }
    catch { $refused = $true }
    Assert-Test $refused "verifier admitted adversarial case: $Label"
    $script:verifierRefusals++
}

function Assert-ProducerRefused([string]$Label, [scriptblock]$Action) {
    $refused = $false
    try { & $Action *> $null }
    catch { $refused = $true }
    Assert-Test $refused "producer admitted unsafe case: $Label"
    $script:producerRefusals++
}

function Remove-TestRoot {
    if (-not [IO.Directory]::Exists($testRoot)) { return }
    $item = Get-Item -LiteralPath $testRoot -Force
    $expectedParent = $temporaryBase.TrimEnd('\', '/')
    $actualParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\', '/')
    Assert-Test ($actualParent.Equals($expectedParent, [StringComparison]::OrdinalIgnoreCase)) 'test cleanup parent differs'
    Assert-Test ($item.Name -cmatch '^cantor-operator-diagnostic-tests-[a-f0-9]{32}$') 'test cleanup leaf differs'
    Assert-Test ($item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'test cleanup target is not one physical directory'
    [IO.Directory]::Delete($item.FullName, $true)
}

[IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    & $verifier -InputDirectory $inputDirectoryPath | Out-Null

    Assert-ProducerRefused 'profile-root' {
        & $builder -OutputDirectory ([Environment]::GetFolderPath('UserProfile')) -UsePrebuilt
    }
    Assert-ProducerRefused 'preexisting-outputs' {
        & $builder -OutputDirectory $inputDirectoryPath -UsePrebuilt
    }
    $fileAsDirectory = Join-Path $testRoot 'not-a-directory'
    [IO.File]::WriteAllText($fileAsDirectory, 'preserve', [Text.UTF8Encoding]::new($false))
    Assert-ProducerRefused 'file-as-output-directory' {
        & $builder -OutputDirectory $fileAsDirectory -UsePrebuilt
    }
    Assert-Test ((Get-Content -LiteralPath $fileAsDirectory -Raw) -ceq 'preserve') 'producer changed the preexisting output-path file'

    Assert-VerifierRefused 'ready-status' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $readyName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.status = 'refused'
        Write-Json $path $report -Compress
        Update-ReportIdentity $caseDirectory $readyName
    }
    Assert-VerifierRefused 'ready-unknown-field' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $readyName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report | Add-Member -NotePropertyName production_ready -NotePropertyValue $true
        Write-Json $path $report -Compress
        Update-ReportIdentity $caseDirectory $readyName
    }
    Assert-VerifierRefused 'ready-privacy' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $readyName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.privacy.listener_bound = $true
        Write-Json $path $report -Compress
        Update-ReportIdentity $caseDirectory $readyName
    }
    Assert-VerifierRefused 'ready-check-order' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $readyName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.checks[0].subject = 'authentication_token'
        $report.checks[1].subject = 'service_config'
        Write-Json $path $report -Compress
        Update-ReportIdentity $caseDirectory $readyName
    }
    Assert-VerifierRefused 'ready-fault-exclusivity' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $readyName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.fault = [ordered]@{ code = 'false'; stage = 'false'; subject = 'service_config'; guidance = 'false' }
        Write-Json $path $report -Compress
        Update-ReportIdentity $caseDirectory $readyName
    }
    Assert-VerifierRefused 'ready-crlf' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $readyName
        $text = (Get-Content -LiteralPath $path -Raw).TrimEnd("`r", "`n") + "`r`n"
        [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))
        Update-ReportIdentity $caseDirectory $readyName
    }
    Assert-VerifierRefused 'refused-subject' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $refusedName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.fault.subject = 'activation_environment'
        Write-Json $path $report -Compress
        Update-ReportIdentity $caseDirectory $refusedName
    }
    Assert-VerifierRefused 'refused-raw-disclosure' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $refusedName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.fault.guidance = 'authentication token must contain exactly 64 hexadecimal characters'
        Write-Json $path $report -Compress
        Update-ReportIdentity $caseDirectory $refusedName
    }
    Assert-VerifierRefused 'refused-summary-exclusivity' {
        param($caseDirectory)
        $ready = Get-Content -LiteralPath (Join-Path $caseDirectory $readyName) -Raw | ConvertFrom-Json
        $path = Join-Path $caseDirectory $refusedName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.ready_summary = $ready.ready_summary
        Write-Json $path $report -Compress
        Update-ReportIdentity $caseDirectory $refusedName
    }
    Assert-VerifierRefused 'receipt-binary-hash' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $evidenceName
        $evidence = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $evidence.cantord.sha256 = 'A' * 64
        Write-Json $path $evidence
    }
    Assert-VerifierRefused 'receipt-source-commit' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $evidenceName
        $evidence = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $evidence.source_commit = '0' * 40
        Write-Json $path $evidence
    }
    Assert-VerifierRefused 'receipt-cleanup' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $evidenceName
        $evidence = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $evidence.cleanup.fixture_root_removed = $false
        Write-Json $path $evidence
    }
    Assert-VerifierRefused 'receipt-provider-contact' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $evidenceName
        $evidence = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $evidence.safety.provider_contacted = $true
        Write-Json $path $evidence
    }
    Assert-VerifierRefused 'receipt-capability' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $evidenceName
        $evidence = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $evidence.capability_denials = @($evidence.capability_denials[0..9])
        Write-Json $path $evidence
    }
    Assert-VerifierRefused 'receipt-unknown-field' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $evidenceName
        $evidence = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $evidence | Add-Member -NotePropertyName operator_ready -NotePropertyValue $true
        Write-Json $path $evidence
    }
    Assert-VerifierRefused 'receipt-report-hash' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $evidenceName
        $evidence = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $evidence.reports[0].sha256 = '0' * 64
        Write-Json $path $evidence
    }
    Assert-VerifierRefused 'missing-refused-report' {
        param($caseDirectory)
        [IO.File]::Delete((Join-Path $caseDirectory $refusedName))
    }

    Write-Output "operator_configuration_diagnostic_evidence_tests=passed producer_refusals=$script:producerRefusals verifier_refusals=$script:verifierRefusals"
}
finally {
    Remove-TestRoot
}
