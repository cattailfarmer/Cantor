[CmdletBinding()]
param(
    [string]$InputPath = 'experiments/operator_bootstrap_transaction/artifacts/operator_bootstrap_transaction_evidence_v1.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$builder = Join-Path $PSScriptRoot 'build_cantor_operator_bootstrap_transaction_evidence.ps1'
$verifier = Join-Path $PSScriptRoot 'verify_cantor_operator_bootstrap_transaction_evidence.ps1'
$inputFullPath = if ([IO.Path]::IsPathRooted($InputPath)) { [IO.Path]::GetFullPath($InputPath) } else { [IO.Path]::GetFullPath((Join-Path $root $InputPath)) }
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $temporaryBase ('cantor-bootstrap-evidence-tests-' + [guid]::NewGuid().ToString('N'))
$script:producerRefusals = 0
$script:verifierRefusals = 0

function Assert-Test([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Write-Json([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path, "$(($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
}
function Assert-ProducerRefused([string]$Label, [scriptblock]$Action) {
    $refused = $false
    try { & $Action *> $null } catch { $refused = $true }
    Assert-Test $refused "producer admitted unsafe case: $Label"
    $script:producerRefusals++
}
function Assert-VerifierRefused([string]$Label, [scriptblock]$Mutation) {
    $path = Join-Path $testRoot "$Label.json"
    $report = Get-Content -LiteralPath $inputFullPath -Raw | ConvertFrom-Json
    & $Mutation $report
    Write-Json $path $report
    $refused = $false
    try { & $verifier -InputPath $path *> $null } catch { $refused = $true }
    Assert-Test $refused "verifier admitted tamper: $Label"
    $script:verifierRefusals++
}
function Remove-TestRoot {
    if (-not [IO.Directory]::Exists($testRoot)) { return }
    $item = Get-Item -LiteralPath $testRoot -Force
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\', '/')
    Assert-Test ($parent.Equals($temporaryBase.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase) -and $item.Name -cmatch '^cantor-bootstrap-evidence-tests-[a-f0-9]{32}$' -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'evidence test cleanup identity differs'
    [IO.Directory]::Delete($item.FullName, $true)
}

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    & $verifier -InputPath $inputFullPath | Out-Null
    Assert-ProducerRefused 'directory-as-output' { & $builder -OutputPath $testRoot -UsePrebuilt }
    Assert-ProducerRefused 'preexisting-default' { & $builder -OutputPath $inputFullPath -UsePrebuilt }
    $preexistingFile = Join-Path $testRoot 'preexisting.json'
    [IO.File]::WriteAllText($preexistingFile, 'preserve', [Text.UTF8Encoding]::new($false))
    Assert-ProducerRefused 'preexisting-file' { & $builder -OutputPath $preexistingFile -UsePrebuilt }
    Assert-Test ((Get-Content -LiteralPath $preexistingFile -Raw) -ceq 'preserve') 'producer changed preexisting output'

    Assert-VerifierRefused 'status' { param($r) $r.status = 'false_success' }
    Assert-VerifierRefused 'source' { param($r) $r.source_commit = '0' * 40 }
    Assert-VerifierRefused 'binary-hash' { param($r) $r.cantord.sha256 = 'A' * 64 }
    Assert-VerifierRefused 'script-hash' { param($r) $r.transaction_script.sha256 = 'B' * 64 }
    Assert-VerifierRefused 'transaction-count' { param($r) $r.observation.transaction_count = 1 }
    Assert-VerifierRefused 'receipt-equality' { param($r) $r.observation.receipt_byte_equal = $false }
    Assert-VerifierRefused 'diagnostic-status' { param($r) $r.observation.final_diagnostic_status = 'refused' }
    Assert-VerifierRefused 'file-count' { param($r) $r.observation.final_file_count_each = @(3, 4) }
    Assert-VerifierRefused 'token-disclosure' { param($r) $r.observation.receipt_token_disclosure = $true }
    Assert-VerifierRefused 'cleanup' { param($r) $r.cleanup.random_tokens_destroyed = $false }
    Assert-VerifierRefused 'provider' { param($r) $r.safety.provider_contacted = $true }
    Assert-VerifierRefused 'capability' { param($r) $r.capability_denials = @($r.capability_denials[0..11]) }
    Assert-VerifierRefused 'unknown-field' { param($r) $r | Add-Member -NotePropertyName production_ready -NotePropertyValue $true }

    Write-Output "operator_bootstrap_transaction_evidence_tests=passed producer_refusals=$script:producerRefusals verifier_refusals=$script:verifierRefusals secrets_created=false cantord_invoked=false"
}
finally { Remove-TestRoot }
