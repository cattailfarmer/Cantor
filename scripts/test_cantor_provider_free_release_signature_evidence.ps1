[CmdletBinding()]
param([string]$InputDirectory = 'experiments/provider_free_release_signature_verification/artifacts')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$inputFullPath = if ([IO.Path]::IsPathRooted($InputDirectory)) { [IO.Path]::GetFullPath($InputDirectory) } else { [IO.Path]::GetFullPath((Join-Path $root $InputDirectory)) }
$builder = Join-Path $PSScriptRoot 'build_cantor_provider_free_release_signature_evidence.ps1'
$verifier = Join-Path $PSScriptRoot 'verify_cantor_provider_free_release_signature_evidence.ps1'
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $temporaryBase ('cantor-release-signature-evidence-tests-' + [guid]::NewGuid().ToString('N'))
$script:producerRefusals = 0
$script:verifierRefusals = 0

function Assert-Test([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Write-Json([string]$Path, [object]$Value) { [IO.File]::WriteAllText($Path, "$(($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false)) }
function Assert-ProducerRefused([string]$Label, [scriptblock]$Action) { $refused=$false; try { & $Action *> $null } catch { $refused=$true }; Assert-Test $refused "producer admitted unsafe case: $Label"; $script:producerRefusals++ }
function Copy-Exact([string]$Destination) { [IO.Directory]::CreateDirectory($Destination) | Out-Null; foreach($item in Get-ChildItem -LiteralPath $inputFullPath -File){ [IO.File]::Copy($item.FullName,(Join-Path $Destination $item.Name)) } }
function Assert-VerifierRefused([string]$Label, [scriptblock]$Mutation) {
    $case = Join-Path $testRoot $Label
    Copy-Exact $case
    & $Mutation $case
    $refused=$false; try { & $verifier -InputDirectory $case *> $null } catch { $refused=$true }
    Assert-Test $refused "verifier admitted tamper: $Label"
    $script:verifierRefusals++
}
function Mutate-Json([string]$Path, [scriptblock]$Mutation) { $value=Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json; & $Mutation $value; Write-Json $Path $value }
function Remove-TestRoot { if(-not [IO.Directory]::Exists($testRoot)){return}; $item=Get-Item -LiteralPath $testRoot -Force; $parent=[IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\','/'); Assert-Test ($parent.Equals($temporaryBase.TrimEnd('\','/'),[StringComparison]::OrdinalIgnoreCase) -and $item.Name -cmatch '^cantor-release-signature-evidence-tests-[a-f0-9]{32}$' -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'test cleanup identity differs'; [IO.Directory]::Delete($item.FullName,$true) }

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    & $verifier -InputDirectory $inputFullPath | Out-Null
    Assert-ProducerRefused 'preexisting-output' { & $builder -OutputDirectory $inputFullPath -UsePrebuilt }
    Assert-ProducerRefused 'file-as-output' { & $builder -OutputDirectory (Join-Path $inputFullPath 'release_signature_evidence_v1.json') -UsePrebuilt }
    Assert-ProducerRefused 'repo-root-output' { & $builder -OutputDirectory $root -UsePrebuilt }
    Assert-VerifierRefused 'report-status' { param($d) Mutate-Json (Join-Path $d 'release_signature_evidence_v1.json') { param($r) $r.status='false_success' } }
    Assert-VerifierRefused 'report-source' { param($d) Mutate-Json (Join-Path $d 'release_signature_evidence_v1.json') { param($r) $r.source_commit='0'*40 } }
    Assert-VerifierRefused 'report-binary-hash' { param($d) Mutate-Json (Join-Path $d 'release_signature_evidence_v1.json') { param($r) $r.artifacts.verifier_binary.sha256='A'*64 } }
    Assert-VerifierRefused 'report-observation' { param($d) Mutate-Json (Join-Path $d 'release_signature_evidence_v1.json') { param($r) $r.observation.signature_verified=$false } }
    Assert-VerifierRefused 'report-safety' { param($d) Mutate-Json (Join-Path $d 'release_signature_evidence_v1.json') { param($r) $r.safety.production_secret_created=$true } }
    Assert-VerifierRefused 'report-unknown' { param($d) Mutate-Json (Join-Path $d 'release_signature_evidence_v1.json') { param($r) $r | Add-Member production_ready $true } }
    Assert-VerifierRefused 'policy-publisher' { param($d) Mutate-Json (Join-Path $d 'release_signature_policy_synthetic_v1.json') { param($r) $r.publisher_id='publisher:changed' } }
    Assert-VerifierRefused 'envelope-signature' { param($d) Mutate-Json (Join-Path $d 'release_signature_envelope_synthetic_v1.json') { param($r) $r.signature_hex='0'*128 } }
    Assert-VerifierRefused 'receipt-signature' { param($d) Mutate-Json (Join-Path $d 'release_signature_receipt_synthetic_v1.json') { param($r) $r.signature_verified=$false } }
    Assert-VerifierRefused 'receipt-safety' { param($d) Mutate-Json (Join-Path $d 'release_signature_receipt_synthetic_v1.json') { param($r) $r.safety.policy_governance_proved=$true } }
    Assert-VerifierRefused 'binary-content' { param($d) [IO.File]::WriteAllBytes((Join-Path $d 'cantor-release-verify-linux-x86_64'),[byte[]](0x7F,0x45,0x4C,0x46,0x00)) }
    Assert-VerifierRefused 'missing-artifact' { param($d) [IO.File]::Delete((Join-Path $d 'release_signature_envelope_synthetic_v1.json')) }
    Assert-VerifierRefused 'extra-artifact' { param($d) [IO.File]::WriteAllText((Join-Path $d 'extra.txt'),'x') }
    Write-Output "release_signature_evidence_tests=passed producer_refusals=$script:producerRefusals verifier_refusals=$script:verifierRefusals verifier_binary_invoked=false signing_performed=false"
}
finally { Remove-TestRoot }
