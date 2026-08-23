[CmdletBinding()]
param([string]$InputDirectory = 'experiments/provider_free_release_signature_verification/artifacts')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$input = if ([IO.Path]::IsPathRooted($InputDirectory)) { [IO.Path]::GetFullPath($InputDirectory) } else { [IO.Path]::GetFullPath((Join-Path $root $InputDirectory)) }
$names = @('cantor-release-verify-linux-x86_64','release_signature_envelope_synthetic_v1.json','release_signature_evidence_v1.json','release_signature_policy_synthetic_v1.json','release_signature_receipt_synthetic_v1.json')
$signatureNonAuthority = 'Signature verification proves payload integrity and possession of a key pinned by the supplied policy. It does not prove policy governance, publisher identity, trust onboarding, supported delivery, installation, production secret lifecycle, operator acceptance, or production authority.'
$reportNonAuthority = 'This checked synthetic fixture proves detached release-signature mechanics only. It does not prove policy governance publisher identity trust onboarding supported delivery installation production secret lifecycle operator acceptance or production authority.'

function Assert-Exact([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Fields([psobject]$Value, [string[]]$Expected, [string]$Label) {
    Assert-Exact ($null -ne $Value) "$Label is absent"
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    Assert-Exact (($actual -join ',') -ceq ($wanted -join ',')) "$Label fields differ"
}
function Assert-Identity([psobject]$Identity, [string]$PhysicalPath, [string]$ExpectedPath, [string]$Label) {
    Assert-Fields $Identity @('path','bytes','sha256') $Label
    $item = Get-Item -LiteralPath $PhysicalPath -Force
    Assert-Exact (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Length -gt 0) "$Label physical file differs"
    Assert-Exact ($Identity.path -ceq $ExpectedPath -and [uint64]$Identity.bytes -eq [uint64]$item.Length -and $Identity.sha256 -ceq (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash) "$Label identity differs"
}

$directory = Get-Item -LiteralPath $input -Force
Assert-Exact ($directory.PSIsContainer -and ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'evidence input must be one physical directory'
$actualNames = @(Get-ChildItem -LiteralPath $directory.FullName -Force | ForEach-Object Name | Sort-Object)
Assert-Exact (($actualNames -join ',') -ceq (($names | Sort-Object) -join ',')) 'evidence artifact inventory differs'
$reportPath = Join-Path $input 'release_signature_evidence_v1.json'
$reportItem = Get-Item -LiteralPath $reportPath -Force
Assert-Exact ($reportItem.Length -gt 0 -and $reportItem.Length -le 65536) 'evidence report byte bound differs'
$reportText = [Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($reportPath))
Assert-Exact ($reportText.EndsWith("`n", [StringComparison]::Ordinal) -and -not $reportText.Contains("`r", [StringComparison]::Ordinal)) 'evidence report encoding differs'
$report = $reportText | ConvertFrom-Json
Assert-Fields $report @('profile','status','source_commit','execution_platform','signed_artifact_target','build_mode','bundle_input','bundle_evidence_input','sources','artifacts','observation','cleanup','safety','capability_denials','non_authority_statement') 'report'
Assert-Exact ($report.profile -ceq 'cantor-provider-free-release-signature-evidence/0.1' -and $report.status -ceq 'synthetic_signature_mechanics_verified_with_declared_trust_gaps' -and $report.execution_platform -ceq 'linux_x86_64_wsl2' -and $report.signed_artifact_target -ceq 'windows-x86_64' -and $report.build_mode -in @('built_locked_offline','verified_prebuilt') -and $report.non_authority_statement -ceq $reportNonAuthority) 'report identity differs'
Assert-Exact ($report.source_commit -cmatch '^[a-f0-9]{40}$') 'source commit syntax differs'
& git -C $root cat-file -e "$($report.source_commit)^{commit}" 2>$null
Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is absent'
& git -C $root merge-base --is-ancestor ([string]$report.source_commit) HEAD
Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not an ancestor of HEAD'

$sourceMap = [ordered]@{
    cargo_lock = @('Cargo.lock','Cargo.lock')
    workspace_manifest = @('Cargo.toml','Cargo.toml')
    crate_manifest = @('crates/cantor_release_signature/Cargo.toml','crates/cantor_release_signature/Cargo.toml')
    library = @('crates/cantor_release_signature/src/lib.rs','crates/cantor_release_signature/src/lib.rs')
    cli = @('crates/cantor_release_signature/src/main.rs','crates/cantor_release_signature/src/main.rs')
    fixture_helper = @('crates/cantor_release_signature/examples/generate_release_signature_fixture.rs','crates/cantor_release_signature/examples/generate_release_signature_fixture.rs')
    library_tests = @('crates/cantor_release_signature/tests/release_signature.rs','crates/cantor_release_signature/tests/release_signature.rs')
    cli_tests = @('crates/cantor_release_signature/tests/release_signature_cli.rs','crates/cantor_release_signature/tests/release_signature_cli.rs')
    producer = @('scripts/build_cantor_provider_free_release_signature_evidence.ps1','scripts/build_cantor_provider_free_release_signature_evidence.ps1')
    verifier = @('scripts/verify_cantor_provider_free_release_signature_evidence.ps1','scripts/verify_cantor_provider_free_release_signature_evidence.ps1')
    adversarial_tests = @('scripts/test_cantor_provider_free_release_signature_evidence.ps1','scripts/test_cantor_provider_free_release_signature_evidence.ps1')
}
Assert-Fields $report.sources @($sourceMap.Keys) 'sources'
foreach ($key in $sourceMap.Keys) { Assert-Identity $report.sources.$key (Join-Path $root $sourceMap[$key][0]) $sourceMap[$key][1] "source $key" }
$bundlePath = Join-Path $root 'experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0.zip'
$bundleEvidencePath = Join-Path $root 'experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0-evidence.json'
Assert-Identity $report.bundle_input $bundlePath 'experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0.zip' 'bundle input'
Assert-Identity $report.bundle_evidence_input $bundleEvidencePath 'experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0-evidence.json' 'bundle evidence input'
Assert-Fields $report.artifacts @('policy','envelope','receipt','verifier_binary') 'artifacts'
foreach ($pair in @(@('policy',$names[3]),@('envelope',$names[1]),@('receipt',$names[4]),@('verifier_binary',$names[0]))) { Assert-Identity $report.artifacts.($pair[0]) (Join-Path $input $pair[1]) $pair[1] "artifact $($pair[0])" }
$binaryBytes = [IO.File]::ReadAllBytes((Join-Path $input $names[0]))
Assert-Exact ($binaryBytes.Length -gt 4 -and $binaryBytes[0] -eq 0x7F -and $binaryBytes[1] -eq 0x45 -and $binaryBytes[2] -eq 0x4C -and $binaryBytes[3] -eq 0x46) 'verifier binary is not ELF'

$policy = Get-Content -LiteralPath (Join-Path $input $names[3]) -Raw | ConvertFrom-Json
$envelope = Get-Content -LiteralPath (Join-Path $input $names[1]) -Raw | ConvertFrom-Json
$receipt = Get-Content -LiteralPath (Join-Path $input $names[4]) -Raw | ConvertFrom-Json
Assert-Fields $policy @('profile','use_status','policy_id','publisher_id','verifying_key_hex','allowed_release_profile','allowed_target','non_authority_statement') 'policy'
Assert-Fields $envelope @('profile','payload','signature_hex') 'envelope'
Assert-Fields $envelope.payload @('profile','use_status','policy_id','publisher_id','release_profile','target','source_commit','bundle','evidence','non_authority_statement') 'payload'
Assert-Fields $receipt @('profile','status','use_status','policy_id','publisher_id','release_profile','target','source_commit','bundle','evidence','signature_verified','safety','non_authority_statement') 'receipt'
Assert-Exact ($policy.profile -ceq 'cantor-release-publisher-policy/0.1' -and $policy.use_status -ceq 'synthetic_fixture_only' -and $policy.policy_id -ceq 'policy:synthetic_release_fixture_only' -and $policy.publisher_id -ceq 'publisher:synthetic_release_fixture_only' -and $policy.verifying_key_hex -cmatch '^[A-F0-9]{64}$' -and $policy.non_authority_statement -ceq $signatureNonAuthority) 'policy form differs'
Assert-Exact ($envelope.profile -ceq 'cantor-provider-free-release-signature-envelope/0.1' -and $envelope.signature_hex -cmatch '^[A-F0-9]{128}$' -and $envelope.payload.use_status -ceq $policy.use_status -and $envelope.payload.policy_id -ceq $policy.policy_id -and $envelope.payload.publisher_id -ceq $policy.publisher_id -and $envelope.payload.release_profile -ceq $policy.allowed_release_profile -and $envelope.payload.target -ceq $policy.allowed_target -and $envelope.payload.non_authority_statement -ceq $signatureNonAuthority) 'envelope binding differs'
Assert-Exact ($receipt.profile -ceq 'cantor-provider-free-release-signature-receipt/0.1' -and $receipt.status -ceq 'verified_with_declared_trust_gaps' -and [bool]$receipt.signature_verified -and $receipt.policy_id -ceq $policy.policy_id -and $receipt.publisher_id -ceq $policy.publisher_id -and $receipt.source_commit -ceq $envelope.payload.source_commit -and $receipt.non_authority_statement -ceq $signatureNonAuthority) 'receipt binding differs'
foreach ($identity in @('bundle','evidence')) { Assert-Exact ([uint64]$receipt.$identity.bytes -eq [uint64]$envelope.payload.$identity.bytes -and $receipt.$identity.sha256 -ceq $envelope.payload.$identity.sha256) "receipt $identity differs" }
Assert-Fields $receipt.safety @('policy_governance_proved','production_publisher_authenticity_proved','supported_delivery_proved','archive_extracted','archive_executed','installation_performed','signing_key_created_or_retained','service_started','provider_contacted','remote_accessed') 'receipt safety'
foreach ($field in $receipt.safety.PSObject.Properties) { Assert-Exact (-not [bool]$field.Value) "receipt safety field is true: $($field.Name)" }
Assert-Fields $report.observation @('verification_count','receipt_byte_equal','signature_verified','use_status','policy_governance_proved','production_publisher_authenticity_proved','supported_delivery_proved') 'observation'
Assert-Exact ([uint32]$report.observation.verification_count -eq 2 -and [bool]$report.observation.receipt_byte_equal -and [bool]$report.observation.signature_verified -and $report.observation.use_status -ceq 'synthetic_fixture_only' -and -not [bool]$report.observation.policy_governance_proved -and -not [bool]$report.observation.production_publisher_authenticity_proved -and -not [bool]$report.observation.supported_delivery_proved) 'observation differs'
foreach ($section in @('cleanup','safety')) { foreach ($field in $report.$section.PSObject.Properties) { $expected = $field.Name -in @('fixture_root_removed','fixture_root_absent_at_publication'); Assert-Exact ([bool]$field.Value -eq $expected) "$section field differs: $($field.Name)" } }
$expectedDenials = @('policy_governance','production_publisher_authenticity','trust_onboarding','supported_delivery','installation_or_extraction','production_secret_lifecycle','service_or_provider_operation','automatic_remote_access','external_effect_execution','fpga_execution','minecraft_scope')
Assert-Exact ((@($report.capability_denials) -join ',') -ceq ($expectedDenials -join ',')) 'capability denials differ'
Write-Output "release_signature_evidence_verified=true source_commit=$($report.source_commit) executions=2 synthetic_only=true governance_proved=false"
