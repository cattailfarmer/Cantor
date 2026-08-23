[CmdletBinding()]
param(
    [string]$InputPath = 'experiments/operator_bootstrap_transaction/artifacts/operator_bootstrap_transaction_evidence_v1.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$inputFullPath = if ([IO.Path]::IsPathRooted($InputPath)) { [IO.Path]::GetFullPath($InputPath) } else { [IO.Path]::GetFullPath((Join-Path $root $InputPath)) }
$nonAuthority = 'This evidence proves one disposable initial-create local bootstrap transaction only. It grants no replacement, repair, migration, production secret lifecycle, permission policy, installation, delivery, service, provider, effect, operator-product, or production authority.'

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Fields([psobject]$Value, [string[]]$Expected, [string]$Label) {
    Assert-Exact ($null -ne $Value) "$Label is absent"
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    Assert-Exact (($actual -join ',') -ceq ($wanted -join ',')) "$Label fields differ"
}

function Assert-Identity([psobject]$Identity, [string]$ExpectedPath, [string]$PhysicalPath, [string]$Label) {
    Assert-Fields $Identity @('path', 'bytes', 'sha256') $Label
    $item = Get-Item -LiteralPath $PhysicalPath -Force
    Assert-Exact (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$Label physical file differs"
    Assert-Exact ($Identity.path -ceq $ExpectedPath -and [uint64]$Identity.bytes -eq [uint64]$item.Length) "$Label path or byte count differs"
    Assert-Exact ($Identity.sha256 -cmatch '^[A-F0-9]{64}$' -and $Identity.sha256 -ceq (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash) "$Label SHA256 differs"
}

$item = Get-Item -LiteralPath $inputFullPath -Force
Assert-Exact (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Length -gt 0 -and $item.Length -le 65536) 'evidence report is not one bounded physical file'
$bytes = [IO.File]::ReadAllBytes($item.FullName)
Assert-Exact (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) 'evidence report contains a BOM'
$text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
Assert-Exact ($text.EndsWith("`n", [StringComparison]::Ordinal) -and -not $text.Contains("`r", [StringComparison]::Ordinal)) 'evidence report is not LF-only and LF-terminated'
foreach ($forbidden in @('cantor-operator-bootstrap-transaction-p0-evidence', 'cantord.token', 'operator-change.txt', 'C:\Users\', '/tmp/', 'changed residual preserved for operator review')) {
    Assert-Exact (-not $text.Contains($forbidden, [StringComparison]::OrdinalIgnoreCase)) "evidence report disclosed forbidden content: $forbidden"
}
$report = $text | ConvertFrom-Json
Assert-Fields $report @(
    'profile', 'status', 'source_commit', 'platform', 'build_mode', 'cargo_lock',
    'cantord', 'transaction_script', 'focused_tests', 'observation', 'cleanup',
    'safety', 'capability_denials', 'non_authority_statement'
) 'evidence report'
Assert-Exact ($report.profile -ceq 'cantor-operator-bootstrap-transaction-evidence/0.1') 'evidence profile differs'
Assert-Exact ($report.status -ceq 'provider_free_initial_create_transaction_verified_with_declared_gaps') 'evidence status differs'
Assert-Exact ($report.platform -ceq 'windows_x86_64_local' -and $report.build_mode -in @('built_locked_offline', 'verified_prebuilt')) 'platform or build mode differs'
Assert-Exact ($report.source_commit -cmatch '^[a-f0-9]{40}$') 'source commit syntax differs'
& git -C $root cat-file -e "$($report.source_commit)^{commit}" 2>$null
Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not one Git commit'
& git -C $root merge-base --is-ancestor ([string]$report.source_commit) HEAD
Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not an ancestor of HEAD'
Assert-Identity $report.cargo_lock 'Cargo.lock' (Join-Path $root 'Cargo.lock') 'Cargo.lock identity'
Assert-Identity $report.cantord 'target/release/cantord.exe' (Join-Path $root 'target/release/cantord.exe') 'cantord identity'
Assert-Identity $report.transaction_script 'scripts/initialize_cantor_service_transaction.ps1' (Join-Path $root 'scripts/initialize_cantor_service_transaction.ps1') 'transaction script identity'
Assert-Identity $report.focused_tests 'scripts/test_cantor_operator_bootstrap_transaction.ps1' (Join-Path $root 'scripts/test_cantor_operator_bootstrap_transaction.ps1') 'focused tests identity'

Assert-Fields $report.observation @(
    'transaction_count', 'receipt_profile', 'receipt_status', 'receipt_bytes',
    'receipt_sha256', 'receipt_byte_equal', 'final_diagnostic_profile',
    'final_diagnostic_status', 'final_diagnostic_bytes', 'final_diagnostic_sha256',
    'final_diagnostic_byte_equal', 'final_file_count_each',
    'token_shape_verified_each', 'receipt_token_disclosure',
    'changed_residual_refusal_proved'
) 'observation'
Assert-Exact ([uint32]$report.observation.transaction_count -eq 2) 'transaction count differs'
Assert-Exact ($report.observation.receipt_profile -ceq 'cantor-operator-bootstrap-transaction/0.1' -and $report.observation.receipt_status -ceq 'initialized') 'receipt observation differs'
Assert-Exact ([uint64]$report.observation.receipt_bytes -gt 0 -and $report.observation.receipt_sha256 -cmatch '^[A-F0-9]{64}$' -and [bool]$report.observation.receipt_byte_equal) 'receipt identity or determinism differs'
Assert-Exact ($report.observation.final_diagnostic_profile -ceq 'cantor-operator-configuration-diagnostic/0.1' -and $report.observation.final_diagnostic_status -ceq 'ready') 'diagnostic observation differs'
Assert-Exact ([uint64]$report.observation.final_diagnostic_bytes -gt 0 -and $report.observation.final_diagnostic_sha256 -cmatch '^[A-F0-9]{64}$' -and [bool]$report.observation.final_diagnostic_byte_equal) 'diagnostic identity or determinism differs'
Assert-Exact ((@($report.observation.final_file_count_each) -join ',') -ceq '3,3') 'final file counts differ'
Assert-Exact ((@($report.observation.token_shape_verified_each) -join ',') -ceq 'True,True') 'token shape proof differs'
Assert-Exact (-not [bool]$report.observation.receipt_token_disclosure -and [bool]$report.observation.changed_residual_refusal_proved) 'redaction or changed-residual proof differs'

Assert-Fields $report.cleanup @('runtime_removed_each', 'random_tokens_destroyed', 'fixture_root_removed', 'fixture_root_absent_at_publication', 'staging_residual', 'live_cantord_residual') 'cleanup'
Assert-Exact ((@($report.cleanup.runtime_removed_each) -join ',') -ceq 'True,True') 'runtime cleanup account differs'
foreach ($field in @('random_tokens_destroyed', 'fixture_root_removed', 'fixture_root_absent_at_publication')) {
    Assert-Exact ([bool]$report.cleanup.$field) "cleanup field is false: $field"
}
Assert-Exact (-not [bool]$report.cleanup.staging_residual -and -not [bool]$report.cleanup.live_cantord_residual) 'cleanup residual account differs'

$safetyFields = @(
    'listener_bound', 'service_started', 'provider_contacted', 'remote_accessed',
    'replacement_performed', 'repair_performed', 'migration_performed',
    'production_secret_lifecycle_claimed', 'token_content_recorded',
    'token_hash_recorded', 'raw_receipt_retained', 'raw_diagnostic_retained'
)
Assert-Fields $report.safety $safetyFields 'safety'
foreach ($field in $safetyFields) { Assert-Exact (-not [bool]$report.safety.$field) "safety field is true: $field" }
$expectedDenials = @(
    'replacement_or_repair', 'migration_or_upgrade',
    'production_secret_rotation_or_revocation', 'permission_or_acl_policy',
    'installer_or_supported_delivery', 'listener_or_service_operation',
    'provider_execution', 'durable_or_distributed_custody',
    'external_effect_execution', 'automatic_remote_access', 'fpga_execution',
    'minecraft_scope', 'operator_product_or_production_readiness'
)
Assert-Exact ((@($report.capability_denials) -join ',') -ceq ($expectedDenials -join ',')) 'capability denials differ'
Assert-Exact ($report.non_authority_statement -ceq $nonAuthority) 'non-authority statement differs'

Write-Output "operator_bootstrap_transaction_evidence_verified=true source_commit=$($report.source_commit) transactions=2 cleanup=true secrets_retained=false"
