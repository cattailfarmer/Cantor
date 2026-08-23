[CmdletBinding()]
param(
    [string]$InputDirectory = 'experiments/operator_configuration_diagnostic/artifacts'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$inputDirectoryPath = if ([IO.Path]::IsPathRooted($InputDirectory)) {
    [IO.Path]::GetFullPath($InputDirectory)
}
else {
    [IO.Path]::GetFullPath((Join-Path $root $InputDirectory))
}
$readyName = 'operator_configuration_ready_v1.json'
$refusedName = 'operator_configuration_refused_v1.json'
$evidenceName = 'operator_configuration_diagnostic_evidence_v1.json'
$readyPath = Join-Path $inputDirectoryPath $readyName
$refusedPath = Join-Path $inputDirectoryPath $refusedName
$evidencePath = Join-Path $inputDirectoryPath $evidenceName
$diagnosticNonAuthority = 'This deterministic preflight validates existing local startup artifacts without binding a listener. It records no authority path, token, raw fault, config, activation, or environment content and grants no mutation, migration, provider, effect, persistence, operator-product, or production authority.'
$evidenceNonAuthority = 'This provider-free preflight evidence proves only exact current startup-artifact validation before listener binding. It grants no configuration, secret, repair, migration, service, provider, effect, persistence, operator-product, or production authority.'

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Fields([psobject]$Value, [string[]]$Expected, [string]$Label) {
    Assert-Exact ($null -ne $Value) "$Label is absent"
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    Assert-Exact (($actual -join ',') -ceq ($wanted -join ',')) "$Label fields differ"
}

function Assert-Digest([psobject]$Value, [string]$Label) {
    Assert-Fields $Value @('algorithm', 'value') $Label
    Assert-Exact ($Value.algorithm -ceq 'sha256' -and $Value.value -cmatch '^[a-f0-9]{64}$') "$Label differs"
}

function Read-CompactRecord([string]$Path, [string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Exact (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "$Label is not one physical file"
    Assert-Exact ($item.Length -gt 1 -and $item.Length -le 65536) "$Label size is outside the admitted range"
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    Assert-Exact (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191)) "$Label contains a BOM"
    Assert-Exact ($bytes[-1] -eq 10 -and $bytes[-2] -ne 13 -and -not ($bytes -contains 13)) "$Label is not LF-only and LF-terminated"
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    Assert-Exact (($text.Substring(0, $text.Length - 1)).IndexOf("`n", [StringComparison]::Ordinal) -lt 0) "$Label is not exactly one JSON line"
    [pscustomobject]@{ item = $item; bytes = $bytes; text = $text; value = ($text | ConvertFrom-Json) }
}

function Assert-Privacy([psobject]$Privacy, [string]$Label) {
    $fields = @(
        'authority_paths_recorded', 'token_content_recorded', 'token_hash_recorded',
        'config_content_recorded', 'activation_content_recorded', 'environment_content_recorded',
        'raw_fault_message_recorded', 'listener_bound', 'service_started',
        'provider_contacted', 'remote_accessed'
    )
    Assert-Fields $Privacy $fields $Label
    foreach ($field in $fields) {
        Assert-Exact (-not [bool]$Privacy.$field) "$Label field is true: $field"
    }
}

function Assert-NoDisclosure([string]$Text, [string]$Label) {
    foreach ($forbidden in @(
        ':\', '/tmp/', '/var/', '/home/',
        'service.json', 'activation.json', 'token.txt', 'environment.json',
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        'invalid-public-fixture-authentication',
        'fixture-only signed semantic coprocessor',
        'authentication token must contain exactly 64 hexadecimal characters'
    )) {
        Assert-Exact (-not $Text.Contains($forbidden, [StringComparison]::OrdinalIgnoreCase)) "$Label disclosed forbidden content: $forbidden"
    }
}

function Assert-Check([psobject]$Check, [uint32]$Ordinal, [string]$Subject, [string]$Status, [string]$Label) {
    Assert-Fields $Check @('ordinal', 'subject', 'status') $Label
    Assert-Exact ([uint32]$Check.ordinal -eq $Ordinal -and $Check.subject -ceq $Subject -and $Check.status -ceq $Status) "$Label differs"
}

function Assert-ReportEnvelope([psobject]$Report, [string]$ExpectedStatus, [string]$Label) {
    Assert-Fields $Report @('profile', 'status', 'config_file_sha256', 'checks', 'ready_summary', 'fault', 'privacy', 'non_authority_statement') $Label
    Assert-Exact ($Report.profile -ceq 'cantor-operator-configuration-diagnostic/0.1') "$Label profile differs"
    Assert-Exact ($Report.status -ceq $ExpectedStatus) "$Label status differs"
    Assert-Digest $Report.config_file_sha256 "$Label config digest"
    Assert-Privacy $Report.privacy "$Label privacy"
    Assert-Exact ($Report.non_authority_statement -ceq $diagnosticNonAuthority) "$Label non-authority statement differs"
}

function Assert-ArtifactIdentity([psobject]$Identity, [string]$ExpectedPath, [string]$FilePath, [string]$Label) {
    Assert-Fields $Identity @('path', 'bytes', 'sha256') $Label
    $item = Get-Item -LiteralPath $FilePath -Force
    Assert-Exact ($Identity.path -ceq $ExpectedPath -and [uint64]$Identity.bytes -eq [uint64]$item.Length) "$Label path or byte count differs"
    Assert-Exact ($Identity.sha256 -cmatch '^[A-F0-9]{64}$' -and $Identity.sha256 -ceq (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash) "$Label digest differs"
}

$directoryItem = Get-Item -LiteralPath $inputDirectoryPath -Force
Assert-Exact ($directoryItem.PSIsContainer -and ($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'input directory is not one physical directory'

$readyRecord = Read-CompactRecord $readyPath 'ready report'
$refusedRecord = Read-CompactRecord $refusedPath 'refused report'
$ready = $readyRecord.value
$refused = $refusedRecord.value
Assert-ReportEnvelope $ready 'ready' 'ready report'
Assert-ReportEnvelope $refused 'refused' 'refused report'
Assert-NoDisclosure $readyRecord.text 'ready report'
Assert-NoDisclosure $refusedRecord.text 'refused report'
Assert-Exact ($ready.config_file_sha256.value -ceq $refused.config_file_sha256.value) 'ready and refused reports do not bind the same configuration bytes'

$readyChecks = @($ready.checks)
Assert-Exact ($readyChecks.Count -eq 3) 'ready check count differs'
Assert-Check $readyChecks[0] 0 'service_config' 'passed' 'ready check 0'
Assert-Check $readyChecks[1] 1 'authentication_token' 'passed' 'ready check 1'
Assert-Check $readyChecks[2] 2 'activation_environment' 'passed' 'ready check 2'
Assert-Exact ($null -ne $ready.ready_summary -and $null -eq $ready.fault) 'ready summary/fault exclusivity differs'
Assert-Fields $ready.ready_summary @(
    'service_config_schema', 'listen_family', 'listen_port', 'max_frame_bytes',
    'max_connections', 'read_timeout_milliseconds', 'write_timeout_milliseconds',
    'active_binding', 'runtime_metrics', 'ordered_package_count'
) 'ready summary'
Assert-Exact (
    $ready.ready_summary.service_config_schema -ceq 'cantor-service-config/0.1' -and
    $ready.ready_summary.listen_family -ceq 'ipv4_loopback' -and
    [uint32]$ready.ready_summary.listen_port -eq 39841 -and
    [uint64]$ready.ready_summary.max_frame_bytes -eq 1048576 -and
    [uint32]$ready.ready_summary.max_connections -eq 32 -and
    [uint64]$ready.ready_summary.read_timeout_milliseconds -eq 5000 -and
    [uint64]$ready.ready_summary.write_timeout_milliseconds -eq 5000 -and
    [uint32]$ready.ready_summary.ordered_package_count -eq 1
) 'ready safe summary differs'
Assert-Fields $ready.ready_summary.active_binding @('generation_id', 'activation_sequence', 'activation_digest', 'environment_file_sha256') 'ready active binding'
Assert-Digest $ready.ready_summary.active_binding.generation_id 'generation digest'
Assert-Digest $ready.ready_summary.active_binding.activation_digest 'activation digest'
Assert-Digest $ready.ready_summary.active_binding.environment_file_sha256 'environment file digest'
Assert-Exact ([uint64]$ready.ready_summary.active_binding.activation_sequence -eq 1) 'activation sequence differs'
$metricFields = @('projection_hits', 'projection_misses', 'projection_preparations', 'projection_replacements', 'executions')
Assert-Fields $ready.ready_summary.runtime_metrics $metricFields 'ready runtime metrics'
foreach ($field in $metricFields) {
    Assert-Exact ([uint64]$ready.ready_summary.runtime_metrics.$field -eq 0) "runtime metric differs: $field"
}

$refusedChecks = @($refused.checks)
Assert-Exact ($refusedChecks.Count -eq 2) 'refused check count differs'
Assert-Check $refusedChecks[0] 0 'service_config' 'passed' 'refused check 0'
Assert-Check $refusedChecks[1] 1 'authentication_token' 'refused' 'refused check 1'
Assert-Exact ($null -eq $refused.ready_summary -and $null -ne $refused.fault) 'refused summary/fault exclusivity differs'
Assert-Fields $refused.fault @('code', 'stage', 'subject', 'guidance') 'refused fault'
Assert-Exact (
    $refused.fault.code -ceq 'invalid_auth_token' -and
    $refused.fault.stage -ceq 'authentication' -and
    $refused.fault.subject -ceq 'authentication_token' -and
    $refused.fault.guidance -ceq 'provision a bounded authentication token with exactly 64 hexadecimal characters'
) 'refused public fault differs'

$evidenceItem = Get-Item -LiteralPath $evidencePath -Force
Assert-Exact (-not $evidenceItem.PSIsContainer -and ($evidenceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $evidenceItem.Length -gt 0 -and $evidenceItem.Length -le 65536) 'evidence receipt is not one bounded physical file'
$evidenceBytes = [IO.File]::ReadAllBytes($evidenceItem.FullName)
Assert-Exact (-not ($evidenceBytes.Length -ge 3 -and $evidenceBytes[0] -eq 239 -and $evidenceBytes[1] -eq 187 -and $evidenceBytes[2] -eq 191)) 'evidence receipt contains a BOM'
$evidenceText = [Text.UTF8Encoding]::new($false, $true).GetString($evidenceBytes)
Assert-Exact ($evidenceText.EndsWith("`n", [StringComparison]::Ordinal) -and -not $evidenceText.Contains("`r", [StringComparison]::Ordinal)) 'evidence receipt is not LF-only and LF-terminated'
$evidence = $evidenceText | ConvertFrom-Json
Assert-Fields $evidence @(
    'profile', 'status', 'source_commit', 'platform', 'build_mode', 'cargo_lock',
    'cantord', 'reports', 'executions', 'cleanup', 'safety', 'capability_denials',
    'non_authority_statement'
) 'evidence receipt'
Assert-Exact ($evidence.profile -ceq 'cantor-operator-configuration-diagnostic-evidence/0.1') 'evidence profile differs'
Assert-Exact ($evidence.status -ceq 'provider_free_configuration_diagnostic_verified_with_declared_gaps') 'evidence status differs'
Assert-Exact ($evidence.platform -ceq 'windows_x86_64_local' -and $evidence.build_mode -in @('built_locked_offline', 'verified_prebuilt')) 'evidence platform or build mode differs'
Assert-Exact ($evidence.source_commit -cmatch '^[a-f0-9]{40}$') 'source commit syntax differs'
& git -C $root cat-file -e "$($evidence.source_commit)^{commit}" 2>$null
Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not a Git commit'
& git -C $root merge-base --is-ancestor ([string]$evidence.source_commit) HEAD
Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not an ancestor of HEAD'
Assert-ArtifactIdentity $evidence.cargo_lock 'Cargo.lock' (Join-Path $root 'Cargo.lock') 'Cargo.lock identity'
Assert-ArtifactIdentity $evidence.cantord 'target/release/cantord.exe' (Join-Path $root 'target/release/cantord.exe') 'cantord identity'
$reports = @($evidence.reports)
Assert-Exact ($reports.Count -eq 2) 'evidence report identity count differs'
Assert-ArtifactIdentity $reports[0] "experiments/operator_configuration_diagnostic/artifacts/$readyName" $readyPath 'ready report identity'
Assert-ArtifactIdentity $reports[1] "experiments/operator_configuration_diagnostic/artifacts/$refusedName" $refusedPath 'refused report identity'

Assert-Fields $evidence.executions @('ready_exit_code', 'ready_replay_exit_code', 'refused_exit_code', 'ready_replay_byte_equal', 'stdout_lf_terminated_each', 'domain_stderr_bytes_each') 'execution receipt'
Assert-Exact (
    [int32]$evidence.executions.ready_exit_code -eq 0 -and
    [int32]$evidence.executions.ready_replay_exit_code -eq 0 -and
    [int32]$evidence.executions.refused_exit_code -eq 3 -and
    [bool]$evidence.executions.ready_replay_byte_equal -and
    [bool]$evidence.executions.stdout_lf_terminated_each -and
    ((@($evidence.executions.domain_stderr_bytes_each) -join ',') -ceq '0,0,0')
) 'execution receipt differs'
Assert-Fields $evidence.cleanup @('fixture_root_removed', 'fixture_root_absent_at_publication', 'staging_removed_after_publication') 'cleanup receipt'
foreach ($field in @('fixture_root_removed', 'fixture_root_absent_at_publication', 'staging_removed_after_publication')) {
    Assert-Exact ([bool]$evidence.cleanup.$field) "cleanup field is false: $field"
}
Assert-Fields $evidence.safety @('diagnostic_listener_bound', 'service_started', 'provider_contacted', 'remote_accessed', 'operator_inputs_mutated', 'production_secret_created', 'raw_fault_recorded') 'safety receipt'
foreach ($field in $evidence.safety.PSObject.Properties.Name) {
    Assert-Exact (-not [bool]$evidence.safety.$field) "safety field is true: $field"
}
$expectedDenials = @(
    'configuration_generation_or_repair', 'production_secret_provisioning',
    'listener_or_service_availability', 'provider_execution', 'migration_or_upgrade',
    'durable_or_distributed_custody', 'external_effect_execution',
    'automatic_remote_access', 'fpga_execution', 'minecraft_scope',
    'operator_product_or_production_readiness'
)
Assert-Exact ((@($evidence.capability_denials) -join ',') -ceq ($expectedDenials -join ',')) 'capability denials differ'
Assert-Exact ($evidence.non_authority_statement -ceq $evidenceNonAuthority) 'evidence non-authority statement differs'

Write-Output "operator_configuration_diagnostic_evidence_verified=true source_commit=$($evidence.source_commit) reports=2 ready_exit=0 refused_exit=3"
