[CmdletBinding()]
param(
    [string]$InputPath = 'experiments/provider_free_private_beta_workflow/artifacts/provider_free_private_beta_workflow_v1.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$input = if ([IO.Path]::IsPathRooted($InputPath)) { $InputPath } else { Join-Path $root $InputPath }

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Fields([psobject]$Value, [string[]]$Expected, [string]$Label) {
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    Assert-Exact (($actual -join ',') -ceq ($wanted -join ',')) "$Label fields differ"
}

$report = Get-Content -LiteralPath $input -Raw | ConvertFrom-Json
Assert-Fields $report @(
    'profile','status','source_commit','cargo_lock','build_mode','platform','run_root',
    'listen_address','release_artifacts','steps','corpus','lifecycle','rollback',
    'provider_contacted','capability_denials','non_authority_statement'
) 'report'
Assert-Exact ($report.profile -ceq 'cantor-provider-free-private-beta-workflow/0.1') 'report profile differs'
Assert-Exact ($report.status -ceq 'provider_free_private_beta_verified_with_declared_gaps') 'report status differs'
Assert-Exact ($report.platform -ceq 'windows_x86_64_local') 'platform differs'
Assert-Exact ($report.build_mode -in @('built_locked_offline','verified_prebuilt')) 'build mode differs'
Assert-Exact (-not [bool]$report.provider_contacted) 'provider contact was claimed'

& git -C $root cat-file -e "$($report.source_commit)^{commit}" 2>$null
Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not a Git commit'
& git -C $root merge-base --is-ancestor ([string]$report.source_commit) HEAD
Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not an ancestor of HEAD'

Assert-Fields $report.cargo_lock @('name','source_path','bytes','sha256') 'Cargo.lock identity'
$lock = Get-Item -LiteralPath (Join-Path $root 'Cargo.lock')
Assert-Exact ($report.cargo_lock.name -ceq 'Cargo.lock' -and $report.cargo_lock.source_path -ceq 'Cargo.lock') 'Cargo.lock path identity differs'
Assert-Exact ([uint64]$report.cargo_lock.bytes -eq [uint64]$lock.Length -and $report.cargo_lock.sha256 -ceq (Get-FileHash -LiteralPath $lock.FullName -Algorithm SHA256).Hash) 'Cargo.lock artifact drift'

$run = [IO.Path]::GetFullPath([string]$report.run_root)
Assert-Exact ([IO.Path]::IsPathRooted([string]$report.run_root) -and [IO.Path]::GetFileName($run) -cmatch '^cantor-private-beta-[a-f0-9]{32}$') 'run root identity differs'
Assert-Exact (-not (Test-Path -LiteralPath $run)) 'reported run root still exists'
Assert-Exact ($report.listen_address -cmatch '^127\.0\.0\.1:([0-9]{4,5})$') 'listen address is not closed IPv4 loopback'
$port = [int]$Matches[1]
Assert-Exact ($port -ge 1024 -and $port -le 65535) 'listen port is outside the admitted range'

$expectedBinaries = @('cantor.exe','cantor-corpus.exe','cantord.exe','cantorctl.exe')
$artifacts = @($report.release_artifacts)
Assert-Exact ($artifacts.Count -eq 4) 'release artifact count differs'
Assert-Exact ((@($artifacts.name) -join ',') -ceq ($expectedBinaries -join ',')) 'release artifact order or names differ'
foreach ($artifact in $artifacts) {
    Assert-Fields $artifact @('name','source_path','installed_path','bytes','sha256','installed_equal') "release artifact $($artifact.name)"
    Assert-Exact ($artifact.source_path -ceq "target/release/$($artifact.name)" -and $artifact.installed_path -ceq "bin/$($artifact.name)") "release path differs: $($artifact.name)"
    Assert-Exact ([uint64]$artifact.bytes -gt 0 -and $artifact.sha256 -cmatch '^[A-F0-9]{64}$' -and [bool]$artifact.installed_equal) "release identity differs: $($artifact.name)"
    $currentBinary = Get-Item -LiteralPath (Join-Path $root ([string]$artifact.source_path))
    Assert-Exact ([uint64]$artifact.bytes -eq [uint64]$currentBinary.Length -and $artifact.sha256 -ceq (Get-FileHash -LiteralPath $currentBinary.FullName -Algorithm SHA256).Hash) "current release binary drift: $($artifact.name)"
}
Assert-Exact (@($artifacts.sha256 | Select-Object -Unique).Count -eq 4) 'release hashes are not distinct'

$expectedSteps = @(
    'published_preflight','release_build','disposable_install','fixture_keys',
    'self_hosted_corpus','loopback_configuration','start_and_health',
    'representative_service_query','graceful_stop','direct_fallback','filesystem_rollback'
)
$steps = @($report.steps)
Assert-Exact ($steps.Count -eq $expectedSteps.Count -and (@($steps.name) -join ',') -ceq ($expectedSteps -join ',')) 'workflow step order differs'
foreach ($step in $steps) {
    Assert-Fields $step @('name','status','detail') "step $($step.name)"
    Assert-Exact ($step.status -ceq 'passed' -and -not [string]::IsNullOrWhiteSpace([string]$step.detail)) "step did not pass: $($step.name)"
}

Assert-Fields $report.corpus @('profile','manifest_sha256','source_count','unit_count','relation_count','package_id','environment_digest') 'corpus'
$manifestPath = Join-Path $root 'corpus/self_hosted/corpus.json'
Assert-Exact ($report.corpus.profile -ceq 'cantor-sop-corpus/0.1') 'corpus profile differs'
Assert-Exact ($report.corpus.manifest_sha256 -ceq (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash) 'corpus manifest drift'
Assert-Exact ([uint32]$report.corpus.source_count -eq 3 -and [uint32]$report.corpus.unit_count -eq 417 -and [uint32]$report.corpus.relation_count -eq 360) 'corpus counts differ'
Assert-Exact ($report.corpus.package_id -cmatch '^package:sha256:[a-f0-9]{64}$' -and $report.corpus.environment_digest -cmatch '^[a-f0-9]{64}$') 'corpus generated identity differs'

Assert-Fields $report.lifecycle @(
    'pid','generation_id','activation_sequence','health_verified','service_query_verified',
    'graceful_stop_verified','state_removed','direct_fallback_verified',
    'protocol_response_equal','service_protocol_response_sha256','direct_protocol_response_sha256'
) 'lifecycle'
Assert-Exact ([int64]$report.lifecycle.pid -gt 0 -and $report.lifecycle.generation_id -cmatch '^[a-f0-9]{64}$' -and [uint64]$report.lifecycle.activation_sequence -eq 1) 'lifecycle process or generation identity differs'
foreach ($field in @('health_verified','service_query_verified','graceful_stop_verified','state_removed','direct_fallback_verified','protocol_response_equal')) {
    Assert-Exact ([bool]$report.lifecycle.$field) "lifecycle proof is false: $field"
}
Assert-Exact ($report.lifecycle.service_protocol_response_sha256 -cmatch '^[A-F0-9]{64}$' -and $report.lifecycle.service_protocol_response_sha256 -ceq $report.lifecycle.direct_protocol_response_sha256) 'service and direct response digest equality differs'

Assert-Fields $report.rollback @(
    'run_root_removed','run_root_absent_at_report','fixture_keys_destroyed','token_destroyed',
    'generated_environment_destroyed','installed_binaries_destroyed','supervisor_state_removed','live_process_residual'
) 'rollback'
foreach ($field in @('run_root_removed','run_root_absent_at_report','fixture_keys_destroyed','token_destroyed','generated_environment_destroyed','installed_binaries_destroyed','supervisor_state_removed')) {
    Assert-Exact ([bool]$report.rollback.$field) "rollback proof is false: $field"
}
Assert-Exact (-not [bool]$report.rollback.live_process_residual) 'live process residual was reported'

$expectedDenials = @(
    'live_provider_success','production_trust_or_secret_lifecycle',
    'os_installer_or_supported_distribution','upgrade_or_migration_policy',
    'durable_or_distributed_custody','external_effect_execution',
    'automatic_remote_access','fpga_execution','minecraft_scope'
)
Assert-Exact ((@($report.capability_denials) -join ',') -ceq ($expectedDenials -join ',')) 'capability denials differ'
Assert-Exact ($report.non_authority_statement -ceq 'This local disposable workflow proves one provider-free private-beta mechanical path. Fixture keys are destroyed and grant no production trust, provider, effect, persistence, operator-product, or production authority.') 'non-authority statement differs'

Write-Output "private_beta_workflow_verified=true artifacts=4 steps=$($steps.Count) source_commit=$($report.source_commit)"
