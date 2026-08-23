[CmdletBinding()]
param(
    [string]$OutputPath = 'experiments/local_product_acceptance/artifacts/local_product_developer_alpha_acceptance_v1.json',
    [switch]$VerifyOnly,
    [switch]$ExecuteFocused,
    [switch]$UseWslFocusedLane
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$output = if ([IO.Path]::IsPathRooted($OutputPath)) { $OutputPath } else { Join-Path $root $OutputPath }

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Read-Json([string]$Path) {
    $resolved = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $root $Path }
    Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
}

function Get-ArtifactIdentity([string]$Name, [string]$RelativePath) {
    $item = Get-Item -LiteralPath (Join-Path $root $RelativePath)
    [ordered]@{
        name = $Name
        path = $RelativePath.Replace('\', '/')
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

function Get-EvidenceState {
    $lines = @(& (Join-Path $PSScriptRoot 'rehash_current_evidence_manifests.ps1') -VerifyOnly)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 1 -or
        $lines[0] -notmatch '^current_manifests=(\d+) artifact_references=(\d+) stale=(\d+)$') {
        throw "recursive evidence verifier output differs: $($lines -join ' | ')"
    }
    [ordered]@{
        current_manifest_count = [uint32]$Matches[1]
        artifact_reference_count = [uint32]$Matches[2]
        stale_reference_count = [uint32]$Matches[3]
    }
}

function Invoke-FocusedVerifier([string]$Name, [scriptblock]$Command) {
    $global:LASTEXITCODE = 0
    Push-Location $root
    try {
        & $Command
        if (-not $? -or $LASTEXITCODE -ne 0) { throw "focused verifier failed: $Name" }
    }
    finally {
        Pop-Location
    }
}

function New-AcceptanceReport([string]$SourceCommit) {
    & git -C $root cat-file -e "$SourceCommit^{commit}" 2>$null
    Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not a Git commit'
    & git -C $root merge-base --is-ancestor $SourceCommit HEAD
    Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not an ancestor of current HEAD'

    $corpusManifest = Read-Json 'experiments/self_hosted_corpus_benchmark/artifacts/self_hosted_corpus_evidence_manifest.json'
    $serviceManifest = Read-Json 'crates/cantor_service/evidence/supervised_lifecycle_evidence_manifest.json'
    $baseline = Read-Json 'experiments/semantic_anchor_catalogue_slice5a/self_hosted_anchor_evidence.json'
    $correction = Read-Json 'experiments/semantic_anchor_catalogue_slice5c/correction_catalogue.json'
    $curation = Read-Json 'experiments/semantic_anchor_catalogue_slice5f/synthetic_curator_selection_fixture.json'
    $p1Release = Read-Json 'experiments/iterative_attention_procedure_loop_p1/artifacts/provider_free_shell_release_manifest_v1.json'
    $p1Witness = Read-Json 'experiments/iterative_attention_procedure_loop_p1/artifacts/discovery_inspection_witness_v1.json'
    $lifecycle = Read-Json 'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_independent_bridge_probe.json'
    $providerUnavailable = Read-Json 'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe.json'
    $providerUnavailableVerification = Read-Json 'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe_verification.json'

    Assert-Exact ($corpusManifest.schema -ceq 'cantor-self-hosted-corpus-evidence-manifest/0.1') 'self-hosted corpus evidence profile differs'
    Assert-Exact ([int]$corpusManifest.corpus.source_count -eq 3 -and [int]$corpusManifest.corpus.unit_count -eq 417 -and [int]$corpusManifest.corpus.relation_count -eq 360) 'self-hosted corpus counts differ'
    Assert-Exact ($serviceManifest.schema -ceq 'cantor-supervised-local-lifecycle-evidence-manifest/0.1' -and $serviceManifest.profile -ceq 'cantor-service-supervisor-state/0.1') 'service lifecycle evidence identity differs'
    Assert-Exact ($baseline.profile -ceq 'cantor-self-hosted-anchor-evidence/0.2' -and [bool]$baseline.proof_complete) 'semantic baseline identity or proof differs'
    Assert-Exact (@($baseline.queries).Count -eq 3) 'semantic query count differs'
    Assert-Exact ([int]($baseline.queries | Measure-Object -Property ambiguous_count -Sum).Sum -eq 48) 'semantic ambiguity account differs'
    Assert-Exact ([int]($baseline.queries | Measure-Object -Property compact_record_count -Sum).Sum -eq 0) 'semantic compact account differs'
    Assert-Exact ($correction.profile -ceq 'cantor-semantic-anchor-correction-catalogue/0.3' -and $correction.training_status -ceq 'training_not_authorized') 'correction catalogue identity or training boundary differs'
    Assert-Exact (@($correction.examples).Count -eq 3 -and @($correction.examples | Where-Object { $null -eq $_.target_unit_id }).Count -eq 3) 'real curator target account differs'
    Assert-Exact ($curation.profile -ceq 'cantor-semantic-anchor-synthetic-curation-fixture/0.1' -and $curation.policy.use_status -ceq 'SyntheticFixtureOnly' -and $curation.receipt.use_status -ceq 'SyntheticFixtureOnly') 'synthetic curation status differs'
    Assert-Exact ($p1Release.profile -ceq 'cantor-provider-free-shell-release-manifest/0.1' -and $p1Release.release_kind -ceq 'provider_free_fixture_shell_release_candidate' -and [int]$p1Release.proof_count -eq 17) 'P1 release identity differs'
    Assert-Exact (-not [bool]$p1Release.capabilities.live_provider_execution -and -not [bool]$p1Release.capabilities.physical_persistence -and -not [bool]$p1Release.capabilities.external_effects -and -not [bool]$p1Release.capabilities.remote_execution -and -not [bool]$p1Release.capabilities.fpga_execution -and -not [bool]$p1Release.capabilities.minecraft_scope) 'P1 release capability denial differs'
    Assert-Exact ($p1Witness.profile -ceq 'cantor-discovery-inspection-witness/0.1' -and -not [bool]$p1Witness.provider_execution_claimed -and -not [bool]$p1Witness.persistence_claimed -and -not [bool]$p1Witness.semantic_relevance_claimed) 'P1 witness boundary differs'
    Assert-Exact ($lifecycle.probe -ceq 'cantor_lifecycle_bridge_probe' -and $lifecycle.status -ceq 'passed' -and -not [bool]$lifecycle.provider_contacted -and -not [bool]$lifecycle.private_reasoning_recorded) 'lifecycle provider-free identity differs'
    Assert-Exact ([uint64]$lifecycle.comparison.stateless_transport_argument_bytes -eq 124144 -and [uint64]$lifecycle.comparison.custody_transport_argument_bytes -eq 1200 -and [uint64]$lifecycle.comparison.transport_bytes_saved -eq 122944 -and [uint16]$lifecycle.comparison.custody_to_stateless_argument_basis_points -eq 96) 'lifecycle byte comparison differs'
    Assert-Exact ([bool]$lifecycle.restart_trial.old_handle_refused -and -not [bool]$lifecycle.restart_trial.persistence_claimed) 'lifecycle restart-loss boundary differs'
    Assert-Exact ($providerUnavailable.status -ceq 'provider_unavailable' -and @($providerUnavailable.trials).Count -eq 0 -and @($providerUnavailable.custody_registrations_outside_measured_steady_state).Count -eq 0) 'provider-unavailable source evidence differs'
    Assert-Exact ($providerUnavailableVerification.profile -ceq 'cantor-lifecycle-provider-unavailable-evidence-verification/0.1' -and $providerUnavailableVerification.status -ceq 'provider_unavailable_verified' -and -not [bool]$providerUnavailableVerification.provider_contacted -and [int]$providerUnavailableVerification.trial_count -eq 0 -and [int]$providerUnavailableVerification.registration_count -eq 0) 'provider-unavailable verification differs'

    $evidenceState = Get-EvidenceState
    Assert-Exact ($evidenceState.current_manifest_count -ge 23 -and $evidenceState.artifact_reference_count -ge 1030 -and $evidenceState.stale_reference_count -eq 0) 'recursive evidence state differs'

    $artifacts = @(
        Get-ArtifactIdentity 'semantic_anchor_baseline' 'experiments/semantic_anchor_catalogue_slice5a/self_hosted_anchor_evidence.json'
        Get-ArtifactIdentity 'semantic_anchor_correction_catalogue' 'experiments/semantic_anchor_catalogue_slice5c/correction_catalogue.json'
        Get-ArtifactIdentity 'semantic_anchor_synthetic_curation_fixture' 'experiments/semantic_anchor_catalogue_slice5f/synthetic_curator_selection_fixture.json'
        Get-ArtifactIdentity 'iterative_attention_provider_free_release' 'experiments/iterative_attention_procedure_loop_p1/artifacts/provider_free_shell_release_manifest_v1.json'
        Get-ArtifactIdentity 'iterative_attention_discovery_inspection_witness' 'experiments/iterative_attention_procedure_loop_p1/artifacts/discovery_inspection_witness_v1.json'
        Get-ArtifactIdentity 'lifecycle_provider_independent_bridge_probe' 'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_independent_bridge_probe.json'
        Get-ArtifactIdentity 'lifecycle_provider_unavailable_probe' 'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe.json'
        Get-ArtifactIdentity 'lifecycle_provider_unavailable_verification' 'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe_verification.json'
    )

    [ordered]@{
        profile = 'cantor-local-product-developer-alpha-acceptance/0.1'
        status = 'provider_free_developer_alpha_verified_with_declared_gaps'
        source_commit = $SourceCommit
        artifacts = $artifacts
        component_acceptance = [ordered]@{
            self_hosted_corpus = 'evidence_manifest_profile_and_3_417_360_counts_verified'
            supervised_local_service = 'historical_evidence_manifest_profile_verified_no_current_process_claim'
            semantic_anchor_catalogue = 'slice5f_protocol_verified_real_targets_null'
            iterative_attention = 'provider_free_slice8b_chain_and_capability_denials_verified'
            lifecycle_tool_loop = 'provider_independent_bridge_and_restart_loss_verified'
            live_provider = 'provider_unavailable_zero_trials'
        }
        evidence_state = $evidenceState
        release_stage = [ordered]@{
            developer_alpha = 'satisfied_provider_free'
            private_beta = 'partial'
            operator_product = 'not_satisfied'
            production_product = 'not_satisfied'
        }
        missing_private_beta_acceptance = @(
            'single_install_configure_start_health_exercise_stop_rollback_workflow'
            'representative_task_outcomes_under_one_release_identity'
            'live_provider_compatibility_when_exact_pinned_provider_is_available'
        )
        missing_operator_product_acceptance = @(
            'supported_distribution_and_upgrade_policy'
            'trust_root_and_secret_lifecycle'
            'configuration_migration_diagnostics_and_support_policy'
        )
        missing_production_acceptance = @(
            'threat_model_and_external_trust_anchor'
            'recovery_observability_slo_and_sustained_workload'
            'security_review_and_deployment_support'
        )
        capability_denials = @(
            'live_provider_success'
            'production_authentication'
            'durable_or_distributed_custody'
            'external_effect_execution'
            'automatic_remote_access'
            'fpga_execution'
            'minecraft_scope'
        )
        non_authority_statement = 'This artifact verifies the current provider-free developer-alpha evidence boundary. It does not prove installation, a current service process, live provider behavior, semantic truth, permission, safety, effects, operator readiness, or production fitness.'
    }
}

if ($ExecuteFocused) {
    Invoke-FocusedVerifier 'semantic curation fixture' {
        & cargo run -q -p cantor_core --bin cantor-semantic-anchor-curation --release -- `
            --verify-synthetic-fixture `
            experiments/semantic_anchor_catalogue_slice5a/self_hosted_anchor_evidence.json `
            experiments/semantic_anchor_catalogue_slice5f/synthetic_curator_selection_fixture.json
    }
    Invoke-FocusedVerifier 'semantic correction catalogue' {
        & (Join-Path $PSScriptRoot 'build_semantic_anchor_correction_catalogue.ps1') -VerifyOnly
    }
    Invoke-FocusedVerifier 'semantic controlled measurement' {
        & (Join-Path $PSScriptRoot 'measure_self_hosted_anchor_evidence.ps1') -VerifyOnly
    }
    Invoke-FocusedVerifier 'semantic curator tests' {
        & cargo test -q -p cantor_core --test semantic_anchor_curation --locked --offline
    }
    Invoke-FocusedVerifier 'lifecycle tool-loop evidence' {
        & (Join-Path $PSScriptRoot 'test_lifecycle_tool_loop_measurement.ps1') -UseWsl:$UseWslFocusedLane
    }
}
elseif ($UseWslFocusedLane) {
    throw 'UseWslFocusedLane requires ExecuteFocused'
}

if ($VerifyOnly) {
    $observed = Read-Json $OutputPath
    $expected = New-AcceptanceReport ([string]$observed.source_commit)
    $observedNormalized = $observed | ConvertTo-Json -Depth 100 -Compress
    $expectedNormalized = $expected | ConvertTo-Json -Depth 100 -Compress
    Assert-Exact ($observedNormalized -ceq $expectedNormalized) 'local product acceptance report differs from exact current replay'
    Write-Output "local_product_acceptance_verified=true artifacts=$(@($observed.artifacts).Count) manifests=$($observed.evidence_state.current_manifest_count) references=$($observed.evidence_state.artifact_reference_count)"
    return
}

$head = (& git -C $root rev-parse HEAD).Trim()
Assert-Exact ($LASTEXITCODE -eq 0) 'unable to resolve source commit'
$report = New-AcceptanceReport $head
$outputParent = Split-Path -Parent $output
if (-not [string]::IsNullOrWhiteSpace($outputParent)) {
    [IO.Directory]::CreateDirectory($outputParent) | Out-Null
}
[IO.File]::WriteAllText($output, "$(($report | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
Write-Output "local_product_acceptance_written=$output artifacts=$(@($report.artifacts).Count)"
