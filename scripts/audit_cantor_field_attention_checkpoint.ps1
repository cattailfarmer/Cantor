[CmdletBinding()]
param(
    [switch] $IncludeEvox2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-JsonAudit {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $raw = & $Path | Out-String
    return $raw | ConvertFrom-Json
}

function Assert-Exact {
    param(
        [Parameter(Mandatory = $true)] [bool] $Condition,
        [Parameter(Mandatory = $true)] [string] $Message
    )
    if (-not $Condition) { throw $Message }
}

$acceptance = Invoke-JsonAudit (Join-Path $PSScriptRoot "test_cantor_field_attention_cycle_p0.ps1")
$closure = Invoke-JsonAudit (Join-Path $PSScriptRoot "audit_cantor_field_attention_closure.ps1")
$requirements = Invoke-JsonAudit (Join-Path $PSScriptRoot "audit_cantor_field_attention_requirement_coverage.ps1")
$tension = Invoke-JsonAudit (Join-Path $PSScriptRoot "audit_cantor_field_attention_tension_policy.ps1")
$manifestLines = @(& (Join-Path $PSScriptRoot "rehash_current_evidence_manifests.ps1") -VerifyOnly)
$manifestStatus = ($manifestLines -join " ").Trim()

Assert-Exact ($acceptance.status -ceq "passed") "field-cycle offline acceptance did not pass"
Assert-Exact ($acceptance.focused_test_count -eq 30) "field-cycle focused test count changed"
Assert-Exact ($closure.status -ceq "passed" -and $closure.cost_corpus_recomputed) "field-cycle closure audit did not pass"
Assert-Exact ($requirements.status -ceq "reconciled_with_open_requirement_residual") "field-cycle requirement disposition changed"
Assert-Exact ((@($requirements.partially_satisfied_requirement_ids) -join ",") -ceq "FADL-011") "field-cycle partial requirement set changed"
Assert-Exact (
    (@($requirements.open_residual_ids) -join ",") -ceq
    "FADL_F009,FADL_R001,FADL_R002,FADL_R003,FADL_R004,FADL_R005,FADL_R006,FADL_R007"
) "field-cycle open residual set changed"
Assert-Exact (-not $requirements.p1_implementation_authority) "field-cycle P1 implementation authority changed"
Assert-Exact ($tension.result -ceq "passed") "field-cycle tension policy audit did not pass"
Assert-Exact ($manifestStatus -ceq "current_manifests=23 artifact_references=1030 stale=0") "current evidence manifest status changed"

$deployment = $null
if ($IncludeEvox2) {
    $deployment = Invoke-JsonAudit (Join-Path $PSScriptRoot "audit_cantor_field_attention_evox2_deployment.ps1")
    Assert-Exact ($deployment.status -ceq "passed_with_open_acl_residual") "EVO-X2 deployment disposition changed"
    Assert-Exact $deployment.replay.all_remote_files_equal_tracked_local_bytes "EVO-X2 remote report bytes diverged"
}

$result = [ordered]@{
    profile = "cantor-field-attention-checkpoint-audit/0.1"
    status = "verified_with_declared_residuals"
    offline_acceptance = [ordered]@{
        status = $acceptance.status
        focused_test_count = $acceptance.focused_test_count
        source_count = $acceptance.source_count
        field_count = $acceptance.field_count
        core_report_count = $acceptance.report_count
        provider_report_count = $acceptance.cost_analysis.provider_report_count
    }
    closure = [ordered]@{
        status = $closure.status
        final_verifier_sha256 = $closure.final_verifier_sha256
        cost_corpus_recomputed = $closure.cost_corpus_recomputed
        remote_reexecution = $closure.remote_reexecution
    }
    requirements = [ordered]@{
        status = $requirements.status
        requirement_count = $requirements.requirement_count
        partially_satisfied_requirement_ids = @($requirements.partially_satisfied_requirement_ids)
        open_residual_ids = @($requirements.open_residual_ids)
        p1_implementation_authority = $requirements.p1_implementation_authority
    }
    semantic_tension = [ordered]@{
        status = $tension.result
        candidate_delineation_reports = $tension.candidate_delineation_reports
        strict_any_signal_blocks_remaining_completed = $tension.strict_any_signal_blocks_remaining_completed
    }
    evidence_manifests = $manifestStatus
    evox2 = if ($null -eq $deployment) {
        [ordered]@{
            included = $false
            effect = "not contacted"
        }
    } else {
        [ordered]@{
            included = $true
            status = $deployment.status
            verifier_sha256_before = $deployment.verifier.sha256_before
            verifier_sha256_after = $deployment.verifier.sha256_after
            verified_report_count = $deployment.replay.verified_count
            ordered_report_file_set_sha256 = $deployment.replay.ordered_file_set_sha256
            provider_requests_made_by_audit = $deployment.replay.provider_requests_made_by_audit
        }
    }
    authority = "checkpoint verification only; local acceptance may refresh build cache and optional EVO-X2 mode is read-only; no semantic P1 runtime production or effect authority"
}

if ($IncludeEvox2) {
    $receiptPath = Join-Path $PSScriptRoot "..\experiments\cantor_field_cycle_p0\checkpoint_audit_v1.json"
    $receipt = Get-Content -Raw -LiteralPath $receiptPath | ConvertFrom-Json
    $actualCanonical = $result | ConvertTo-Json -Depth 20 -Compress
    $expectedCanonical = $receipt | ConvertTo-Json -Depth 20 -Compress
    Assert-Exact ($actualCanonical -ceq $expectedCanonical) "EVO-X2 composite checkpoint differs from pinned receipt"
}

$result | ConvertTo-Json -Depth 8
