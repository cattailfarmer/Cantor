[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Invoke-JsonAudit {
    param([Parameter(Mandatory)] [string] $Path)

    $raw = & $Path | Out-String
    return $raw | ConvertFrom-Json
}

function Assert-Exact {
    param(
        [Parameter(Mandatory)] [bool] $Condition,
        [Parameter(Mandatory)] [string] $Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

$fieldCheckpoint = Invoke-JsonAudit (Join-Path $PSScriptRoot 'audit_cantor_field_attention_checkpoint.ps1')
$reproducibility = Invoke-JsonAudit (Join-Path $PSScriptRoot 'audit_cantor_field_attention_reproducible_windows_build.ps1')

Assert-Exact ($fieldCheckpoint.profile -ceq 'cantor-field-attention-checkpoint-audit/0.1') 'Field-attention checkpoint profile changed.'
Assert-Exact ($fieldCheckpoint.status -ceq 'verified_with_declared_residuals') 'Field-attention checkpoint did not pass.'
Assert-Exact (-not $fieldCheckpoint.requirements.p1_implementation_authority) 'Field-attention checkpoint unexpectedly grants P1 authority.'
Assert-Exact ($fieldCheckpoint.evox2.included -eq $false) 'Local proof checkpoint must not contact EVO-X2.'
Assert-Exact ($reproducibility.profile -ceq 'cantor-field-attention-reproducible-windows-build-audit/0.1') 'Reproducibility audit profile changed.'
Assert-Exact ($reproducibility.result -ceq 'passed_with_declared_boundaries') 'Reproducibility audit did not pass.'
Assert-Exact ($reproducibility.source_commit -ceq 'b4532cff5876d94b116bf7ab44ee5017d70ce5ea') 'Pinned reproducibility source commit changed.'
Assert-Exact ($reproducibility.receipt_sha256 -ceq 'f284a021919a597368e13bed14852997dfa424bd524db145535ece93a345c5b8') 'Pinned reproducibility receipt changed.'
Assert-Exact ($reproducibility.artifact_sha256 -ceq '983cbd21308456d9a920f1dde98359d08e1d434ef5fe0133b3e9159653ae838b') 'Pinned reproducibility artifact changed.'
Assert-Exact ($reproducibility.git_anchor_count -eq 5) 'Reproducibility Git anchor count changed.'
Assert-Exact ($reproducibility.current_branch -ceq 'codex/self-hosted-corpus') 'Reproducibility publication branch changed.'
Assert-Exact ($reproducibility.upstream -ceq 'origin/codex/self-hosted-corpus') 'Reproducibility publication upstream changed.'
Assert-Exact $reproducibility.head_contains_latest_git_anchor 'Current HEAD does not contain the latest reproducibility anchor.'
Assert-Exact $reproducibility.upstream_contains_all_git_anchors 'Configured upstream does not contain every reproducibility anchor.'
Assert-Exact ($reproducibility.provider_request_count -eq 0) 'Reproducibility audit reported provider access.'

[ordered]@{
    profile = 'cantor-field-attention-local-proof-checkpoint/0.1'
    status = 'verified_with_declared_residuals'
    field_attention = [ordered]@{
        status = $fieldCheckpoint.status
        focused_test_count = $fieldCheckpoint.offline_acceptance.focused_test_count
        provider_report_count = $fieldCheckpoint.offline_acceptance.provider_report_count
        partially_satisfied_requirement_ids = @($fieldCheckpoint.requirements.partially_satisfied_requirement_ids)
        open_residual_ids = @($fieldCheckpoint.requirements.open_residual_ids)
        p1_implementation_authority = $fieldCheckpoint.requirements.p1_implementation_authority
        evidence_manifests = $fieldCheckpoint.evidence_manifests
    }
    reproducible_windows_build = [ordered]@{
        status = $reproducibility.result
        source_commit = $reproducibility.source_commit
        receipt_sha256 = $reproducibility.receipt_sha256
        artifact_sha256 = $reproducibility.artifact_sha256
        git_anchor_count = $reproducibility.git_anchor_count
        publication_branch = $reproducibility.current_branch
        publication_upstream = $reproducibility.upstream
        current_head_contains_latest_anchor = $reproducibility.head_contains_latest_git_anchor
        upstream_contains_all_anchors = $reproducibility.upstream_contains_all_git_anchors
        provider_request_count = $reproducibility.provider_request_count
    }
    evox2 = [ordered]@{
        included = $false
        effect = 'not contacted'
    }
    authority = 'read-only local proof aggregation only; no fresh rebuild cross-host deployment signing semantic P1 or remote-effect authority'
} | ConvertTo-Json -Depth 8
