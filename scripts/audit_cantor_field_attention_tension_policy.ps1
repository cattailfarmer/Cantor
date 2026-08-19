[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$analysisPath = Join-Path $PSScriptRoot "analyze_cantor_field_attention_tension_policy.ps1"
$summaryPath = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\cross_pass_tension_policy_analysis_v1.json"

function Assert-Exact {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [AllowNull()] $Actual,
        [AllowNull()] $Expected
    )
    if ($Actual -cne $Expected) {
        throw "$Name mismatch: expected '$Expected', observed '$Actual'"
    }
}

$analysis = & $analysisPath | ConvertFrom-Json
$summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json

Assert-Exact "summary profile" $summary.profile "cantor-field-attention-tension-policy-summary/0.1"
Assert-Exact "analysis profile" $analysis.profile $summary.analysis_profile
Assert-Exact "analysis script" $analysis.analysis_script $summary.analysis_script
Assert-Exact "corpus" $analysis.corpus $summary.corpus
Assert-Exact "ordered corpus identity" $analysis.ordered_cycle_report_set_sha256 $summary.ordered_cycle_report_set_sha256

$countPairs = @(
    @("cycle reports", $analysis.cycle_report_count, $summary.counts.cycle_reports),
    @("provider reports", $analysis.provider_report_count, $summary.counts.provider_reports),
    @("candidate delineation reports", $analysis.candidate_delineation_report_count, $summary.counts.candidate_delineation_reports),
    @("completed reports", $analysis.current_completed_report_count, $summary.counts.current_completed_reports),
    @("provider completed reports", $analysis.current_provider_completed_report_count, $summary.counts.current_provider_completed_reports),
    @("completed with signals", $analysis.current_completed_with_signal_count, $summary.counts.current_completed_with_signals),
    @("completed without signals", $analysis.current_completed_without_signal_count, $summary.counts.current_completed_without_signals),
    @("completed typed conflicts", $analysis.completed_typed_whole_proposal_conflict_signal_count, $summary.counts.completed_typed_whole_proposal_conflict_signals),
    @("completed epistemic caveats", $analysis.completed_epistemic_fixture_caveat_count, $summary.counts.completed_epistemic_fixture_caveats),
    @("counterfactual newly rejected", $analysis.strict_any_signal_blocks.newly_rejected_completed_reports, $summary.strict_any_signal_blocks_counterfactual.newly_rejected_completed_reports),
    @("counterfactual remaining", $analysis.strict_any_signal_blocks.remaining_completed_reports, $summary.strict_any_signal_blocks_counterfactual.remaining_completed_reports)
)
foreach ($pair in $countPairs) {
    Assert-Exact $pair[0] ([decimal]$pair[1]) ([decimal]$pair[2])
}

$completedRows = @($analysis.rows | Where-Object { $_.terminal_state -ceq "completed" })
$providerCompletedRows = @($completedRows | Where-Object { -not $_.fixture })
$fixtureCompletedRows = @($completedRows | Where-Object { $_.fixture })
if (@($providerCompletedRows | Where-Object { $_.typed_whole_proposal_conflict_count -ne 4 }).Count -ne 0) {
    throw "A provider completion does not retain exactly four typed whole-proposal conflicts"
}
if ($fixtureCompletedRows.Count -ne 1 -or
    $fixtureCompletedRows[0].typed_whole_proposal_conflict_count -ne 0 -or
    $fixtureCompletedRows[0].epistemic_fixture_caveat_count -ne 4) {
    throw "The deterministic fixture no longer supplies the distinct four-caveat, zero-typed-conflict case"
}

$requiredClasses = @(
    "semantic_conflict",
    "semantic_exclusion",
    "semantic_uncertainty",
    "host_boundary_violation",
    "epistemic_limit",
    "legacy_unclassified"
)
Assert-Exact "successor class catalogue" (@($summary.required_successor_signal_classes) -join "`n") ($requiredClasses -join "`n")

[pscustomobject]@{
    profile = "cantor-field-attention-tension-policy-audit/0.1"
    result = "passed"
    ordered_cycle_report_set_sha256 = $analysis.ordered_cycle_report_set_sha256
    candidate_delineation_reports = $analysis.candidate_delineation_report_count
    provider_completed_with_four_typed_conflicts = $providerCompletedRows.Count
    fixture_completed_with_four_epistemic_caveats = $fixtureCompletedRows.Count
    strict_any_signal_blocks_remaining_completed = $analysis.strict_any_signal_blocks.remaining_completed_reports
    authority = "effect-free evidence consistency audit only; no P1 runtime or policy authority"
} | ConvertTo-Json -Depth 4
