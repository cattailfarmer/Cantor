[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$evidenceRoot = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0"
$compiledConflict = "typed assessment marks the whole proposal conflicted without member attribution"
$fixtureCaveat = "Model agreement remains correlated evidence rather than truth."

$reports = @()
foreach ($file in @(Get-ChildItem -LiteralPath $evidenceRoot -Recurse -Filter "*.json" -File | Sort-Object FullName)) {
    try {
        $report = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    } catch {
        continue
    }
    if ($null -eq $report.PSObject.Properties["profile"] -or
        $report.profile -cne "cantor-field-attention-cycle/0.1") {
        continue
    }
    $relativePath = $file.FullName.Substring($evidenceRoot.Length + 1).Replace("\", "/")
    $isFixture = $report.provider.base_url -ceq "fixture://local"
    $hasCandidate = $null -ne $report.PSObject.Properties["candidate"] -and $null -ne $report.candidate
    $hasDelineation = $null -ne $report.PSObject.Properties["delineation_proposal"] -and $null -ne $report.delineation_proposal
    $hasResult = $null -ne $report.PSObject.Properties["delineation_result"] -and $null -ne $report.delineation_result
    $tensions = @($report.probes | ForEach-Object { @($_.tensions) })
    $exclusions = @($report.probes | ForEach-Object { @($_.exclusions) })
    $uncertainty = @($report.probes | ForEach-Object { @($_.uncertainty) })
    $signalCount = $tensions.Count + $exclusions.Count + $uncertainty.Count
    $reports += [pscustomobject]@{
        path = $relativePath
        file_sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        fixture = $isFixture
        terminal_state = [string]$report.terminal_state
        candidate = $hasCandidate
        delineation = $hasDelineation
        proposal_status = if ($hasDelineation) { [string]$report.delineation_proposal.status } else { $null }
        result_status = if ($hasResult) { [string]$report.delineation_result.status } else { $null }
        probe_count = @($report.probes).Count
        tension_count = $tensions.Count
        exclusion_count = $exclusions.Count
        uncertainty_count = $uncertainty.Count
        signal_count = $signalCount
        typed_whole_proposal_conflict_count = @($tensions | Where-Object { $_ -ceq $compiledConflict }).Count
        epistemic_fixture_caveat_count = @($tensions | Where-Object { $_ -ceq $fixtureCaveat }).Count
    }
}

$identityText = ($reports | ForEach-Object { "$($_.path) $($_.file_sha256)" }) -join "`n"
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $orderedCorpusSha256 = -join ($sha256.ComputeHash(
        [Text.Encoding]::UTF8.GetBytes($identityText)
    ) | ForEach-Object { $_.ToString("x2") })
} finally {
    $sha256.Dispose()
}

$candidateDelineations = @($reports | Where-Object { $_.candidate -and $_.delineation })
$completed = @($candidateDelineations | Where-Object { $_.terminal_state -ceq "completed" })
$completedWithSignals = @($completed | Where-Object { $_.signal_count -gt 0 })
$providerCompleted = @($completed | Where-Object { -not $_.fixture })

[pscustomobject]@{
    profile = "cantor-field-attention-tension-policy-analysis/0.1"
    analysis_script = "scripts/analyze_cantor_field_attention_tension_policy.ps1"
    corpus = "experiments/cantor_field_cycle_p0"
    ordered_cycle_report_set_sha256 = $orderedCorpusSha256
    cycle_report_count = $reports.Count
    provider_report_count = @($reports | Where-Object { -not $_.fixture }).Count
    candidate_delineation_report_count = $candidateDelineations.Count
    current_completed_report_count = $completed.Count
    current_provider_completed_report_count = $providerCompleted.Count
    current_completed_with_signal_count = $completedWithSignals.Count
    current_completed_without_signal_count = @($completed | Where-Object { $_.signal_count -eq 0 }).Count
    completed_typed_whole_proposal_conflict_signal_count = ($completed | Measure-Object -Property typed_whole_proposal_conflict_count -Sum).Sum
    completed_epistemic_fixture_caveat_count = ($completed | Measure-Object -Property epistemic_fixture_caveat_count -Sum).Sum
    strict_any_signal_blocks = [pscustomobject]@{
        newly_rejected_completed_reports = $completedWithSignals.Count
        remaining_completed_reports = @($completed | Where-Object { $_.signal_count -eq 0 }).Count
        interpretation = "Falsifies array-presence-as-pertinence; it collapses typed semantic conflict and an explicit non-truth caveat."
    }
    required_successor_distinctions = @(
        "typed semantic conflict exclusion or uncertainty over the candidate or relation scope",
        "existing host identity or relation boundary violation",
        "epistemic non-authority caveat retained without pretending it is semantic conflict",
        "legacy untyped signal that cannot be promoted by text classification"
    )
    rows = @($candidateDelineations | Select-Object path, fixture, terminal_state, proposal_status, result_status, probe_count, tension_count, exclusion_count, uncertainty_count, signal_count, typed_whole_proposal_conflict_count, epistemic_fixture_caveat_count)
    authority = "effect-free retrospective policy analysis only; no P1 runtime or blocking authority"
} | ConvertTo-Json -Depth 8
