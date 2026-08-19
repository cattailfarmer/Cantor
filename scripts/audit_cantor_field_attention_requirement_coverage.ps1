[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

function Assert-Exact {
    param(
        [Parameter(Mandatory = $true)] [bool] $Condition,
        [Parameter(Mandatory = $true)] [string] $Message
    )
    if (-not $Condition) { throw $Message }
}

function Read-WorkspaceText {
    param([Parameter(Mandatory = $true)] [string] $RelativePath)
    $path = Join-Path $workspaceRoot $RelativePath
    Assert-Exact (Test-Path -LiteralPath $path -PathType Leaf) "missing coverage surface: $RelativePath"
    return Get-Content -LiteralPath $path -Raw
}

function Get-Ids {
    param(
        [Parameter(Mandatory = $true)] [string] $Text,
        [Parameter(Mandatory = $true)] [string] $Pattern
    )
    return @([regex]::Matches($Text, $Pattern) | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
}

function Assert-IdSet {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [string[]] $Actual,
        [Parameter(Mandatory = $true)] [string[]] $Expected
    )
    Assert-Exact (($Actual -join "`n") -ceq ($Expected -join "`n")) "$Name requirement set changed"
}

$paths = [ordered]@{
    canonical = "specifications\Cantor_Field_Attention_Delineation_Latch_P0.sop"
    matrix = "feature_support\Cantor_Field_Attention_Delineation_Latch_P0_Requirement_Matrix.sop"
    review = "feature_support\reviews\FieldAttentionCycleP0CompletionReview.sop"
    proof = "proofs\Cantor_Field_Attention_Delineation_Latch_P0_Proof.sop"
    plan = "plans\Cantor_Field_Attention_Delineation_Latch_P0_Plan.sop"
    solution = "solutions\Cantor_Field_Attention_Delineation_Latch_P0_Solution.sop"
    faults = "narrative\operational_faults\1787093837058_field_attention_cycle_p0_faults.sop"
    reentry = "narrative\reentry\Cantor_Field_Attention_Semantic_Tension_P1_Reentry.sop"
    deployment_observation = "experiments\cantor_field_cycle_p0\evox2_h8_read_only_audit_2026-08-18.json"
    deployment_turn = "narrative\turns\1787101136441_cantor_field_attention_evox2_deployment_audit.sop"
}
$texts = @{}
foreach ($entry in $paths.GetEnumerator()) {
    $texts[$entry.Key] = Read-WorkspaceText -RelativePath $entry.Value
}

$requirements = @(1..13 | ForEach-Object { "FADL-{0:D3}" -f $_ })
$surfacePatterns = [ordered]@{
    canonical = '(?m)^\s*\+ \[(FADL-\d{3})\]'
    matrix = '(?m)^\s*\+ \[(FADL-\d{3})\]'
    review = '(?m)^\s*\+ \[(FADL-\d{3})\]'
    proof = '(?m)^& \[(FADL-\d{3})\]'
}
foreach ($surface in $surfacePatterns.Keys) {
    $ids = Get-Ids -Text $texts[$surface] -Pattern $surfacePatterns[$surface]
    Assert-IdSet -Name $surface -Actual $ids -Expected $requirements
}

foreach ($requirement in $requirements) {
    Assert-Exact ([regex]::IsMatch($texts.matrix, "(?m)^\s*\+ \[$requirement\].*support_status is passed")) "matrix does not pass $requirement"
    Assert-Exact ([regex]::IsMatch($texts.review, "(?m)^\s*\+ \[$requirement\] is passed")) "completion review does not pass $requirement"
    Assert-Exact ([regex]::IsMatch($texts.proof, "(?m)^& \[$requirement\] passes")) "proof does not pass $requirement"
}
foreach ($phase in 1..6) {
    Assert-Exact ([regex]::IsMatch($texts.plan, "(?m)^\s*\+ \[P$phase\] is completed")) "plan phase P$phase is not completed"
}
Assert-Exact ($texts.solution.Contains("& [Boundary] is experimental attention I/O only")) "solution boundary is missing"
Assert-Exact ($texts.proof.Contains("[AcceptanceConclusion] is FADL-001 through FADL-013 satisfied for experimental P0 mechanism scope")) "proof conclusion changed"

$faultIds = @(1..14 | ForEach-Object { "FADL_F{0:D3}" -f $_ })
$residualIds = @(1..5 | ForEach-Object { "FADL_R{0:D3}" -f $_ })
$ledgerIds = Get-Ids -Text $texts.faults -Pattern '(?m)^& \[(FADL_[FR]\d{3})\]'
Assert-IdSet -Name "fault and residual ledger" -Actual $ledgerIds -Expected @(($faultIds + $residualIds) | Sort-Object)

$headers = @([regex]::Matches($texts.faults, '(?m)^& \[(FADL_[FR]\d{3})\]'))
$statuses = [ordered]@{}
for ($index = 0; $index -lt $headers.Count; $index++) {
    $start = $headers[$index].Index
    $end = if ($index + 1 -lt $headers.Count) { $headers[$index + 1].Index } else { $texts.faults.Length }
    $block = $texts.faults.Substring($start, $end - $start)
    $statusMatch = [regex]::Match($block, '(?m)^\s*\+ \[status\] is ([^\r\n]+)')
    Assert-Exact $statusMatch.Success "ledger entry has no status: $($headers[$index].Groups[1].Value)"
    $statuses[$headers[$index].Groups[1].Value] = $statusMatch.Groups[1].Value
}

$openIds = @($statuses.Keys | Where-Object { $statuses[$_] -like "open_*" } | Sort-Object)
$expectedOpenIds = @("FADL_F009", "FADL_R001", "FADL_R002", "FADL_R003", "FADL_R004", "FADL_R005")
Assert-IdSet -Name "open residual" -Actual $openIds -Expected $expectedOpenIds
Assert-Exact ($statuses["FADL_F011"] -ceq "closed_for_current_artifact_environmental_recurrence_possible") "current artifact Application Control closure changed"

$deploymentObservationPath = Join-Path $workspaceRoot $paths.deployment_observation
$deploymentObservationSha256 = (Get-FileHash -LiteralPath $deploymentObservationPath -Algorithm SHA256).Hash.ToLowerInvariant()
Assert-Exact ($texts.deployment_turn.Contains("@ [evidence_sha256] $deploymentObservationSha256")) "deployment observation is not bound by its turn"
$deploymentObservation = $texts.deployment_observation | ConvertFrom-Json
Assert-Exact ($deploymentObservation.status -ceq "passed_with_open_acl_residual") "deployment ACL residual is not visible"
Assert-Exact $deploymentObservation.remote_replay.all_remote_files_equal_tracked_local_bytes "remote report byte equality is not preserved"

Assert-Exact ($texts.reentry.Contains("A new user-preserved source and SJS specification remain mandatory before implementation.")) "P1 source authority boundary changed"
Assert-Exact ($texts.reentry.Contains("no implementation should choose the vocabulary status mapping or legacy migration policy implicitly")) "P1 implementation refusal changed"

$summaryPath = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\requirement_coverage_audit_v1.json"
$summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
Assert-Exact ($summary.profile -ceq "cantor-field-attention-requirement-coverage-audit/0.1") "coverage summary profile changed"
Assert-Exact ($summary.audit_script -ceq "scripts/audit_cantor_field_attention_requirement_coverage.ps1") "coverage summary script identity changed"
Assert-Exact ($summary.requirement_count -eq $requirements.Count) "coverage summary requirement count changed"
Assert-Exact ($summary.completed_plan_phase_count -eq 6) "coverage summary plan count changed"
Assert-Exact ($summary.fault_count -eq $faultIds.Count) "coverage summary fault count changed"
Assert-Exact ($summary.residual_record_count -eq $residualIds.Count) "coverage summary residual count changed"
Assert-Exact ((@($summary.open_residual_ids) -join "`n") -ceq ($openIds -join "`n")) "coverage summary open residuals changed"
Assert-Exact ($summary.deployment_observation_sha256 -ceq $deploymentObservationSha256) "coverage summary deployment identity changed"
Assert-Exact (-not $summary.p1_implementation_authority) "coverage summary improperly grants P1 authority"

[pscustomobject]@{
    profile = "cantor-field-attention-requirement-coverage-audit/0.1"
    status = "passed"
    requirement_count = $requirements.Count
    requirement_surfaces = @($surfacePatterns.Keys)
    completed_plan_phase_count = 6
    fault_count = $faultIds.Count
    residual_record_count = $residualIds.Count
    open_residual_ids = $openIds
    closed_current_artifact_environmental_fault = "FADL_F011"
    deployment_observation_sha256 = $deploymentObservationSha256
    p1_implementation_authority = $false
    authority = "effect-free traceability and current-byte audit only; no source specification runtime or production authority"
} | ConvertTo-Json -Depth 6
