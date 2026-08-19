[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

function Invoke-CargoJson {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & cargo.exe @Arguments 2>&1
        $exit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorPreference
    }
    if ($exit -ne 0) {
        throw "$Label failed: $($output -join [Environment]::NewLine)"
    }
    return (($output -join [Environment]::NewLine) | ConvertFrom-Json)
}

function Invoke-CargoCheck {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & cargo.exe @Arguments 2>&1
        $exit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorPreference
    }
    if ($exit -ne 0) {
        throw "$Label failed: $($output -join [Environment]::NewLine)"
    }
}

$sources = @(
    [pscustomobject]@{
        Path = "source_documents\2026-08-18_field_attention_delineation_latch\Dictated_Field_Attention_Delineation_Latch_Source.sop"
        Manifest = "source_documents\2026-08-18_field_attention_delineation_latch\Source_Document_Manifest.sop"
        Sha256 = "547066edb0583b6575c563aad88cbb034a86b07f01555ee57ef6e84dd4981f70"
        Bytes = 1325
    },
    [pscustomobject]@{
        Path = "source_documents\2026-08-18_field_attention_request_compiler\Observed_Request_Compiler_Evidence.sop"
        Manifest = "source_documents\2026-08-18_field_attention_request_compiler\Source_Document_Manifest.sop"
        Sha256 = "d5042d1b32870d0451aae57c3fbd8294e9af8c178711865e6c601db016224c5d"
        Bytes = 3751
    },
    [pscustomobject]@{
        Path = "source_documents\2026-08-18_field_attention_resource_bounds\Observed_Field_Attention_Resource_Bound_Evidence.sop"
        Manifest = "source_documents\2026-08-18_field_attention_resource_bounds\Source_Document_Manifest.sop"
        Sha256 = "1716df7863b26bfb39251dd914eab2e7ef43081e93461f6a24f01794f9025276"
        Bytes = 2160
    },
    [pscustomobject]@{
        Path = "source_documents\2026-08-18_field_attention_fault_assurance\Observed_Field_Attention_Fault_Assurance_Evidence.sop"
        Manifest = "source_documents\2026-08-18_field_attention_fault_assurance\Source_Document_Manifest.sop"
        Sha256 = "2ac898d3bae7330f297bb9949f72c5be61b229731cf096ead548758d8be4eb25"
        Bytes = 2165
    }
)

foreach ($source in $sources) {
    $path = Join-Path $workspaceRoot $source.Path
    $manifestPath = Join-Path $workspaceRoot $source.Manifest
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $bytes = (Get-Item -LiteralPath $path).Length
    $manifest = Get-Content -LiteralPath $manifestPath -Raw
    if ($hash -cne $source.Sha256 -or $bytes -ne $source.Bytes) {
        throw "preserved source identity changed: $($source.Path)"
    }
    if (-not $manifest.Contains("[source_sha256] is $hash") -or
        -not $manifest.Contains("[source_bytes] is $bytes")) {
        throw "source manifest disagrees: $($source.Manifest)"
    }
}

$canonical = Get-Content -LiteralPath (
    Join-Path $workspaceRoot "specifications\Cantor_Field_Attention_Delineation_Latch_P0.sop"
) -Raw
$amendment = Get-Content -LiteralPath (
    Join-Path $workspaceRoot "specifications\amendments\Cantor_Field_Attention_Typed_Request_Compiler_P0.sop"
) -Raw
$resourceAmendment = Get-Content -LiteralPath (
    Join-Path $workspaceRoot "specifications\amendments\Cantor_Field_Attention_Resource_Bounds_P0.sop"
) -Raw
$assuranceAmendment = Get-Content -LiteralPath (
    Join-Path $workspaceRoot "specifications\amendments\Cantor_Field_Attention_Fault_Assurance_P0.sop"
) -Raw
foreach ($document in @($canonical, $amendment, $resourceAmendment, $assuranceAmendment)) {
    if (-not $document.Contains("ad10f10f-d506-48ef-a805-f8b0a133766c")) {
        throw "canonical document omitted the specification satisfaction protocol"
    }
}

Invoke-CargoCheck -Label "focused tests" -Arguments @(
    "test", "-p", "cantor_field_cycle", "--all-targets", "--quiet"
)
Invoke-CargoCheck -Label "focused Clippy" -Arguments @(
    "clippy", "-p", "cantor_field_cycle", "--all-targets", "--", "-D", "warnings"
)

$contract = Invoke-CargoJson -Label "contract" -Arguments @(
    "run", "-q", "-p", "cantor_field_cycle", "--", "contract"
)
if ($contract.profile -cne "cantor-field-attention-cycle/0.1" -or
    $contract.request_profile -cne "cantor-field-attention-requests/0.5" -or
    $contract.probe_count -ne 4 -or
    $contract.minimum_support -ne 3 -or
    $contract.provider_connect_timeout_seconds -ne 5 -or
    $contract.provider_request_timeout_seconds -ne 90 -or
    $contract.max_provider_response_bytes -ne 1048576 -or
    $contract.provider_proxy_policy -cne "disabled" -or
    $contract.provider_redirect_limit -ne 0 -or
    (@($contract.verification_assurance) -join ",") -cne "deterministic_construction,stored_provider_replay,response_backed_fault_replay,structural_runtime_fault_only" -or
    $contract.resource_budgets.element_content_bytes -ne 16384 -or
    $contract.resource_budgets.semantic_field_file_bytes -ne 524288 -or
    $contract.resource_budgets.cycle_report_file_bytes -ne 16777216) {
    throw "discovered contract disagrees with P0"
}

$fields = @(
    [pscustomobject]@{
        Path = "experiments\cantor_field_cycle_p0\attention_cycle_field.json"
        Digest = "136955ea1f1931de88c22cef392377f3a1fa4e6d4bd1de53450cb7e1f598c8e0"
    },
    [pscustomobject]@{
        Path = "experiments\cantor_field_cycle_p0\attention_cycle_forbidden_comembership_field.json"
        Digest = "1fe069762f31c4afe7a2478b210c9a332191eb4099602a6333eb179654c54a71"
    },
    [pscustomobject]@{
        Path = "experiments\cantor_field_cycle_p0\attention_cycle_forbidden_relation_field.json"
        Digest = "f90a4a5682ed4893ac67a742ce3c9c27bb71c826567c26d77fb9fe26b0051331"
    },
    [pscustomobject]@{
        Path = "experiments\cantor_field_cycle_p0\attention_cycle_forbidden_relation_all_kinds_field.json"
        Digest = "821f57f68e1dff8c3469b0815e4dd72cdc38539e327487abd5f574e738f1bba8"
    }
)
foreach ($field in $fields) {
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $digestOutput = & cargo.exe run -q -p cantor_field_cycle -- field-digest (
            Join-Path $workspaceRoot $field.Path
        ) 2>&1
        $exit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorPreference
    }
    if ($exit -ne 0 -or ($digestOutput -join "").Trim() -cne $field.Digest) {
        throw "field digest disagrees: $($field.Path)"
    }
}

$reports = @(
    [pscustomobject]@{ Path = "deterministic_fixture_report.json"; Terminal = "completed"; Latch = "admitted_for_attention"; Assurance = "deterministic_construction" },
    [pscustomobject]@{ Path = "evox2_live_v1.json"; Terminal = "rejected"; Latch = "rejected"; Assurance = "stored_provider_replay" },
    [pscustomobject]@{ Path = "evox2_live_v2.json"; Terminal = "rejected"; Latch = "rejected"; Assurance = "stored_provider_replay" },
    [pscustomobject]@{ Path = "evox2_live_v3_fault.json"; Terminal = "faulted"; Latch = $null; Assurance = "response_backed_fault_replay" },
    [pscustomobject]@{ Path = "evox2_live_v4_fault.json"; Terminal = "faulted"; Latch = $null; Assurance = "response_backed_fault_replay" },
    [pscustomobject]@{ Path = "evox2_live_v5.json"; Terminal = "completed"; Latch = "admitted_for_attention"; Assurance = "stored_provider_replay" },
    [pscustomobject]@{ Path = "evox2_control_v5.json"; Terminal = "control_completed"; Latch = $null; Assurance = "stored_provider_replay" },
    [pscustomobject]@{ Path = "evox2_hostile_boundary_v5.json"; Terminal = "rejected"; Latch = $null; Assurance = "stored_provider_replay" }
    [pscustomobject]@{ Path = "evox2_forbidden_relation_v1.json"; Terminal = "rejected"; Latch = "rejected"; Assurance = "stored_provider_replay" }
    [pscustomobject]@{ Path = "evox2_forbidden_relation_all_kinds_v1.json"; Terminal = "rejected"; Latch = "rejected"; Assurance = "stored_provider_replay" }
)
$verifiedReports = @()
foreach ($report in $reports) {
    $path = Join-Path $workspaceRoot ("experiments\cantor_field_cycle_p0\" + $report.Path)
    $verification = Invoke-CargoJson -Label ("verify " + $report.Path) -Arguments @(
        "run", "-q", "-p", "cantor_field_cycle", "--", "verify", $path
    )
    if (-not $verification.valid -or $verification.terminal_state -cne $report.Terminal -or
        $verification.latch_status -cne $report.Latch -or
        $verification.assurance -cne $report.Assurance) {
        throw "report disposition disagrees: $($report.Path)"
    }
    $verifiedReports += [pscustomobject]@{
        path = $report.Path
        terminal_state = $verification.terminal_state
        latch_status = $verification.latch_status
        exchange_count = $verification.exchange_count
        assurance = $verification.assurance
        report_sha256 = $verification.report_sha256
    }
}
$relationBoundaryReport = Get-Content -LiteralPath (
    Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\evox2_forbidden_relation_all_kinds_v1.json"
) -Raw | ConvertFrom-Json
if ($relationBoundaryReport.delineation_proposal.status -cne "supported" -or
    @($relationBoundaryReport.delineation_result.failed_gates) -notcontains "boundary_conflict" -or
    @($relationBoundaryReport.latch_decision.failed_gates) -notcontains "boundary_conflict") {
    throw "all-kinds relation-boundary report does not prove post-delineation host enforcement"
}

$campaignRoot = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\campaign-field-attend-h1"
$campaignExpectations = @(
    1..5 | ForEach-Object {
        [pscustomobject]@{ Path = ("positive-{0:d2}.json" -f $_); Terminal = "completed"; Latch = "admitted_for_attention" }
    }
) + @(
    1..5 | ForEach-Object {
        [pscustomobject]@{ Path = ("control-{0:d2}.json" -f $_); Terminal = "control_completed"; Latch = $null }
    }
) + @(
    1..3 | ForEach-Object {
        [pscustomobject]@{ Path = ("hostile-{0:d2}.json" -f $_); Terminal = "rejected"; Latch = $null }
    }
)
$campaignCandidate = "683031089a19e019b2b7a30fc09e2b69e3c1df518d6cdf5eb4bd29420571bcac"
$campaignFileHashes = @()
foreach ($expected in $campaignExpectations) {
    $path = Join-Path $campaignRoot $expected.Path
    $verification = Invoke-CargoJson -Label ("verify campaign " + $expected.Path) -Arguments @(
        "run", "-q", "-p", "cantor_field_cycle", "--", "verify", $path
    )
    if (-not $verification.valid -or $verification.terminal_state -cne $expected.Terminal -or
        $verification.latch_status -cne $expected.Latch) {
        throw "campaign disposition disagrees: $($expected.Path)"
    }
    $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($expected.Path.StartsWith("positive-")) {
        if ($report.candidate.candidate_id -cne $campaignCandidate) {
            throw "positive campaign candidate drifted: $($expected.Path)"
        }
        $assessments = @($report.exchanges | Select-Object -First 4 | ForEach-Object {
            (($_.response.choices[0].message.content | ConvertFrom-Json).assessment)
        })
        if (@($assessments | Where-Object { $_ -cne "conflicted" }).Count -ne 0) {
            throw "positive campaign no longer preserves the semantic-confidence residual: $($expected.Path)"
        }
        $relations = @($report.delineation_proposal.relations | ForEach-Object { $_.kind })
        if (($relations -join ",") -cne "constrains,supports,constrains,constrains") {
            throw "positive campaign relation sequence drifted: $($expected.Path)"
        }
    } else {
        $hasCandidate = $null -ne $report.PSObject.Properties["candidate"] -and
            $null -ne $report.candidate
        $hasLatch = $null -ne $report.PSObject.Properties["latch_decision"] -and
            $null -ne $report.latch_decision
        if ($hasCandidate -or $hasLatch) {
            throw "negative or control campaign report contains candidate or latch: $($expected.Path)"
        }
    }
    $campaignFileHashes += (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$observedCampaignFiles = @(Get-ChildItem -LiteralPath $campaignRoot -Filter "*.json" -File)
if ($observedCampaignFiles.Count -ne $campaignExpectations.Count) {
    throw "campaign file set is not exact"
}
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
$campaignSetDigest = -join ($sha256.ComputeHash(
        [Text.Encoding]::UTF8.GetBytes(($campaignFileHashes -join "`n"))
    ) | ForEach-Object { $_.ToString("x2") })
} finally {
    $sha256.Dispose()
}

$smokeRoot = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\smoke-field-attend-h2"
$smokeExpectations = @(
    [pscustomobject]@{ Path = "positive.json"; Terminal = "completed"; Latch = "admitted_for_attention" },
    [pscustomobject]@{ Path = "control.json"; Terminal = "control_completed"; Latch = $null },
    [pscustomobject]@{ Path = "hostile.json"; Terminal = "rejected"; Latch = $null }
)
$smokeReplayHashes = @()
foreach ($expected in $smokeExpectations) {
    $path = Join-Path $smokeRoot $expected.Path
    $verification = Invoke-CargoJson -Label ("verify h2 smoke " + $expected.Path) -Arguments @(
        "run", "-q", "-p", "cantor_field_cycle", "--", "verify", $path
    )
    if (-not $verification.valid -or $verification.terminal_state -cne $expected.Terminal -or
        $verification.latch_status -cne $expected.Latch) {
        throw "h2 smoke disposition disagrees: $($expected.Path)"
    }
    $smokeReplayHashes += $verification.report_sha256
}

$finalSmokeRoot = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\smoke-field-attend-h3"
$finalSmokeReplayHashes = @()
foreach ($expected in $smokeExpectations) {
    $path = Join-Path $finalSmokeRoot $expected.Path
    $verification = Invoke-CargoJson -Label ("verify h3 smoke " + $expected.Path) -Arguments @(
        "run", "-q", "-p", "cantor_field_cycle", "--", "verify", $path
    )
    if (-not $verification.valid -or $verification.terminal_state -cne $expected.Terminal -or
        $verification.latch_status -cne $expected.Latch) {
        throw "h3 smoke disposition disagrees: $($expected.Path)"
    }
    $finalSmokeReplayHashes += $verification.report_sha256
}

$currentThreadSmokeRoot = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\smoke-field-attend-h4"
$currentThreadSmokeReplayHashes = @()
foreach ($expected in $smokeExpectations) {
    $path = Join-Path $currentThreadSmokeRoot $expected.Path
    $verification = Invoke-CargoJson -Label ("verify h4 smoke " + $expected.Path) -Arguments @(
        "run", "-q", "-p", "cantor_field_cycle", "--", "verify", $path
    )
    if (-not $verification.valid -or $verification.terminal_state -cne $expected.Terminal -or
        $verification.latch_status -cne $expected.Latch) {
        throw "h4 smoke disposition disagrees: $($expected.Path)"
    }
    $currentThreadSmokeReplayHashes += $verification.report_sha256
}

$analysisOutput = & (Join-Path $PSScriptRoot "analyze_cantor_field_attention_costs.ps1")
$costAnalysis = ($analysisOutput -join [Environment]::NewLine) | ConvertFrom-Json
$costSummary = Get-Content -LiteralPath (
    Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\attention_cost_summary_v1.json"
) -Raw | ConvertFrom-Json
if ($costAnalysis.provider_report_count -ne $costSummary.provider_report_count -or
    $costAnalysis.ordered_corpus_input_sha256 -cne $costSummary.ordered_corpus_input_sha256) {
    throw "cost summary corpus identity disagrees"
}
$metricNames = @(
    "exchange_count", "prompt_tokens", "cached_prompt_tokens", "completion_tokens",
    "total_tokens", "observed_compute_ms", "report_bytes"
)
foreach ($summaryGroup in @($costSummary.groups)) {
    $observedGroup = @($costAnalysis.groups | Where-Object { $_.class -ceq $summaryGroup.class })
    if ($observedGroup.Count -ne 1 -or $observedGroup[0].report_count -ne $summaryGroup.report_count) {
        throw "cost summary group identity disagrees: $($summaryGroup.class)"
    }
    foreach ($metric in $metricNames) {
        $observedValues = @(
            $observedGroup[0].$metric.minimum,
            $observedGroup[0].$metric.median,
            $observedGroup[0].$metric.mean,
            $observedGroup[0].$metric.maximum
        )
        $expectedValues = @($summaryGroup.$metric)
        if (($observedValues -join ",") -cne ($expectedValues -join ",")) {
            throw "cost summary metric disagrees: $($summaryGroup.class) $metric"
        }
    }
}

[pscustomobject]@{
    profile = "cantor-field-attention-offline-acceptance/0.1"
    status = "passed"
    cycle_profile = $contract.profile
    request_profile = $contract.request_profile
    focused_test_count = 30
    source_count = $sources.Count
    field_count = $fields.Count
    report_count = $verifiedReports.Count
    reports = $verifiedReports
    campaign = [pscustomobject]@{
        report_count = $campaignExpectations.Count
        positive_completed = 5
        control_completed = 5
        hostile_rejected = 3
        stable_candidate_id = $campaignCandidate
        stable_relation_sequence = @("constrains", "supports", "constrains", "constrains")
        probe_assessment = "conflicted_in_all_twenty_positive_probes"
        ordered_file_set_sha256 = $campaignSetDigest
    }
    resource_smoke_h2 = [pscustomobject]@{
        report_count = $smokeExpectations.Count
        positive_completed = 1
        control_completed = 1
        hostile_rejected = 1
        replay_sha256 = $smokeReplayHashes
    }
    network_smoke_h3 = [pscustomobject]@{
        report_count = $smokeExpectations.Count
        positive_completed = 1
        control_completed = 1
        hostile_rejected = 1
        replay_sha256 = $finalSmokeReplayHashes
    }
    final_smoke_h4 = [pscustomobject]@{
        report_count = $smokeExpectations.Count
        positive_completed = 1
        control_completed = 1
        hostile_rejected = 1
        replay_sha256 = $currentThreadSmokeReplayHashes
    }
    cost_analysis = [pscustomobject]@{
        provider_report_count = $costAnalysis.provider_report_count
        ordered_corpus_input_sha256 = $costAnalysis.ordered_corpus_input_sha256
        group_count = @($costAnalysis.groups).Count
    }
    external_effects = "none"
} | ConvertTo-Json -Depth 8
