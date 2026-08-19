[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$proofPath = Join-Path $workspaceRoot "proofs\Cantor_Field_Attention_Delineation_Latch_P0_Proof.sop"
$acceptancePath = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\offline_acceptance_v1.json"
$costPath = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\attention_cost_summary_v1.json"
$deploymentPath = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0\deployment_manifest_2026-08-18.json"
$costAnalyzerPath = Join-Path $PSScriptRoot "analyze_cantor_field_attention_costs.ps1"

function Assert-Exact {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,
        [Parameter(Mandatory)]
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Resolve-ProofPath {
    param([Parameter(Mandatory)][string]$DeclaredPath)
    $prefix = "C:\Project\Cantor\"
    if ($DeclaredPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        return Join-Path $workspaceRoot $DeclaredPath.Substring($prefix.Length)
    }
    return $DeclaredPath
}

function Assert-StatisticSummary {
    param(
        [Parameter(Mandatory)]$Observed,
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)][string[]]$Order,
        [Parameter(Mandatory)][string]$Label
    )
    $expectedValues = @($Expected)
    Assert-Exact -Condition ($expectedValues.Count -eq $Order.Count) -Message "statistic cardinality mismatch: $Label"
    for ($index = 0; $index -lt $Order.Count; $index++) {
        $propertyName = $Order[$index]
        $property = $Observed.PSObject.Properties[$propertyName]
        Assert-Exact -Condition ($null -ne $property) -Message "missing statistic $propertyName`: $Label"
        Assert-Exact -Condition ([decimal]$property.Value -eq [decimal]$expectedValues[$index]) -Message "statistic mismatch $propertyName`: $Label"
    }
}

$sources = @(
    [pscustomobject]@{
        Path = "source_documents\2026-08-18_field_attention_delineation_latch\Dictated_Field_Attention_Delineation_Latch_Source.sop"
        Sha256 = "547066edb0583b6575c563aad88cbb034a86b07f01555ee57ef6e84dd4981f70"
        Bytes = 1325
    },
    [pscustomobject]@{
        Path = "source_documents\2026-08-18_field_attention_request_compiler\Observed_Request_Compiler_Evidence.sop"
        Sha256 = "d5042d1b32870d0451aae57c3fbd8294e9af8c178711865e6c601db016224c5d"
        Bytes = 3751
    },
    [pscustomobject]@{
        Path = "source_documents\2026-08-18_field_attention_resource_bounds\Observed_Field_Attention_Resource_Bound_Evidence.sop"
        Sha256 = "1716df7863b26bfb39251dd914eab2e7ef43081e93461f6a24f01794f9025276"
        Bytes = 2160
    },
    [pscustomobject]@{
        Path = "source_documents\2026-08-18_field_attention_fault_assurance\Observed_Field_Attention_Fault_Assurance_Evidence.sop"
        Sha256 = "2ac898d3bae7330f297bb9949f72c5be61b229731cf096ead548758d8be4eb25"
        Bytes = 2165
    }
)

foreach ($source in $sources) {
    $path = Join-Path $workspaceRoot $source.Path
    Assert-Exact -Condition (Test-Path -LiteralPath $path -PathType Leaf) -Message "missing preserved source: $($source.Path)"
    Assert-Exact -Condition ((Get-Item -LiteralPath $path).Length -eq $source.Bytes) -Message "source byte mismatch: $($source.Path)"
    Assert-Exact -Condition ((Get-Sha256 -Path $path) -ceq $source.Sha256) -Message "source digest mismatch: $($source.Path)"
}

$proof = Get-Content -LiteralPath $proofPath -Raw
$acceptance = Get-Content -LiteralPath $acceptancePath -Raw | ConvertFrom-Json
$cost = Get-Content -LiteralPath $costPath -Raw | ConvertFrom-Json
$deployment = Get-Content -LiteralPath $deploymentPath -Raw | ConvertFrom-Json

$acceptanceSha = Get-Sha256 -Path $acceptancePath
$costSha = Get-Sha256 -Path $costPath
$deploymentSha = Get-Sha256 -Path $deploymentPath
Assert-Exact -Condition $proof.Contains("[receipt_sha256] is $acceptanceSha") -Message "proof does not bind current acceptance receipt"
Assert-Exact -Condition $proof.Contains("[summary_sha256] is $costSha") -Message "proof does not bind current cost summary"
Assert-Exact -Condition $proof.Contains("[manifest_sha256] is $deploymentSha") -Message "proof does not bind current deployment manifest"

Assert-Exact -Condition ($acceptance.status -ceq "passed") -Message "offline acceptance is not passed"
Assert-Exact -Condition ($acceptance.source_count -eq 4) -Message "offline acceptance source count changed"
Assert-Exact -Condition ($acceptance.field_count -eq 4) -Message "offline acceptance field count changed"
Assert-Exact -Condition ($acceptance.report_count -eq 10) -Message "offline acceptance core report count changed"
Assert-Exact -Condition ($acceptance.cost_analysis.provider_report_count -eq 31) -Message "provider report count changed"
Assert-Exact -Condition ($acceptance.cost_analysis.ordered_corpus_input_sha256 -ceq $cost.ordered_corpus_input_sha256) -Message "acceptance and cost corpus identities disagree"

$costAnalysis = (& $costAnalyzerPath | Out-String | ConvertFrom-Json)
Assert-Exact -Condition ($costAnalysis.profile -ceq "cantor-field-attention-cost-analysis/0.1") -Message "cost analyzer profile changed"
Assert-Exact -Condition ($cost.profile -ceq "cantor-field-attention-cost-summary/0.1") -Message "cost summary profile changed"
Assert-Exact -Condition ($cost.analysis_script -ceq "scripts/analyze_cantor_field_attention_costs.ps1") -Message "cost summary analyzer identity changed"
Assert-Exact -Condition ($costAnalysis.provider_report_count -eq $cost.provider_report_count) -Message "recomputed provider report count changed"
Assert-Exact -Condition ($costAnalysis.ordered_corpus_input_sha256 -ceq $cost.ordered_corpus_input_sha256) -Message "recomputed provider corpus identity changed"
$statOrder = @($cost.stat_order | ForEach-Object { [string]$_ })
Assert-Exact -Condition (($statOrder -join ",") -ceq "minimum,median,mean,maximum") -Message "cost statistic order changed"
$observedGroups = @($costAnalysis.groups)
$expectedGroups = @($cost.groups)
Assert-Exact -Condition ($observedGroups.Count -eq $expectedGroups.Count) -Message "recomputed cost group count changed"
foreach ($observedGroup in $observedGroups) {
    $matches = @($expectedGroups | Where-Object { $_.class -ceq $observedGroup.class })
    Assert-Exact -Condition ($matches.Count -eq 1) -Message "missing or duplicate cost group: $($observedGroup.class)"
    $expectedGroup = $matches[0]
    Assert-Exact -Condition ($observedGroup.report_count -eq $expectedGroup.report_count) -Message "cost report count mismatch: $($observedGroup.class)"
    foreach ($statistic in @("exchange_count", "prompt_tokens", "cached_prompt_tokens", "completion_tokens", "total_tokens", "observed_compute_ms", "report_bytes")) {
        Assert-StatisticSummary -Observed $observedGroup.$statistic -Expected $expectedGroup.$statistic -Order $statOrder -Label "$($observedGroup.class).$statistic"
    }
}

$assuranceCounts = @{}
foreach ($report in @($acceptance.reports)) {
    $assurance = [string]$report.assurance
    if (-not $assuranceCounts.ContainsKey($assurance)) {
        $assuranceCounts[$assurance] = 0
    }
    $assuranceCounts[$assurance]++
}
Assert-Exact -Condition ($assuranceCounts.Count -eq 3) -Message "core assurance class count changed"
Assert-Exact -Condition ($assuranceCounts["deterministic_construction"] -eq 1) -Message "deterministic assurance count changed"
Assert-Exact -Condition ($assuranceCounts["stored_provider_replay"] -eq 7) -Message "stored-provider assurance count changed"
Assert-Exact -Condition ($assuranceCounts["response_backed_fault_replay"] -eq 2) -Message "response-backed fault assurance count changed"

Assert-Exact -Condition ($deployment.final_verifier.path -ceq "C:\AI\services\cantor-field-cycle\cantor-field-cycle-p0-h8.exe") -Message "final verifier path changed"
Assert-Exact -Condition ($deployment.final_verifier.sha256 -ceq "abf9c33976320297018bc90723c50ee779b746b129539daaf963e91f5eb40b52") -Message "final verifier digest changed"
Assert-Exact -Condition ($deployment.final_verifier.bytes -eq 2840064) -Message "final verifier byte count changed"
Assert-Exact -Condition ($deployment.final_h8_replay.verified_count -eq 31) -Message "final h8 replay count changed"
Assert-Exact -Condition ($deployment.final_h8_replay.stored_provider_replay -eq 29) -Message "final h8 stored-provider count changed"
Assert-Exact -Condition ($deployment.final_h8_replay.response_backed_fault_replay -eq 2) -Message "final h8 response-backed fault count changed"
Assert-Exact -Condition (-not $deployment.provider.modified_or_restarted) -Message "deployment claims provider mutation"

$referencePattern = '(?m)^\s*@\s+\[[^\]]+\]\s+(C:\\Project\\Cantor\\[^\r\n]+)$'
$proofReferences = @([regex]::Matches($proof, $referencePattern) | ForEach-Object { $_.Groups[1].Value.Trim() })
Assert-Exact -Condition ($proofReferences.Count -gt 0) -Message "proof exposes no local artifact references"
foreach ($reference in $proofReferences) {
    $resolved = Resolve-ProofPath -DeclaredPath $reference
    Assert-Exact -Condition (Test-Path -LiteralPath $resolved -PathType Leaf) -Message "missing proof reference: $reference"
}

[pscustomobject]@{
    profile = "cantor-field-attention-closure-audit/0.1"
    status = "passed"
    preserved_source_count = $sources.Count
    proof_reference_count = $proofReferences.Count
    acceptance_sha256 = $acceptanceSha
    cost_summary_sha256 = $costSha
    deployment_manifest_sha256 = $deploymentSha
    final_verifier_sha256 = $deployment.final_verifier.sha256
    core_assurance_counts = $assuranceCounts
    cost_corpus_recomputed = $true
    remote_reexecution = $false
    external_effects = "none"
} | ConvertTo-Json -Depth 5
