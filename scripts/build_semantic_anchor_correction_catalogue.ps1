[CmdletBinding()]
param(
    [string]$OutputPath = 'experiments/semantic_anchor_catalogue_slice5c/correction_catalogue.json',
    [switch]$VerifyOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$baselinePath = Join-Path $root 'experiments/semantic_anchor_catalogue_slice5a/self_hosted_anchor_evidence.json'
$output = if ([IO.Path]::IsPathRooted($OutputPath)) { $OutputPath } else { Join-Path $root $OutputPath }
$baseline = Get-Content $baselinePath -Raw | ConvertFrom-Json
$baselineHash = (Get-FileHash $baselinePath -Algorithm SHA256).Hash

function Assert-Catalogue($catalogue) {
    $allowed = @('profile','baseline_sha256','baseline_report_digest','use_status','training_status','selection_protocol','examples','non_authority_statement')
    $actual = @($catalogue.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ',') -ne (($allowed | Sort-Object) -join ',')) { throw 'catalogue fields differ' }
    if ($catalogue.profile -ne 'cantor-semantic-anchor-correction-catalogue/0.3' -or
        $catalogue.baseline_sha256 -ne $baselineHash -or
        $catalogue.baseline_report_digest -ne $baseline.report_digest.value -or
        $catalogue.use_status -ne 'evaluation_and_curation_only' -or
        $catalogue.training_status -ne 'training_not_authorized' -or
        $catalogue.selection_protocol.policy_profile -ne 'cantor-semantic-anchor-curator-policy/0.1' -or
        $catalogue.selection_protocol.selection_profile -ne 'cantor-semantic-anchor-curator-selection/0.1' -or
        $catalogue.selection_protocol.receipt_profile -ne 'cantor-semantic-anchor-curator-receipt/0.1' -or
        $catalogue.selection_protocol.real_target_status -ne 'null_until_independently_governed_policy_and_verified_selection_receipt' -or
        -not [bool]$catalogue.selection_protocol.synthetic_fixture_not_authority) { throw 'catalogue identity authority or selection protocol differs' }
    $examples = @($catalogue.examples)
    if ($examples.Count -ne @($baseline.queries).Count -or $examples.Count -gt 128) { throw 'example cardinality differs' }
    $expectedNames = @($baseline.queries.name | Sort-Object)
    if ((@($examples.query_name) -join ',') -ne ($expectedNames -join ',')) { throw 'example order differs' }
    foreach ($example in $examples) {
        $observed = @($baseline.queries | Where-Object name -eq $example.query_name)
        $candidateIds = @($observed[0].candidates.unit_id)
        $exactIds = @($observed[0].candidates | Where-Object exact_requested_expression | ForEach-Object unit_id)
        if ($observed.Count -ne 1 -or $null -ne $example.target_unit_id -or
            $example.status -ne 'requires_curated_exact_identity' -or
            (@($example.candidate_unit_ids) -join ',') -ne ($candidateIds -join ',') -or
            (@($example.exact_requested_expression_candidate_ids) -join ',') -ne ($exactIds -join ',') -or
            [int]$example.observed.lexical_candidate_count -ne [int]$observed[0].lexical_match_count -or
            [int]$example.observed.ambiguous_count -ne [int]$observed[0].ambiguous_count -or
            [int]$example.observed.unresolved_count -ne [int]$observed[0].unresolved_count -or
            [int]$example.observed.compact_record_count -ne [int]$observed[0].compact_record_count -or
            [int]$example.desired.eligible_count -ne 1 -or [int]$example.desired.ambiguous_count -ne 0 -or [int]$example.desired.unresolved_count -ne 0) {
            throw "example differs for $($example.query_name)"
        }
    }
}

if ($VerifyOnly) {
    $catalogue = Get-Content $output -Raw | ConvertFrom-Json
    Assert-Catalogue $catalogue
    Write-Output "correction_catalogue_verified=true examples=$(@($catalogue.examples).Count)"
    return
}
$examples = @($baseline.queries | Sort-Object name | ForEach-Object {
    [ordered]@{
        example_id = "correction:$($_.name)"
        query_name = $_.name
        input_terms = @($_.requested_terms)
        observed = [ordered]@{
            lexical_candidate_count = $_.lexical_match_count
            ambiguous_count = $_.ambiguous_count
            unresolved_count = $_.unresolved_count
            compact_record_count = $_.compact_record_count
        }
        desired = [ordered]@{ eligible_count = 1; ambiguous_count = 0; unresolved_count = 0; compact_record_count = 1 }
        target_unit_id = $null
        candidate_unit_ids = @($_.candidates.unit_id)
        exact_requested_expression_candidate_ids = @($_.candidates | Where-Object exact_requested_expression | ForEach-Object unit_id)
        required_action = 'curate one exact semantic identity from proof-bound ambiguous candidates'
        evidence_needed = @('independently governed curator policy','Ed25519 signed selection','verified selection receipt','source anchor','exact gate replay')
        status = 'requires_curated_exact_identity'
    }
})
$catalogue = [ordered]@{
    profile = 'cantor-semantic-anchor-correction-catalogue/0.3'
    baseline_sha256 = $baselineHash
    baseline_report_digest = $baseline.report_digest.value
    use_status = 'evaluation_and_curation_only'
    training_status = 'training_not_authorized'
    selection_protocol = [ordered]@{
        policy_profile = 'cantor-semantic-anchor-curator-policy/0.1'
        selection_profile = 'cantor-semantic-anchor-curator-selection/0.1'
        receipt_profile = 'cantor-semantic-anchor-curator-receipt/0.1'
        real_target_status = 'null_until_independently_governed_policy_and_verified_selection_receipt'
        synthetic_fixture_not_authority = $true
    }
    examples = $examples
    non_authority_statement = 'Candidate identities exact-expression observations and synthetic protocol fixtures are curation work items and grant no governed target selection source admission training semantic execution or effect authority.'
}
$catalogue = $catalogue | ConvertTo-Json -Depth 10 | ConvertFrom-Json
Assert-Catalogue $catalogue
[IO.Directory]::CreateDirectory((Split-Path -Parent $output)) | Out-Null
[IO.File]::WriteAllText($output, "$(($catalogue | ConvertTo-Json -Depth 10).Replace("`r`n","`n"))`n", [Text.UTF8Encoding]::new($false))
Write-Output "correction_catalogue_written=$output examples=$($examples.Count)"
