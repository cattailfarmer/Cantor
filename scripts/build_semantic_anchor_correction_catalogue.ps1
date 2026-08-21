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
    $allowed = @('profile','baseline_sha256','baseline_report_digest','use_status','training_status','examples','non_authority_statement')
    $actual = @($catalogue.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ',') -ne (($allowed | Sort-Object) -join ',')) { throw 'catalogue fields differ' }
    if ($catalogue.profile -ne 'cantor-semantic-anchor-correction-catalogue/0.1' -or
        $catalogue.baseline_sha256 -ne $baselineHash -or
        $catalogue.baseline_report_digest -ne $baseline.report_digest.value -or
        $catalogue.use_status -ne 'evaluation_and_curation_only' -or
        $catalogue.training_status -ne 'training_not_authorized') { throw 'catalogue identity or authority differs' }
    $examples = @($catalogue.examples)
    if ($examples.Count -ne @($baseline.queries).Count -or $examples.Count -gt 128) { throw 'example cardinality differs' }
    $expectedNames = @($baseline.queries.name | Sort-Object)
    if ((@($examples.query_name) -join ',') -ne ($expectedNames -join ',')) { throw 'example order differs' }
    foreach ($example in $examples) {
        $observed = @($baseline.queries | Where-Object name -eq $example.query_name)
        if ($observed.Count -ne 1 -or $null -ne $example.target_unit_id -or
            $example.status -ne 'requires_curated_exact_identity' -or
            [int]$example.observed.lexical_candidate_count -ne [int]$observed[0].lexical_match_count -or
            [int]$example.observed.unauthorized_count -ne [int]$observed[0].unauthorized_count -or
            [int]$example.observed.unresolved_count -ne [int]$observed[0].unresolved_count -or
            [int]$example.observed.compact_record_count -ne [int]$observed[0].compact_record_count -or
            [int]$example.desired.eligible_count -ne 1 -or [int]$example.desired.unauthorized_count -ne 0 -or [int]$example.desired.unresolved_count -ne 0) {
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
            unauthorized_count = $_.unauthorized_count
            unresolved_count = $_.unresolved_count
            compact_record_count = $_.compact_record_count
        }
        desired = [ordered]@{ eligible_count = 1; unauthorized_count = 0; unresolved_count = 0; compact_record_count = 1 }
        target_unit_id = $null
        required_action = 'curate and source-authorize one exact semantic identity from proof-bound candidates'
        evidence_needed = @('curator identity','source anchor','authority scope','exact gate replay')
        status = 'requires_curated_exact_identity'
    }
})
$catalogue = [ordered]@{
    profile = 'cantor-semantic-anchor-correction-catalogue/0.1'
    baseline_sha256 = $baselineHash
    baseline_report_digest = $baseline.report_digest.value
    use_status = 'evaluation_and_curation_only'
    training_status = 'training_not_authorized'
    examples = $examples
    non_authority_statement = 'Labels are curation work items and grant no source admission training semantic execution or effect authority.'
}
$catalogue = $catalogue | ConvertTo-Json -Depth 10 | ConvertFrom-Json
Assert-Catalogue $catalogue
[IO.Directory]::CreateDirectory((Split-Path -Parent $output)) | Out-Null
[IO.File]::WriteAllText($output, "$(($catalogue | ConvertTo-Json -Depth 10).Replace("`r`n","`n"))`n", [Text.UTF8Encoding]::new($false))
Write-Output "correction_catalogue_written=$output examples=$($examples.Count)"
