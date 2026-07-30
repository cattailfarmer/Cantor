param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactsPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$resolvedArtifacts = (Resolve-Path -LiteralPath $ArtifactsPath).Path
$reports = Get-ChildItem -LiteralPath $resolvedArtifacts -Filter '2026-07-29-run-*.json' -File |
    Sort-Object Name

if ($reports.Count -ne 3) {
    throw "Expected exactly three raw benchmark reports, found $($reports.Count)."
}

$parsed = @($reports | ForEach-Object {
    $value = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
    if ($value.profile -ne 'cantor-self-hosted-corpus-benchmark/0.1') {
        throw "Unexpected benchmark profile in $($_.Name)."
    }
    if ($value.correctness_mismatches -ne 0) {
        throw "Correctness mismatch reported in $($_.Name)."
    }
    $value
})

$identityFields = @(
    'iterations',
    'source_count',
    'unit_count',
    'relation_count',
    'source_bytes',
    'environment_bytes',
    'request_bytes'
)
foreach ($field in $identityFields) {
    $distinct = @($parsed | ForEach-Object { $_.$field } | Sort-Object -Unique)
    if ($distinct.Count -ne 1) {
        throw "Benchmark reports disagree on $field."
    }
}

$measurementNames = @(
    'parse_lower',
    'compile_signed_package',
    'full_build_preflight',
    'environment_load',
    'direct_query',
    'prepared_hit'
)
$ranges = [ordered]@{}
foreach ($measurement in $measurementNames) {
    $medians = @($parsed | ForEach-Object {
        [double]$_.measurements_microseconds.$measurement.median
    })
    $p95s = @($parsed | ForEach-Object {
        [double]$_.measurements_microseconds.$measurement.p95
    })
    $ranges[$measurement] = [ordered]@{
        median_min = ($medians | Measure-Object -Minimum).Minimum
        median_max = ($medians | Measure-Object -Maximum).Maximum
        p95_min = ($p95s | Measure-Object -Minimum).Minimum
        p95_max = ($p95s | Measure-Object -Maximum).Maximum
    }
}

$rawReports = [ordered]@{}
foreach ($report in $reports) {
    $rawReports[$report.Name] = [ordered]@{
        sha256 = (Get-FileHash -LiteralPath $report.FullName -Algorithm SHA256).Hash
        bytes = $report.Length
    }
}

$summary = [ordered]@{
    profile = 'cantor-self-hosted-corpus-evidence/0.1'
    captured_at = '2026-07-29'
    run_count = 3
    iterations_per_run = $parsed[0].iterations
    source_count = $parsed[0].source_count
    unit_count = $parsed[0].unit_count
    relation_count = $parsed[0].relation_count
    source_bytes = $parsed[0].source_bytes
    environment_bytes = $parsed[0].environment_bytes
    request_bytes = $parsed[0].request_bytes
    correctness_mismatches = 0
    prepared_projection_preparations_per_run = $parsed[0].prepared_projection_preparations
    prepared_projection_hits_per_run = $parsed[0].prepared_projection_hits
    ranges_microseconds = $ranges
    raw_reports = $rawReports
    limitations = $parsed[0].limitations
}

$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = [IO.Path]::GetDirectoryName($outputFullPath)
if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    [IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
$json = $summary | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($outputFullPath, $json + "`n", [Text.UTF8Encoding]::new($false))

[ordered]@{
    output = $outputFullPath
    sha256 = (Get-FileHash -LiteralPath $outputFullPath -Algorithm SHA256).Hash
    bytes = (Get-Item -LiteralPath $outputFullPath).Length
} | ConvertTo-Json -Compress
