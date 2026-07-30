param(
    [string]$ArtifactDirectory = "experiments/resident_service_benchmark/artifacts",
    [string]$OutputPath = "experiments/resident_service_benchmark/artifacts/2026-07-29-three-run-summary.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$repositoryUri = [Uri]::new($repositoryRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar)
$artifactDirectoryFull = if ([IO.Path]::IsPathRooted($ArtifactDirectory)) {
    [IO.Path]::GetFullPath($ArtifactDirectory)
}
else {
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot $ArtifactDirectory))
}

$reports = Get-ChildItem -LiteralPath $artifactDirectoryFull -Filter "2026-07-29-run-*.json" -File |
    Sort-Object Name |
    ForEach-Object {
        $relativePath = [Uri]::UnescapeDataString(
            $repositoryUri.MakeRelativeUri([Uri]::new($_.FullName)).ToString()
        )
        [ordered]@{
            path = $relativePath
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash
            bytes = $_.Length
            report = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
        }
    }
if ($reports.Count -ne 3) {
    throw "Expected exactly three resident service benchmark reports"
}
if ($reports | Where-Object { $_.report.correctness_mismatches -ne 0 }) {
    throw "A resident service benchmark report contains correctness mismatches"
}

$measurementNames = @(
    "restart_preflight",
    "resident_dispatch",
    "status_round_trip",
    "query_round_trip"
)
$ranges = [ordered]@{}
foreach ($name in $measurementNames) {
    $medians = @($reports | ForEach-Object { [UInt64]$_.report.$name.median_microseconds })
    $p95s = @($reports | ForEach-Object { [UInt64]$_.report.$name.p95_microseconds })
    $ranges[$name] = [ordered]@{
        median_min = ($medians | Measure-Object -Minimum).Minimum
        median_max = ($medians | Measure-Object -Maximum).Maximum
        p95_min = ($p95s | Measure-Object -Minimum).Minimum
        p95_max = ($p95s | Measure-Object -Maximum).Maximum
    }
}
$startup = @($reports | ForEach-Object { [UInt64]$_.report.startup_microseconds })
$first = $reports[0].report
$summary = [ordered]@{
    schema = "cantor-resident-service-evidence/0.1"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    run_count = 3
    iterations_per_run = [UInt64]$first.iterations
    environment_bytes = [UInt64]$first.environment_bytes
    package_count = [UInt64]$first.package_count
    generation_id = $first.generation_id
    startup_microseconds = [ordered]@{
        minimum = ($startup | Measure-Object -Minimum).Minimum
        maximum = ($startup | Measure-Object -Maximum).Maximum
    }
    ranges_microseconds = $ranges
    correctness_mismatches = 0
    raw_reports = @($reports | ForEach-Object {
        [ordered]@{
            path = $_.path
            sha256 = $_.sha256
            bytes = $_.bytes
        }
    })
}

$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputPath))
}
[IO.File]::WriteAllText(
    $outputFullPath,
    "$($summary | ConvertTo-Json -Depth 10)`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $outputFullPath
