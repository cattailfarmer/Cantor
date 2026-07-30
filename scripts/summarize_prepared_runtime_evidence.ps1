param(
    [string]$ArtifactDirectory = "experiments/prepared_runtime_benchmark/artifacts",
    [string]$OutputPath = "experiments/prepared_runtime_benchmark/artifacts/2026-07-29_three_run_summary.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$latencyFiles = Get-ChildItem -LiteralPath $ArtifactDirectory -Filter "latency_run_*.json" |
    Sort-Object Name
$memoryFiles = Get-ChildItem -LiteralPath $ArtifactDirectory -Filter "memory_run_*.json" |
    Sort-Object Name
if ($latencyFiles.Count -ne 9) {
    throw "expected 9 latency artifacts, found $($latencyFiles.Count)"
}
if ($memoryFiles.Count -ne 18) {
    throw "expected 18 memory artifacts, found $($memoryFiles.Count)"
}

$latency = $latencyFiles | ForEach-Object {
    $value = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
    if ($value.schema -ne "cantor-prepared-runtime-latency/0.2") {
        throw "unexpected latency schema in $($_.Name)"
    }
    if ($value.exact_response_mismatches -ne 0) {
        throw "response mismatch recorded in $($_.Name)"
    }
    $value
}
$memory = $memoryFiles | ForEach-Object {
    $value = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
    if ($value.schema -ne "cantor-prepared-runtime-memory/0.1") {
        throw "unexpected memory schema in $($_.Name)"
    }
    $value
}

$shapeReports = foreach ($packageCount in @(1, 32, 256)) {
    $shapeLatency = @($latency | Where-Object { $_.package_count -eq $packageCount })
    $baseline = @($memory | Where-Object {
        $_.package_count -eq $packageCount -and $_.mode -eq "baseline"
    })
    $prepared = @($memory | Where-Object {
        $_.package_count -eq $packageCount -and $_.mode -eq "prepared"
    })
    if ($shapeLatency.Count -ne 3 -or $baseline.Count -ne 3 -or $prepared.Count -ne 3) {
        throw "incomplete three-run evidence for package count $packageCount"
    }
    $speedups = $shapeLatency | ForEach-Object {
        $_.direct_request.median_us / $_.prepared_hit.median_us
    }
    $retainedRatios = for ($index = 0; $index -lt 3; $index++) {
        $prepared[$index].current_bytes / $baseline[$index].current_bytes
    }
    $peakRatios = for ($index = 0; $index -lt 3; $index++) {
        $prepared[$index].peak_bytes / $baseline[$index].peak_bytes
    }
    [ordered]@{
        package_count = $packageCount
        latency_median_us_range = [ordered]@{
            cold_process_prepare = @(
                ($shapeLatency.cold_process_prepare.median_us | Measure-Object -Minimum).Minimum,
                ($shapeLatency.cold_process_prepare.median_us | Measure-Object -Maximum).Maximum
            )
            prepared_construct = @(
                ($shapeLatency.prepared_construct.median_us | Measure-Object -Minimum).Minimum,
                ($shapeLatency.prepared_construct.median_us | Measure-Object -Maximum).Maximum
            )
            warm_scope_preparation = @(
                ($shapeLatency.warm_scope_preparation.median_us | Measure-Object -Minimum).Minimum,
                ($shapeLatency.warm_scope_preparation.median_us | Measure-Object -Maximum).Maximum
            )
            direct_request = @(
                ($shapeLatency.direct_request.median_us | Measure-Object -Minimum).Minimum,
                ($shapeLatency.direct_request.median_us | Measure-Object -Maximum).Maximum
            )
            cold_runtime_first_request = @(
                ($shapeLatency.cold_runtime_first_request.median_us | Measure-Object -Minimum).Minimum,
                ($shapeLatency.cold_runtime_first_request.median_us | Measure-Object -Maximum).Maximum
            )
            prepared_scope_replacement_pair = @(
                ($shapeLatency.prepared_scope_replacement.median_us | Measure-Object -Minimum).Minimum,
                ($shapeLatency.prepared_scope_replacement.median_us | Measure-Object -Maximum).Maximum
            )
            prepared_hit = @(
                ($shapeLatency.prepared_hit.median_us | Measure-Object -Minimum).Minimum,
                ($shapeLatency.prepared_hit.median_us | Measure-Object -Maximum).Maximum
            )
        }
        median_hit_speedup_range = @(
            ($speedups | Measure-Object -Minimum).Minimum,
            ($speedups | Measure-Object -Maximum).Maximum
        )
        memory = [ordered]@{
            baseline_current_bytes = @(
                ($baseline.current_bytes | Measure-Object -Minimum).Minimum,
                ($baseline.current_bytes | Measure-Object -Maximum).Maximum
            )
            prepared_current_bytes = @(
                ($prepared.current_bytes | Measure-Object -Minimum).Minimum,
                ($prepared.current_bytes | Measure-Object -Maximum).Maximum
            )
            retained_delta_bytes = @(
                (($prepared[0].current_bytes - $baseline[0].current_bytes)),
                (($prepared[1].current_bytes - $baseline[1].current_bytes)),
                (($prepared[2].current_bytes - $baseline[2].current_bytes))
            )
            retained_ratio_range = @(
                ($retainedRatios | Measure-Object -Minimum).Minimum,
                ($retainedRatios | Measure-Object -Maximum).Maximum
            )
            baseline_peak_bytes = @(
                ($baseline.peak_bytes | Measure-Object -Minimum).Minimum,
                ($baseline.peak_bytes | Measure-Object -Maximum).Maximum
            )
            prepared_peak_bytes = @(
                ($prepared.peak_bytes | Measure-Object -Minimum).Minimum,
                ($prepared.peak_bytes | Measure-Object -Maximum).Maximum
            )
            peak_ratio_range = @(
                ($peakRatios | Measure-Object -Minimum).Minimum,
                ($peakRatios | Measure-Object -Maximum).Maximum
            )
        }
        exact_response_mismatches = 0
    }
}

$artifactHashes = @($latencyFiles + $memoryFiles) | ForEach-Object {
    [ordered]@{
        path = $_.FullName
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash
        bytes = $_.Length
    }
}

$processor = try {
    (Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name).Trim()
} catch {
    "unavailable"
}
$report = [ordered]@{
    schema = "cantor-prepared-runtime-evidence-summary/0.1"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    method = [ordered]@{
        release_profile = $true
        overflow_checks = $true
        latency_runs_per_shape = 3
        latency_iterations_per_run = 40
        prepared_hit_samples_per_run = 160
        memory_runs_per_shape_and_mode = 3
        memory_profiler = "dhat 0.3.3 process-wide allocation tracker"
        memory_process_boundary = "separate baseline and prepared release processes"
        fixture = "synthetic signed packages with one term and source per package"
        package_shapes = @(1, 32, 256)
        rustc = (& rustc --version)
        cargo = (& cargo --version)
        operating_system = [Environment]::OSVersion.VersionString
        processor = $processor
    }
    shapes = @($shapeReports)
    correctness = [ordered]@{
        measured_exact_response_mismatches = 0
        test_oracle = "full ProtocolResponse equality"
    }
    limitations = @(
        "Synthetic fixtures are not a reviewed production SOP corpus.",
        "Dhat current bytes are allocation-level heap, not operating-system RSS or allocator fragmentation.",
        "Peak heap includes fixture compilation in both modes and preparation in prepared mode.",
        "Latency is local single-process release execution, not distributed or realtime service performance.",
        "Trust time remains the pinned environment now_epoch_seconds; no live wall-clock authority is claimed."
    )
    raw_artifacts = @($artifactHashes)
}

$json = $report | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText(
    (Join-Path (Get-Location) $OutputPath),
    "$json`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $OutputPath
