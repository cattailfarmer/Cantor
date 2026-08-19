[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$evidenceRoot = Join-Path $workspaceRoot "experiments\cantor_field_cycle_p0"

function Get-Statistic {
    param(
        [Parameter(Mandatory)]
        [double[]]$Values
    )
    if ($Values.Count -eq 0) {
        return $null
    }
    $ordered = @($Values | Sort-Object)
    $middle = [int][Math]::Floor($ordered.Count / 2)
    $median = if ($ordered.Count % 2 -eq 0) {
        ($ordered[$middle - 1] + $ordered[$middle]) / 2
    } else {
        $ordered[$middle]
    }
    [pscustomobject]@{
        minimum = [Math]::Round($ordered[0], 3)
        median = [Math]::Round($median, 3)
        mean = [Math]::Round(($ordered | Measure-Object -Average).Average, 3)
        maximum = [Math]::Round($ordered[-1], 3)
    }
}

$rows = @()
foreach ($file in @(Get-ChildItem -LiteralPath $evidenceRoot -Recurse -Filter "*.json" -File | Sort-Object FullName)) {
    $report = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    if ($null -eq $report.PSObject.Properties["profile"] -or
        $report.profile -cne "cantor-field-attention-cycle/0.1" -or
        $report.provider.base_url -ceq "fixture://local") {
        continue
    }
    $promptTokens = 0
    $cachedTokens = 0
    $completionTokens = 0
    $computeMs = 0.0
    foreach ($exchange in @($report.exchanges)) {
        $usage = $exchange.response.usage
        if ($null -ne $usage) {
            $promptTokens += [int]$usage.prompt_tokens
            $completionTokens += [int]$usage.completion_tokens
            if ($null -ne $usage.prompt_tokens_details) {
                $cachedTokens += [int]$usage.prompt_tokens_details.cached_tokens
            }
        }
        $timings = $exchange.response.timings
        if ($null -ne $timings) {
            $computeMs += [double]$timings.prompt_ms + [double]$timings.predicted_ms
        }
    }
    $hasCandidate = $null -ne $report.PSObject.Properties["candidate"] -and $null -ne $report.candidate
    $class = if ($report.terminal_state -ceq "completed") {
        "completed"
    } elseif ($report.terminal_state -ceq "control_completed") {
        "control"
    } elseif ($report.terminal_state -ceq "faulted") {
        "faulted"
    } elseif (-not $hasCandidate -and @($report.exchanges).Count -eq 4) {
        "host_boundary_rejected"
    } else {
        "post_delineation_rejected"
    }
    $rows += [pscustomobject]@{
        path = $file.FullName.Substring($evidenceRoot.Length + 1).Replace("\", "/")
        file_sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        class = $class
        request_profile = if ($null -eq $report.PSObject.Properties["request_profile"]) {
            "cantor-field-attention-requests/0.1"
        } else {
            $report.request_profile
        }
        exchange_count = @($report.exchanges).Count
        prompt_tokens = $promptTokens
        cached_prompt_tokens = $cachedTokens
        completion_tokens = $completionTokens
        total_tokens = $promptTokens + $completionTokens
        observed_compute_ms = [Math]::Round($computeMs, 3)
        report_bytes = $file.Length
    }
}

$identityText = ($rows | ForEach-Object { "$($_.path) $($_.file_sha256)" }) -join "`n"
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $corpusInputSha256 = -join ($sha256.ComputeHash(
        [Text.Encoding]::UTF8.GetBytes($identityText)
    ) | ForEach-Object { $_.ToString("x2") })
} finally {
    $sha256.Dispose()
}

$groups = @()
foreach ($group in @($rows | Group-Object class | Sort-Object Name)) {
    $items = @($group.Group)
    $groups += [pscustomobject]@{
        class = $group.Name
        report_count = $items.Count
        exchange_count = Get-Statistic -Values @($items.exchange_count)
        prompt_tokens = Get-Statistic -Values @($items.prompt_tokens)
        cached_prompt_tokens = Get-Statistic -Values @($items.cached_prompt_tokens)
        completion_tokens = Get-Statistic -Values @($items.completion_tokens)
        total_tokens = Get-Statistic -Values @($items.total_tokens)
        observed_compute_ms = Get-Statistic -Values @($items.observed_compute_ms)
        report_bytes = Get-Statistic -Values @($items.report_bytes)
    }
}

[pscustomobject]@{
    profile = "cantor-field-attention-cost-analysis/0.1"
    corpus = "experiments/cantor_field_cycle_p0"
    provider_report_count = $rows.Count
    ordered_corpus_input_sha256 = $corpusInputSha256
    provider = "Qwen3.5-0.8B-Q4_0 through unmodified llama.cpp loopback"
    groups = $groups
    rows = $rows
    interpretation = @(
        "timings are provider-reported prompt_ms plus predicted_ms and exclude SSH, process startup, file I/O, and model discovery",
        "cache counts are observations rather than a stable API guarantee",
        "token and byte cost do not measure semantic correctness",
        "reports preserve repeated executions and are not independent semantic witnesses"
    )
} | ConvertTo-Json -Depth 8
