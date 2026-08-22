[CmdletBinding()]
param(
    [string]$OutputPath = 'experiments/semantic_anchor_catalogue_slice5b/controlled_measurement.json',
    [switch]$VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$manifest = Join-Path $root 'corpus/self_hosted/corpus.json'
$checked = Join-Path $root 'experiments/semantic_anchor_catalogue_slice5a/self_hosted_anchor_evidence.json'
$output = if ([IO.Path]::IsPathRooted($OutputPath)) { $OutputPath } else { Join-Path $root $OutputPath }
$head = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'unable to resolve git HEAD' }

function Get-RawHash([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function ConvertTo-WslPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^([A-Za-z]):\\(.*)$') { throw "path is not on a Windows drive: $full" }
    "/mnt/$($Matches[1].ToLowerInvariant())/$($Matches[2].Replace('\', '/'))"
}

function Assert-Evidence($Evidence) {
    if ($Evidence.profile -ne 'cantor-self-hosted-anchor-controlled-measurement/0.1' -or
        $Evidence.manifest_sha256 -ne (Get-RawHash $manifest) -or
        $Evidence.checked_evidence_sha256 -ne (Get-RawHash $checked) -or
        @($Evidence.trials).Count -ne 7) {
        throw 'measurement identity or trial cardinality differs'
    }
    & git -C $root merge-base --is-ancestor ([string]$Evidence.git_head) $head
    if ($LASTEXITCODE -ne 0) { throw 'measured git identity is not an ancestor of current HEAD' }
    $ordinals = @($Evidence.trials | ForEach-Object { [int]$_.ordinal })
    if (($ordinals -join ',') -ne '1,2,3,4,5,6,7') { throw 'trial ordinals differ' }
    foreach ($trial in $Evidence.trials) {
        if ([decimal]$trial.elapsed_milliseconds -le 0 -or [uint64]$trial.peak_resident_bytes -eq 0 -or
            [uint64]$trial.report_bytes -ne (Get-Item $checked).Length -or
            [string]$trial.report_sha256 -ne (Get-RawHash $checked)) {
            throw "trial measurement or exact report equality differs: ordinal=$($trial.ordinal) elapsed_ms=$($trial.elapsed_milliseconds) peak_bytes=$($trial.peak_resident_bytes) report_bytes=$($trial.report_bytes) expected_bytes=$((Get-Item $checked).Length) report_sha256=$($trial.report_sha256) expected_sha256=$(Get-RawHash $checked)"
        }
    }
    $times = @($Evidence.trials | ForEach-Object { [decimal]$_.elapsed_milliseconds } | Sort-Object)
    $rss = @($Evidence.trials | ForEach-Object { [uint64]$_.peak_resident_bytes } | Sort-Object)
    if ([decimal]$Evidence.elapsed_milliseconds.minimum -ne $times[0] -or
        [decimal]$Evidence.elapsed_milliseconds.median -ne $times[3] -or
        [decimal]$Evidence.elapsed_milliseconds.maximum -ne $times[6] -or
        [uint64]$Evidence.peak_resident_bytes.minimum -ne $rss[0] -or
        [uint64]$Evidence.peak_resident_bytes.median -ne $rss[3] -or
        [uint64]$Evidence.peak_resident_bytes.maximum -ne $rss[6]) {
        throw 'measurement aggregates differ from seven ordered trials'
    }
}

if ($VerifyOnly) {
    $evidence = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    Assert-Evidence $evidence
    Write-Output 'controlled_measurement_verified=true trials=7'
    return
}

$target = '/home/pinky/.cache/cantor-workspace-verification'
$build = 'set -euo pipefail; export CARGO_TARGET_DIR=' + $target + ' CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 LC_ALL=C; cargo build -p cantor_core --bin cantor-self-hosted-anchor-evidence --release --locked --offline --quiet'
& wsl.exe -d Ubuntu-24.04 --cd $root -- bash -lc $build
if ($LASTEXITCODE -ne 0) { throw 'offline optimized evidence binary build failed' }
$rustcVersion = (& wsl.exe -d Ubuntu-24.04 -- bash -lc '$HOME/.cargo/bin/rustc --version').Trim()
$binaryWindows = '\\wsl.localhost\Ubuntu-24.04\home\pinky\.cache\cantor-workspace-verification\release\cantor-self-hosted-anchor-evidence'
$binaryHash = Get-RawHash $binaryWindows
$trialDir = Join-Path ([IO.Path]::GetTempPath()) ('cantor-slice5b-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($trialDir) | Out-Null
try {
    $command = "$target/release/cantor-self-hosted-anchor-evidence corpus/self_hosted/corpus.json"
    & wsl.exe -d Ubuntu-24.04 --cd $root -- bash -lc "$command /tmp/cantor-slice5b-warmup.json"
    if ($LASTEXITCODE -ne 0) { throw 'warmup failed' }
    $trials = @()
    foreach ($ordinal in 1..7) {
        $trialOutput = Join-Path $trialDir "trial-$ordinal.json"
        $trialTime = Join-Path $trialDir "trial-$ordinal.time"
        $wslOutput = ConvertTo-WslPath $trialOutput
        $wslTime = ConvertTo-WslPath $trialTime
        $timed = "/usr/bin/time -f '%e|%M' -o '$wslTime' $command '$wslOutput'"
        & wsl.exe -d Ubuntu-24.04 --cd $root -- bash -lc $timed
        if ($LASTEXITCODE -ne 0) { throw "trial $ordinal failed" }
        if ((Get-RawHash $trialOutput) -ne (Get-RawHash $checked)) { throw "trial $ordinal report differs" }
        $parts = (Get-Content -LiteralPath $trialTime -Raw).Trim().Split('|')
        if ($parts.Count -ne 2) { throw "trial $ordinal time record malformed" }
        $trials += [ordered]@{
            ordinal = $ordinal
            elapsed_milliseconds = [decimal]::Parse($parts[0], [Globalization.CultureInfo]::InvariantCulture) * 1000
            peak_resident_bytes = [uint64]$parts[1] * 1024
            report_bytes = (Get-Item $trialOutput).Length
            report_sha256 = Get-RawHash $trialOutput
        }
    }
    $times = @($trials.elapsed_milliseconds | Sort-Object)
    $rss = @($trials.peak_resident_bytes | Sort-Object)
    $evidence = [ordered]@{
        profile = 'cantor-self-hosted-anchor-controlled-measurement/0.1'
        git_head = $head
        distro = 'Ubuntu-24.04'
        rustc_version = $rustcVersion
        cargo_profile = 'release_locked_offline'
        build_jobs = 1
        warmup_count = 1
        trial_count = 7
        manifest_sha256 = Get-RawHash $manifest
        checked_evidence_sha256 = Get-RawHash $checked
        executable_sha256 = $binaryHash
        measurement_command = "/usr/bin/time -f %e|%M $command OUTPUT"
        memory_metric = 'maximum_resident_set_bytes_not_allocation_count'
        trials = $trials
        elapsed_milliseconds = [ordered]@{ minimum=$times[0]; median=$times[3]; maximum=$times[6] }
        peak_resident_bytes = [ordered]@{ minimum=$rss[0]; median=$rss[3]; maximum=$rss[6] }
        non_authority_statement = 'Process measurements grant no semantic provider training execution or effect authority.'
    }
    Assert-Evidence $evidence
    [IO.Directory]::CreateDirectory((Split-Path -Parent $output)) | Out-Null
    [IO.File]::WriteAllText($output, "$(($evidence | ConvertTo-Json -Depth 10).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
    Write-Output "controlled_measurement_written=$output trials=7"
} finally {
    if (Test-Path -LiteralPath $trialDir) { Remove-Item -LiteralPath $trialDir -Recurse -Force }
}
