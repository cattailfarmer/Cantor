[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $PackageRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packageRootPath = (Resolve-Path -LiteralPath $PackageRoot).Path
$package = & (Join-Path $PSScriptRoot 'verify_cantor_evox2_current_build_host_pilot_p0_package.ps1') -PackageRoot $packageRootPath | ConvertFrom-Json
$manifest = Get-Content -LiteralPath (Join-Path $packageRootPath 'deployment_manifest.json') -Raw | ConvertFrom-Json
$verifyEvidence = Join-Path $PSScriptRoot 'verify_cantor_evox2_current_build_host_pilot_p0_evidence.ps1'
$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = [IO.Path]::GetFullPath((Join-Path $parent ('evox2-evidence-test-' + [guid]::NewGuid().Guid)))
if (-not $testRoot.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe evidence test root' }

function Write-Utf8Lf([string] $Path, [string] $Text) {
    [IO.File]::WriteAllText($Path, ($Text.TrimEnd("`r", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
}

function Get-Sha256Text([string] $Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha.Dispose()
    }
}

try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    $replays = @()
    $verifier = Join-Path $packageRootPath 'bin\cantor-b1-production-broker-projection-evidence-verify.exe'
    $input = Join-Path $packageRootPath 'evidence\a8'
    for ($ordinal = 1; $ordinal -le 2; $ordinal++) {
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $lines = @(& $verifier $input 2>&1)
        $exit = $LASTEXITCODE
        $stopwatch.Stop()
        if ($exit -ne 0) { throw 'local A8 replay failed during evidence fixture construction' }
        $outputPath = Join-Path $testRoot "a8_replay_$ordinal.stdout.json"
        Write-Utf8Lf $outputPath (($lines | ForEach-Object { $_.ToString() }) -join "`n")
        $item = Get-Item -LiteralPath $outputPath
        $replays += [ordered]@{
            ordinal = $ordinal
            executable_relative_path = 'bin/cantor-b1-production-broker-projection-evidence-verify.exe'
            input_relative_path = 'evidence/a8'
            duration_ms = [int64]$stopwatch.ElapsedMilliseconds
            exit_code = 0
            stdout_bytes = [int64]$item.Length
            stdout_sha256 = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
            status = 'passed'
        }
    }
    $membership = @($manifest.artifacts | ForEach-Object {
        [ordered]@{ relative_path = $_.relative_path; role = $_.role; bytes = [int64]$_.bytes; sha256 = $_.sha256 }
    })
    $protected = @(
        [ordered]@{ root = 'C:/AI/services/cantor-attention-mcp'; file_count = 3; aggregate_bytes = 1; set_sha256 = ('1' * 64) },
        [ordered]@{ root = 'C:/AI/services/cantor-needle-runtime'; file_count = 4; aggregate_bytes = 2; set_sha256 = ('2' * 64) },
        [ordered]@{ root = 'C:/AI/services/sop-agent'; file_count = 1; aggregate_bytes = 3; set_sha256 = ('3' * 64) }
    )
    $provider = [ordered]@{ pid = 1; creation_utc = '2026-09-08T00:00:00.0000000Z'; command_sha256 = ('4' * 64); executable_bytes = 1; executable_sha256 = ('5' * 64); model_bytes = 1; model_sha256 = ('6' * 64); listener = '127.0.0.1:8081' }
    Write-Utf8Lf (Join-Path $testRoot 'preflight.json') (([ordered]@{ protected_roots = $protected; provider = $provider } | ConvertTo-Json -Depth 20 -Compress))
    Write-Utf8Lf (Join-Path $testRoot 'final_audit.json') (([ordered]@{ protected_roots = $protected; provider = $provider; persistent_process_count = 0; listener_delta = 0 } | ConvertTo-Json -Depth 20 -Compress))
    $receipt = [ordered]@{
        profile = 'cantor-evox2-current-build-pilot-receipt/0.1'
        receipt_uuid = [guid]::NewGuid().Guid
        manifest_sha256 = $package.manifest_sha256
        source_commit = '8e37e3e701d41d61328f89296ae77b8ea3707812'
        host_name = 'EVO-X2'
        remote_root = 'C:/AI/services/cantor-current-pilot-48479932'
        started_utc = '2026-09-08T00:00:00.0000000Z'
        completed_utc = '2026-09-08T00:00:01.0000000Z'
        install_status = 'installed_exact'
        membership_before = $membership
        membership_after = $membership
        protected_before = $protected
        protected_after = $protected
        provider_before = $provider
        provider_after = $provider
        replay_count = 2
        replays = $replays
        optional_query_status = 'skipped_incompatible'
        optional_query_measurement = $null
        configuration_changed = $false
        persistent_process_count = 0
        listener_delta = 0
        refusal = $null
        receipt_sha256 = ''
    }
    $canonical = $receipt | ConvertTo-Json -Depth 30 -Compress
    $receipt.receipt_sha256 = Get-Sha256Text ('cantor-evox2-current-build-pilot-receipt-v1' + [char]0 + $canonical)
    Write-Utf8Lf (Join-Path $testRoot 'pilot_receipt.json') (($receipt | ConvertTo-Json -Depth 30 -Compress))
    $valid = & $verifyEvidence -PackageRoot $packageRootPath -EvidenceRoot $testRoot | ConvertFrom-Json
    if ($valid.status -cne 'verified') { throw 'constructed evidence did not verify' }

    $preflightPath = Join-Path $testRoot 'preflight.json'
    $finalAuditPath = Join-Path $testRoot 'final_audit.json'
    $precisionPreflight = Get-Content -LiteralPath $preflightPath -Raw | ConvertFrom-Json
    $precisionFinal = Get-Content -LiteralPath $finalAuditPath -Raw | ConvertFrom-Json
    $precisionPreflight.provider.creation_utc = '2026-09-08T00:00:00Z'
    $precisionFinal.provider.creation_utc = '2026-09-08T00:00:00Z'
    Write-Utf8Lf $preflightPath (($precisionPreflight | ConvertTo-Json -Depth 20 -Compress))
    Write-Utf8Lf $finalAuditPath (($precisionFinal | ConvertTo-Json -Depth 20 -Compress))
    $precisionValid = & $verifyEvidence -PackageRoot $packageRootPath -EvidenceRoot $testRoot | ConvertFrom-Json
    if ($precisionValid.status -cne 'verified') { throw 'equivalent timestamp precision did not verify' }
    $precisionPreflight.provider.creation_utc = '2026-09-08T00:00:01Z'
    Write-Utf8Lf $preflightPath (($precisionPreflight | ConvertTo-Json -Depth 20 -Compress))
    $refused = $false
    try { & $verifyEvidence -PackageRoot $packageRootPath -EvidenceRoot $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'different provider creation moment was admitted' }
    $precisionPreflight.provider.creation_utc = '2026-09-08T00:00:00Z'
    Write-Utf8Lf $preflightPath (($precisionPreflight | ConvertTo-Json -Depth 20 -Compress))

    $outputOne = Join-Path $testRoot 'a8_replay_1.stdout.json'
    [IO.File]::AppendAllText($outputOne, 'x')
    $refused = $false
    try { & $verifyEvidence -PackageRoot $packageRootPath -EvidenceRoot $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'output tamper was admitted' }
    $lines = @(& $verifier $input 2>&1)
    Write-Utf8Lf $outputOne (($lines | ForEach-Object { $_.ToString() }) -join "`n")

    $extra = Join-Path $testRoot 'extra.json'
    Write-Utf8Lf $extra '{}'
    $refused = $false
    try { & $verifyEvidence -PackageRoot $packageRootPath -EvidenceRoot $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'extra evidence was admitted' }
    Remove-Item -LiteralPath $extra -Force

    $receiptPath = Join-Path $testRoot 'pilot_receipt.json'
    $changed = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    $changed.configuration_changed = $true
    Write-Utf8Lf $receiptPath (($changed | ConvertTo-Json -Depth 30 -Compress))
    $refused = $false
    try { & $verifyEvidence -PackageRoot $packageRootPath -EvidenceRoot $testRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'configuration drift was admitted' }

    [pscustomobject]@{
        profile = 'cantor-evox2-current-build-pilot-evidence-tests/0.1'
        status = 'passed'
        real_replays = 2
        deterministic = ($replays[0].stdout_sha256 -ceq $replays[1].stdout_sha256)
        valid_evidence = 1
        timestamp_precision_equivalences = 1
        isolated_refusals = 4
        stdout_bytes = $replays[0].stdout_bytes
        stdout_sha256 = $replays[0].stdout_sha256
    } | ConvertTo-Json -Compress
} finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
