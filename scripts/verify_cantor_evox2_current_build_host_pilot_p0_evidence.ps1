[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $PackageRoot,
    [Parameter(Mandatory = $true)] [string] $EvidenceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$receiptDomain = 'cantor-evox2-current-build-pilot-receipt-v1'
$expectedReceiptFields = @(
    'profile', 'receipt_uuid', 'manifest_sha256', 'source_commit', 'host_name', 'remote_root',
    'started_utc', 'completed_utc', 'install_status', 'membership_before',
    'membership_after', 'protected_before', 'protected_after', 'provider_before', 'provider_after',
    'replay_count', 'replays', 'optional_query_status', 'optional_query_measurement',
    'configuration_changed', 'persistent_process_count', 'listener_delta', 'refusal', 'receipt_sha256'
)
$expectedReplayFields = @('ordinal', 'executable_relative_path', 'input_relative_path', 'duration_ms', 'exit_code', 'stdout_bytes', 'stdout_sha256', 'status')

function Assert-Exact([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-ExactFieldOrder($Object, [string[]] $Fields, [string] $Name) {
    $actual = @($Object.PSObject.Properties.Name)
    Assert-Exact ($actual.Count -eq $Fields.Count) "$Name field count changed"
    for ($index = 0; $index -lt $Fields.Count; $index++) {
        Assert-Exact ($actual[$index] -ceq $Fields[$index]) "$Name field order changed"
    }
}

function Get-Sha256Text([string] $Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') })
    } finally {
        $sha.Dispose()
    }
}

function Assert-JsonEqual($Left, $Right, [string] $Name) {
    $leftJson = $Left | ConvertTo-Json -Depth 30 -Compress
    $rightJson = $Right | ConvertTo-Json -Depth 30 -Compress
    Assert-Exact ($leftJson -ceq $rightJson) "$Name changed"
}

$package = & (Join-Path $PSScriptRoot 'verify_cantor_evox2_current_build_host_pilot_p0_package.ps1') -PackageRoot $PackageRoot | ConvertFrom-Json
Assert-Exact ($package.status -ceq 'verified') 'package verification failed'
$evidence = (Resolve-Path -LiteralPath $EvidenceRoot).Path
$evidenceItem = Get-Item -LiteralPath $evidence
Assert-Exact ($evidenceItem.PSIsContainer -and -not ($evidenceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'evidence root must be a direct directory'
$expectedFiles = @('preflight.json', 'pilot_receipt.json', 'a8_replay_1.stdout.json', 'a8_replay_2.stdout.json', 'final_audit.json')
$actualFiles = @(Get-ChildItem -LiteralPath $evidence -File | Sort-Object Name)
Assert-Exact ($actualFiles.Count -eq $expectedFiles.Count) 'evidence file count changed'
for ($index = 0; $index -lt $expectedFiles.Count; $index++) {
    Assert-Exact ($actualFiles[$index].Name -ceq @($expectedFiles | Sort-Object)[$index]) 'evidence membership changed'
    Assert-Exact (-not ($actualFiles[$index].Attributes -band [IO.FileAttributes]::ReparsePoint)) 'linked evidence file refused'
    Assert-Exact ($actualFiles[$index].Length -le 1048576) 'evidence file exceeds one MiB'
}

$preflight = Get-Content -LiteralPath (Join-Path $evidence 'preflight.json') -Raw | ConvertFrom-Json
$receiptPath = Join-Path $evidence 'pilot_receipt.json'
$receiptRaw = Get-Content -LiteralPath $receiptPath -Raw
Assert-Exact ($receiptRaw.EndsWith("`n", [StringComparison]::Ordinal) -and -not $receiptRaw.EndsWith("`r`n", [StringComparison]::Ordinal)) 'receipt transport must end in one LF'
$receipt = $receiptRaw | ConvertFrom-Json
$finalAudit = Get-Content -LiteralPath (Join-Path $evidence 'final_audit.json') -Raw | ConvertFrom-Json
Assert-ExactFieldOrder $receipt $expectedReceiptFields 'receipt'
Assert-Exact ($receipt.profile -ceq 'cantor-evox2-current-build-pilot-receipt/0.1') 'receipt profile changed'
Assert-Exact ([string]$receipt.receipt_uuid -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') 'receipt UUID is invalid'
Assert-Exact ($receipt.manifest_sha256 -ceq $package.manifest_sha256) 'receipt manifest identity changed'
Assert-Exact ($receipt.source_commit -ceq '8e37e3e701d41d61328f89296ae77b8ea3707812') 'receipt source lineage changed'
Assert-Exact ($receipt.host_name -ceq 'EVO-X2' -and $receipt.remote_root -ceq 'C:/AI/services/cantor-current-pilot-48479932') 'receipt target changed'
Assert-Exact (-not [string]::IsNullOrWhiteSpace([string]$receipt.started_utc) -and -not [string]::IsNullOrWhiteSpace([string]$receipt.completed_utc)) 'receipt timestamps are absent'
Assert-Exact ($receipt.install_status -ceq 'installed_exact') 'install status changed'
Assert-Exact ([int]$receipt.replay_count -eq 2 -and @($receipt.replays).Count -eq 2) 'replay count changed'
Assert-Exact ($receipt.optional_query_status -ceq 'skipped_incompatible' -and $null -eq $receipt.optional_query_measurement) 'optional query truth changed'
Assert-Exact ($receipt.configuration_changed -eq $false -and [int]$receipt.persistent_process_count -eq 0 -and [int]$receipt.listener_delta -eq 0) 'closure invariant changed'
Assert-Exact ($null -eq $receipt.refusal) 'successful receipt contains a refusal'

$providedDigest = [string]$receipt.receipt_sha256
Assert-Exact ($providedDigest -cmatch '^[0-9a-f]{64}$') 'receipt digest grammar changed'
$canonicalTransport = $receiptRaw.Substring(0, $receiptRaw.Length - 1)
$canonical = [regex]::Replace($canonicalTransport, '"receipt_sha256":"[0-9a-f]{64}"\}$', '"receipt_sha256":""}')
Assert-Exact ($canonical -cne $canonicalTransport) 'receipt digest field was not the final canonical field'
Assert-Exact ((Get-Sha256Text ($receiptDomain + [char]0 + $canonical)) -ceq $providedDigest) 'receipt self digest changed'

Assert-JsonEqual $receipt.membership_before $receipt.membership_after 'package membership'
Assert-Exact (@($receipt.membership_before).Count -eq 36) 'receipt package membership count changed'
Assert-JsonEqual $receipt.protected_before $receipt.protected_after 'protected roots'
Assert-JsonEqual $receipt.provider_before $receipt.provider_after 'provider identity'
Assert-JsonEqual $preflight.protected_roots $receipt.protected_before 'preflight protected roots'
Assert-JsonEqual $preflight.provider $receipt.provider_before 'preflight provider identity'
Assert-JsonEqual $finalAudit.protected_roots $receipt.protected_after 'final protected roots'
Assert-JsonEqual $finalAudit.provider $receipt.provider_after 'final provider identity'
Assert-Exact ([int]$finalAudit.persistent_process_count -eq 0 -and [int]$finalAudit.listener_delta -eq 0) 'final audit closure changed'

for ($index = 0; $index -lt 2; $index++) {
    $replay = $receipt.replays[$index]
    Assert-ExactFieldOrder $replay $expectedReplayFields 'replay'
    Assert-Exact ([int]$replay.ordinal -eq ($index + 1)) 'replay ordinal changed'
    Assert-Exact ($replay.executable_relative_path -ceq 'bin/cantor-b1-production-broker-projection-evidence-verify.exe') 'replay executable changed'
    Assert-Exact ($replay.input_relative_path -ceq 'evidence/a8') 'replay input changed'
    Assert-Exact ([int64]$replay.duration_ms -ge 0 -and [int64]$replay.duration_ms -le 600000) 'replay duration outside bound'
    Assert-Exact ([int]$replay.exit_code -eq 0 -and $replay.status -ceq 'passed') 'replay did not pass'
    $outputPath = Join-Path $evidence ("a8_replay_$($index + 1).stdout.json")
    $outputItem = Get-Item -LiteralPath $outputPath
    Assert-Exact ($outputItem.Length -eq [int64]$replay.stdout_bytes) 'replay output bytes changed'
    Assert-Exact ((Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant() -ceq [string]$replay.stdout_sha256) 'replay output digest changed'
    $null = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
}
Assert-Exact ($receipt.replays[0].stdout_bytes -eq $receipt.replays[1].stdout_bytes -and $receipt.replays[0].stdout_sha256 -ceq $receipt.replays[1].stdout_sha256) 'fresh replay outputs differ'

[pscustomobject]@{
    profile = 'cantor-evox2-current-build-pilot-evidence-verification/0.1'
    status = 'verified'
    receipt_sha256 = $providedDigest
    manifest_sha256 = $package.manifest_sha256
    artifacts = 36
    retained_evidence = 34
    replays = 2
    replay_stdout_bytes = [int64]$receipt.replays[0].stdout_bytes
    replay_stdout_sha256 = [string]$receipt.replays[0].stdout_sha256
    optional_query = [string]$receipt.optional_query_status
    protected_state_unchanged = $true
    provider_state_unchanged = $true
    persistent_processes = 0
    listener_delta = 0
} | ConvertTo-Json -Compress
