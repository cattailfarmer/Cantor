[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $EvidenceRoot,
    [string] $PackageRoot = 'D:\CantorBuilds\evox2-plan-only-build-job-p0-package-4fdd29cb',
    [switch] $AllowRepositoryLfNormalization
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedManifest = '2a8a26fea6fcaef8e3cfd1a70d051339814e0883b08ac632740682e119207eff'
$expectedSource = '4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271'
$expectedArchive = '162a82f42619249a11a81ce64c29889eb5cd448a2d3d864ccb5bf26f1b0f325d'
$expectedPlanRaw = '119402a3aebb4b959b7b71ccdf399a00215696b855d5d7a8b3e00b8be68b336a'
$expectedPlanSemantic = '4e3cfa2632a860782ae48000be1b0267ecd308ca5ebb3828a62cfa448e9494e2'
$expectedVerificationRaw = '79e3b008a84d0a78eeb3ac8aaddf18e35ab98303f44e585071fcc46ec64dfe54'
$expectedProtectedRoots = @(
    'C:/AI/services/cantor-current-pilot-48479932',
    'C:/AI/services/cantor-attention-mcp',
    'C:/AI/services/cantor-needle-runtime',
    'C:/AI/services/sop-agent'
)

function Get-TextSha256([string] $Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
}

function Assert-Equal($Actual, $Expected, [string] $Name) {
    if ($Actual -cne $Expected) { throw "$Name mismatch" }
}

function Assert-Shape($Object, [string[]] $Expected, [string] $Name) {
    $actual = @($Object.PSObject.Properties.Name)
    if (($actual -join [char]0) -cne ($Expected -join [char]0)) { throw "$Name shape mismatch" }
}

function Read-BoundedJson([string] $Path, [int64] $MaximumBytes) {
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -le 0 -or $item.Length -gt $MaximumBytes) { throw "evidence file boundary refused: $Path" }
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf) { throw "UTF-8 BOM refused: $Path" }
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    try { $raw = $utf8.GetString($bytes) } catch { throw "invalid UTF-8 evidence: $Path" }
    try { $value = $raw | ConvertFrom-Json } catch { throw "invalid JSON evidence: $Path" }
    return [pscustomobject]@{ Raw = $raw; Value = $value; Bytes = [int64] $bytes.Length }
}

function Assert-ProtectedRoots($Roots, [string] $Name) {
    $rows = @($Roots)
    if ($rows.Count -ne 4) { throw "$Name protected-root count mismatch" }
    for ($index = 0; $index -lt 4; $index++) {
        $row = $rows[$index]
        Assert-Shape $row @('root', 'file_count', 'aggregate_bytes', 'set_sha256') "$Name protected root $index"
        Assert-Equal ([string] $row.root) $expectedProtectedRoots[$index] "$Name protected root $index identity"
        if ([int64] $row.file_count -lt 0 -or [int64] $row.file_count -gt 1000000 -or [int64] $row.aggregate_bytes -lt 0) { throw "$Name protected root $index bounds mismatch" }
        if ([string] $row.set_sha256 -cnotmatch '^[0-9a-f]{64}$') { throw "$Name protected root $index digest mismatch" }
    }
}

function Assert-Provider($Provider, [string] $Name) {
    Assert-Shape $Provider @('pid', 'creation_utc', 'command_sha256', 'executable_bytes', 'executable_sha256', 'model_bytes', 'model_sha256', 'listener') "$Name provider"
    if ([int64] $Provider.pid -le 0 -or [int64] $Provider.executable_bytes -le 0 -or [int64] $Provider.model_bytes -le 0) { throw "$Name provider bounds mismatch" }
    foreach ($digest in @([string] $Provider.command_sha256, [string] $Provider.executable_sha256, [string] $Provider.model_sha256)) {
        if ($digest -cnotmatch '^[0-9a-f]{64}$') { throw "$Name provider digest mismatch" }
    }
    $createdText = if ($Provider.creation_utc -is [datetime]) { $Provider.creation_utc.ToUniversalTime().ToString('o') } else { [string] $Provider.creation_utc }
    $created = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse($createdText, [ref] $created) -or $created.Offset -ne [timespan]::Zero) { throw "$Name provider creation time mismatch" }
    Assert-Equal ([string] $Provider.listener) '127.0.0.1:8081' "$Name provider listener"
}

function Get-CompactJson($Value) { return ($Value | ConvertTo-Json -Depth 50 -Compress) }
function Get-CustodyRaw($Record, [string] $Name) {
    $raw = [string] $Record.Raw
    if (-not $AllowRepositoryLfNormalization) { return $raw }
    if ($raw.EndsWith("`r`n", [StringComparison]::Ordinal) -or $raw.EndsWith("`n`n", [StringComparison]::Ordinal)) { throw "$Name repository normalization boundary mismatch" }
    if ($raw.EndsWith("`n", [StringComparison]::Ordinal)) { return $raw.Substring(0, $raw.Length - 1) }
    return $raw
}

$buildParent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$root = [IO.Path]::GetFullPath($EvidenceRoot)
if ($AllowRepositoryLfNormalization) {
    $repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
    $repositoryEvidenceParent = [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'experiments\evox2_plan_only_build_job_p0'))
    $underRepositoryEvidence = $root.StartsWith($repositoryEvidenceParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    $underGeneratedEvidence = $root.StartsWith($buildParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    if (-not $underRepositoryEvidence -and -not $underGeneratedEvidence) { throw 'normalized EvidenceRoot must remain beneath a governed or generated evidence root' }
} elseif (-not $root.StartsWith($buildParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'EvidenceRoot must remain beneath D:\CantorBuilds' }
$rootItem = Get-Item -LiteralPath $root
if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'evidence root boundary refused' }
$expectedFiles = @('final_audit.json', 'plan-1.json', 'plan-2.json', 'preflight.json', 'receipt.json', 'request.json', 'verification-1.json', 'verification-2.json')
$directories = @(Get-ChildItem -LiteralPath $root -Directory -Force)
$files = @(Get-ChildItem -LiteralPath $root -File -Force)
$actualFiles = @($files.Name | Sort-Object)
if ($directories.Count -ne 0 -or $files.Count -ne 8 -or ($actualFiles -join [char]0) -cne (($expectedFiles | Sort-Object) -join [char]0)) { throw 'live evidence exact membership mismatch' }
if ((@($files | Measure-Object -Property Length -Sum).Sum) -gt 8388608) { throw 'live evidence aggregate bound mismatch' }

$packageJson = & (Join-Path $PSScriptRoot 'verify_cantor_evox2_plan_only_build_job_p0_package.ps1') -PackageRoot $PackageRoot | ConvertFrom-Json
if ($packageJson.status -cne 'passed' -or $packageJson.manifest_sha256 -cne $expectedManifest -or $packageJson.source_archive_sha256 -cne $expectedArchive) { throw 'external package identity mismatch' }
$request = Read-BoundedJson (Join-Path $root 'request.json') 1048576
$plan1 = Read-BoundedJson (Join-Path $root 'plan-1.json') 1048576
$plan2 = Read-BoundedJson (Join-Path $root 'plan-2.json') 1048576
$verification1 = Read-BoundedJson (Join-Path $root 'verification-1.json') 1048576
$verification2 = Read-BoundedJson (Join-Path $root 'verification-2.json') 1048576
$receiptRecord = Read-BoundedJson (Join-Path $root 'receipt.json') 2097152
$preflightRecord = Read-BoundedJson (Join-Path $root 'preflight.json') 2097152
$finalRecord = Read-BoundedJson (Join-Path $root 'final_audit.json') 2097152
$requestRaw = Get-CustodyRaw $request 'request'
$plan1Raw = Get-CustodyRaw $plan1 'plan 1'
$plan2Raw = Get-CustodyRaw $plan2 'plan 2'
$verification1Raw = Get-CustodyRaw $verification1 'verification 1'
$verification2Raw = Get-CustodyRaw $verification2 'verification 2'
$receiptRaw = Get-CustodyRaw $receiptRecord 'receipt'

$packageRequest = [IO.File]::ReadAllText((Join-Path (Resolve-Path -LiteralPath $PackageRoot).Path 'request.json'), [Text.UTF8Encoding]::new($false, $true))
if ($requestRaw -cne $packageRequest) { throw 'retrieved request differs from exact package request' }
if ($plan1Raw -cne $plan2Raw -or [Text.Encoding]::UTF8.GetByteCount($plan1Raw) -ne 6704 -or (Get-TextSha256 $plan1Raw) -cne $expectedPlanRaw) { throw 'retrieved plan byte identity mismatch' }
if ($verification1Raw -cne $verification2Raw -or [Text.Encoding]::UTF8.GetByteCount($verification1Raw) -ne 606 -or (Get-TextSha256 $verification1Raw) -cne $expectedVerificationRaw) { throw 'retrieved verification byte identity mismatch' }

$verifier = Join-Path (Resolve-Path -LiteralPath $PackageRoot).Path 'bin\cantor-evox2-plan-only-build-job-verify.exe'
$replayRoot = $root
$temporaryReplayRoot = $null
if ($AllowRepositoryLfNormalization) {
    $temporaryReplayRoot = [IO.Path]::GetFullPath((Join-Path $buildParent ('evox2-plan-only-live-replay-' + [guid]::NewGuid().Guid)))
    New-Item -ItemType Directory -Path $temporaryReplayRoot | Out-Null
    [IO.File]::WriteAllText((Join-Path $temporaryReplayRoot 'request.json'), $requestRaw, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $temporaryReplayRoot 'plan-1.json'), $plan1Raw, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $temporaryReplayRoot 'plan-2.json'), $plan2Raw, [Text.UTF8Encoding]::new($false))
    $replayRoot = $temporaryReplayRoot
}
Push-Location -LiteralPath $replayRoot
try {
    $replayed1 = (& $verifier request.json plan-1.json 2>&1 | Out-String).TrimEnd("`r", "`n")
    $exit1 = $LASTEXITCODE
    $replayed2 = (& $verifier request.json plan-2.json 2>&1 | Out-String).TrimEnd("`r", "`n")
    $exit2 = $LASTEXITCODE
} finally {
    Pop-Location
    if ($null -ne $temporaryReplayRoot -and (Test-Path -LiteralPath $temporaryReplayRoot)) { [IO.Directory]::Delete(('\\?\' + $temporaryReplayRoot), $true) }
}
if ($exit1 -ne 0 -or $exit2 -ne 0 -or $replayed1 -cne $verification1Raw -or $replayed2 -cne $verification2Raw) { throw 'independent native verification replay mismatch' }
$verification = $verification1.Value
if ($verification.status -cne 'passed' -or $verification.plan_sha256 -cne $expectedPlanSemantic -or [int] $verification.operation_count -ne 7 -or [int] $verification.authority_denial_count -ne 15 -or [int] $verification.authority_grant_count -ne 0 -or [int] $verification.unresolved_count -ne 5 -or -not [bool] $verification.byte_identical_recompilation -or [int] $verification.effects -ne 0) { throw 'verification semantic boundary mismatch' }

$auditShape = @('profile', 'host_name', 'final_exists', 'staging_exists', 'run_exists', 'free_bytes', 'protected_roots', 'provider', 'persistent_process_count')
$preflight = $preflightRecord.Value
$final = $finalRecord.Value
Assert-Shape $preflight $auditShape 'preflight'
Assert-Shape $final $auditShape 'final audit'
foreach ($audit in @($preflight, $final)) {
    Assert-Equal ([string] $audit.profile) 'cantor-evox2-plan-only-build-job-host-audit/0.1' 'audit profile'
    Assert-Equal ([string] $audit.host_name) 'EVO-X2' 'audit host'
    if ([int64] $audit.free_bytes -lt 0 -or [int] $audit.persistent_process_count -ne 0) { throw 'audit bounds or process mismatch' }
}
if ([bool] $preflight.final_exists -or [bool] $preflight.staging_exists -or [bool] $preflight.run_exists) { throw 'preflight absence mismatch' }
if (-not [bool] $final.final_exists -or [bool] $final.staging_exists -or [bool] $final.run_exists) { throw 'final installation mismatch' }
Assert-ProtectedRoots $preflight.protected_roots 'preflight'
Assert-ProtectedRoots $final.protected_roots 'final audit'
Assert-Provider $preflight.provider 'preflight'
Assert-Provider $final.provider 'final audit'

$receipt = $receiptRecord.Value
$receiptShape = @('profile', 'receipt_uuid', 'manifest_sha256', 'source_commit', 'source_archive_sha256', 'host_name', 'remote_root', 'install_status', 'compiler_processes', 'verifier_processes', 'compile_duration_ms', 'verify_duration_ms', 'plan_bytes', 'plan_sha256', 'semantic_plan_sha256', 'operation_count', 'authority_grants', 'unresolved', 'effects', 'protected_before', 'protected_after', 'provider_before', 'provider_after', 'persistent_process_count', 'physical_build_performed', 'receipt_sha256')
Assert-Shape $receipt $receiptShape 'receipt'
$receiptGuid = [guid]::Empty
if (-not [guid]::TryParse([string] $receipt.receipt_uuid, [ref] $receiptGuid)) { throw 'receipt UUID mismatch' }
Assert-Equal ([string] $receipt.profile) 'cantor-evox2-plan-only-build-job-live-receipt/0.1' 'receipt profile'
Assert-Equal ([string] $receipt.manifest_sha256) $expectedManifest 'receipt manifest'
Assert-Equal ([string] $receipt.source_commit) $expectedSource 'receipt source'
Assert-Equal ([string] $receipt.source_archive_sha256) $expectedArchive 'receipt archive'
Assert-Equal ([string] $receipt.host_name) 'EVO-X2' 'receipt host'
Assert-Equal ([string] $receipt.remote_root) 'C:/AI/services/cantor-build-planner-d805681d' 'receipt install root'
Assert-Equal ([string] $receipt.install_status) 'installed_exact' 'receipt install status'
if ([int] $receipt.compiler_processes -ne 2 -or [int] $receipt.verifier_processes -ne 2 -or @($receipt.compile_duration_ms).Count -ne 2 -or @($receipt.verify_duration_ms).Count -ne 2) { throw 'receipt process account mismatch' }
foreach ($duration in @($receipt.compile_duration_ms) + @($receipt.verify_duration_ms)) { if ([int64] $duration -lt 0 -or [int64] $duration -gt 7200000) { throw 'receipt duration bound mismatch' } }
if ([int64] $receipt.plan_bytes -ne 6704 -or [string] $receipt.plan_sha256 -cne $expectedPlanRaw -or [string] $receipt.semantic_plan_sha256 -cne $expectedPlanSemantic -or [int] $receipt.operation_count -ne 7 -or [int] $receipt.authority_grants -ne 0 -or [int] $receipt.unresolved -ne 5 -or [int] $receipt.effects -ne 0 -or [int] $receipt.persistent_process_count -ne 0 -or [bool] $receipt.physical_build_performed) { throw 'receipt semantic account mismatch' }
Assert-ProtectedRoots $receipt.protected_before 'receipt before'
Assert-ProtectedRoots $receipt.protected_after 'receipt after'
Assert-Provider $receipt.provider_before 'receipt before'
Assert-Provider $receipt.provider_after 'receipt after'
$protectedBefore = Get-CompactJson $receipt.protected_before
$protectedAfter = Get-CompactJson $receipt.protected_after
$providerBefore = Get-CompactJson $receipt.provider_before
$providerAfter = Get-CompactJson $receipt.provider_after
if ($protectedBefore -cne $protectedAfter -or $protectedBefore -cne (Get-CompactJson $preflight.protected_roots) -or $protectedAfter -cne (Get-CompactJson $final.protected_roots) -or $providerBefore -cne $providerAfter -or $providerBefore -cne (Get-CompactJson $preflight.provider) -or $providerAfter -cne (Get-CompactJson $final.provider)) { throw 'receipt conservation mismatch' }
$providedReceiptSha = [string] $receipt.receipt_sha256
if ($providedReceiptSha -cnotmatch '^[0-9a-f]{64}$') { throw 'receipt digest syntax mismatch' }
$receiptSuffix = '"receipt_sha256":"' + $providedReceiptSha + '"}'
if (-not $receiptRaw.EndsWith($receiptSuffix, [StringComparison]::Ordinal)) { throw 'receipt canonical suffix mismatch' }
$unsignedReceiptRaw = $receiptRaw.Substring(0, $receiptRaw.Length - $receiptSuffix.Length) + '"receipt_sha256":""}'
$recomputedReceiptSha = Get-TextSha256 ('cantor-evox2-plan-only-build-job-live-receipt-v1' + [char]0 + $unsignedReceiptRaw)
if ($recomputedReceiptSha -cne $providedReceiptSha) { throw 'receipt self digest mismatch' }

[pscustomobject]@{profile='cantor-evox2-plan-only-build-job-live-evidence-verification/0.1';status='passed';source_commit=$expectedSource;manifest_sha256=$expectedManifest;evidence_files=8;compiler_processes=2;verifier_processes=2;operation_count=7;authority_grants=0;unresolved=5;protected_roots=4;provider_conserved=$true;repository_lf_normalization=[bool]$AllowRepositoryLfNormalization;persistent_processes=0;physical_build_performed=$false;effects=0} | ConvertTo-Json -Compress
