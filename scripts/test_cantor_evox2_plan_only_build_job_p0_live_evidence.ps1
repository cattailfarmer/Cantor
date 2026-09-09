[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $PackageRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$parent = [IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot = [IO.Path]::GetFullPath((Join-Path $parent ('evox2-plan-only-live-evidence-test-' + [guid]::NewGuid().Guid)))
$caseRoots = New-Object System.Collections.Generic.List[string]

function Write-Utf8([string] $Path, [string] $Text) { [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false)) }
function Get-TextSha256([string] $Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
}
function Remove-GeneratedRoot([string] $Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $full.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'unsafe generated root' }
    if (Test-Path -LiteralPath $full) { [IO.Directory]::Delete(('\\?\' + $full), $true) }
}
function New-CaseRoot([string] $Name) {
    $path = [IO.Path]::GetFullPath((Join-Path $parent ('evox2-plan-only-live-evidence-' + $Name + '-' + [guid]::NewGuid().Guid)))
    [void] $caseRoots.Add($path)
    Copy-Item -LiteralPath $testRoot -Destination $path -Recurse
    return $path
}
function Assert-Refused([string] $Path, [string] $Name) {
    $refused = $false
    try { & $verify -EvidenceRoot $Path -PackageRoot $PackageRoot | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw "$Name admitted" }
}

$verify = Join-Path $PSScriptRoot 'verify_cantor_evox2_plan_only_build_job_p0_live_evidence.ps1'
$package = (Resolve-Path -LiteralPath $PackageRoot).Path
$compiler = Join-Path $package 'bin\cantor-evox2-plan-only-build-job.exe'
$nativeVerifier = Join-Path $package 'bin\cantor-evox2-plan-only-build-job-verify.exe'
try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $package 'request.json') -Destination $testRoot
    Push-Location -LiteralPath $testRoot
    try {
        $plan1 = (& $compiler request.json 2>&1 | Out-String).TrimEnd("`r", "`n")
        $exit1 = $LASTEXITCODE
        $plan2 = (& $compiler request.json 2>&1 | Out-String).TrimEnd("`r", "`n")
        $exit2 = $LASTEXITCODE
        if ($exit1 -ne 0 -or $exit2 -ne 0 -or $plan1 -cne $plan2) { throw 'fixture compiler mismatch' }
        Write-Utf8 (Join-Path $testRoot 'plan-1.json') $plan1
        Write-Utf8 (Join-Path $testRoot 'plan-2.json') $plan2
        $verification1 = (& $nativeVerifier request.json plan-1.json 2>&1 | Out-String).TrimEnd("`r", "`n")
        $verifyExit1 = $LASTEXITCODE
        $verification2 = (& $nativeVerifier request.json plan-2.json 2>&1 | Out-String).TrimEnd("`r", "`n")
        $verifyExit2 = $LASTEXITCODE
        if ($verifyExit1 -ne 0 -or $verifyExit2 -ne 0 -or $verification1 -cne $verification2) { throw 'fixture verifier mismatch' }
        Write-Utf8 (Join-Path $testRoot 'verification-1.json') $verification1
        Write-Utf8 (Join-Path $testRoot 'verification-2.json') $verification2
    } finally { Pop-Location }

    $protected = @(
        [ordered]@{root='C:/AI/services/cantor-current-pilot-48479932';file_count=10;aggregate_bytes=1000;set_sha256=('1' * 64)},
        [ordered]@{root='C:/AI/services/cantor-attention-mcp';file_count=20;aggregate_bytes=2000;set_sha256=('2' * 64)},
        [ordered]@{root='C:/AI/services/cantor-needle-runtime';file_count=30;aggregate_bytes=3000;set_sha256=('3' * 64)},
        [ordered]@{root='C:/AI/services/sop-agent';file_count=40;aggregate_bytes=4000;set_sha256=('4' * 64)}
    )
    $provider = [ordered]@{pid=4242;creation_utc='2026-09-08T12:00:00.0000000Z';command_sha256=('5' * 64);executable_bytes=5000;executable_sha256=('6' * 64);model_bytes=6000;model_sha256=('7' * 64);listener='127.0.0.1:8081'}
    $preflight = [ordered]@{profile='cantor-evox2-plan-only-build-job-host-audit/0.1';host_name='EVO-X2';final_exists=$false;staging_exists=$false;run_exists=$false;free_bytes=1000000000;protected_roots=$protected;provider=$provider;persistent_process_count=0}
    $final = [ordered]@{profile='cantor-evox2-plan-only-build-job-host-audit/0.1';host_name='EVO-X2';final_exists=$true;staging_exists=$false;run_exists=$false;free_bytes=999000000;protected_roots=$protected;provider=$provider;persistent_process_count=0}
    Write-Utf8 (Join-Path $testRoot 'preflight.json') (($preflight | ConvertTo-Json -Depth 30 -Compress) + "`n")
    Write-Utf8 (Join-Path $testRoot 'final_audit.json') (($final | ConvertTo-Json -Depth 30 -Compress) + "`n")

    $request = Get-Content -LiteralPath (Join-Path $testRoot 'request.json') -Raw | ConvertFrom-Json
    $verification = $verification1 | ConvertFrom-Json
    $planItem = Get-Item -LiteralPath (Join-Path $testRoot 'plan-1.json')
    $receipt = [ordered]@{
        profile='cantor-evox2-plan-only-build-job-live-receipt/0.1';receipt_uuid='0ec4b6a1-7cf4-4110-93be-ff01c0c8ec18'
        manifest_sha256='2a8a26fea6fcaef8e3cfd1a70d051339814e0883b08ac632740682e119207eff';source_commit='4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271';source_archive_sha256=[string]$request.source_archive_sha256
        host_name='EVO-X2';remote_root='C:/AI/services/cantor-build-planner-d805681d';install_status='installed_exact';compiler_processes=2;verifier_processes=2
        compile_duration_ms=@(1,2);verify_duration_ms=@(3,4);plan_bytes=[int64]$planItem.Length;plan_sha256=(Get-FileHash -LiteralPath $planItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant();semantic_plan_sha256=[string]$verification.plan_sha256
        operation_count=[int]$verification.operation_count;authority_grants=[int]$verification.authority_grant_count;unresolved=[int]$verification.unresolved_count;effects=[int]$verification.effects
        protected_before=$protected;protected_after=$protected;provider_before=$provider;provider_after=$provider;persistent_process_count=0;physical_build_performed=$false;receipt_sha256=''
    }
    $receipt.receipt_sha256 = Get-TextSha256 ('cantor-evox2-plan-only-build-job-live-receipt-v1' + [char]0 + ($receipt | ConvertTo-Json -Depth 30 -Compress))
    Write-Utf8 (Join-Path $testRoot 'receipt.json') ($receipt | ConvertTo-Json -Depth 30 -Compress)

    $result = & $verify -EvidenceRoot $testRoot -PackageRoot $package | ConvertFrom-Json
    if ($result.status -cne 'passed' -or [int]$result.evidence_files -ne 8 -or [int]$result.authority_grants -ne 0 -or [int]$result.effects -ne 0) { throw 'valid live evidence fixture failed' }

    $case = New-CaseRoot 'plan-tamper'
    [IO.File]::AppendAllText((Join-Path $case 'plan-1.json'), "`n", [Text.UTF8Encoding]::new($false))
    Assert-Refused $case 'plan byte tamper'

    $case = New-CaseRoot 'receipt-tamper'
    $tamperedReceipt = Get-Content -LiteralPath (Join-Path $case 'receipt.json') -Raw | ConvertFrom-Json
    $tamperedReceipt.effects = 1
    Write-Utf8 (Join-Path $case 'receipt.json') ($tamperedReceipt | ConvertTo-Json -Depth 30 -Compress)
    Assert-Refused $case 'receipt semantic tamper'

    $case = New-CaseRoot 'provider-tamper'
    $tamperedFinal = Get-Content -LiteralPath (Join-Path $case 'final_audit.json') -Raw | ConvertFrom-Json
    $tamperedFinal.provider.model_sha256 = '8' * 64
    Write-Utf8 (Join-Path $case 'final_audit.json') (($tamperedFinal | ConvertTo-Json -Depth 30 -Compress) + "`n")
    Assert-Refused $case 'provider conservation tamper'

    $case = New-CaseRoot 'extra-file'
    Write-Utf8 (Join-Path $case 'extra.json') '{}'
    Assert-Refused $case 'extra evidence file'

    "cantor_evox2_plan_only_build_job_p0_live_evidence_tests=passed successes=1 isolated_refusals=4 remote_calls=0 effects=0"
} finally {
    foreach ($caseRoot in $caseRoots) { Remove-GeneratedRoot $caseRoot }
    Remove-GeneratedRoot $testRoot
}
