[CmdletBinding()]
param(
    [string] $SshHost = 'evo-x2',
    [string] $PackageRoot = 'D:\CantorBuilds\evox2-current-build-host-pilot-p0-package-8e37e3e7',
    [string] $LocalEvidenceRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($SshHost -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$') { throw 'SshHost is outside the closed alias grammar' }
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$packageRootPath = (Resolve-Path -LiteralPath $PackageRoot).Path
$package = & (Join-Path $PSScriptRoot 'verify_cantor_evox2_current_build_host_pilot_p0_package.ps1') -PackageRoot $packageRootPath | ConvertFrom-Json
if ($package.status -cne 'verified') { throw 'local package verification failed' }
$manifest = Get-Content -LiteralPath (Join-Path $packageRootPath 'deployment_manifest.json') -Raw | ConvertFrom-Json
$runId = [guid]::NewGuid().Guid
if ([string]::IsNullOrWhiteSpace($LocalEvidenceRoot)) {
    $LocalEvidenceRoot = Join-Path $repositoryRoot ".local\evox2-current-build-host-pilot-p0\$runId"
}
$evidencePath = [IO.Path]::GetFullPath($LocalEvidenceRoot)
$localAllowed = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.local\evox2-current-build-host-pilot-p0'))
if (-not $evidencePath.StartsWith($localAllowed + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'LocalEvidenceRoot must remain beneath the pilot .local root' }
if (Test-Path -LiteralPath $evidencePath) { throw 'LocalEvidenceRoot already exists' }
New-Item -ItemType Directory -Path $evidencePath -Force | Out-Null

$remoteRoot = 'C:\AI\services\cantor-current-pilot-48479932'
$remoteRootPortable = 'C:/AI/services/cantor-current-pilot-48479932'
$remoteStage = "C:\AI\services\cantor-current-pilot-staging-$runId"
$remoteZip = "$remoteStage.zip"
$transportZip = Join-Path $evidencePath 'transport.zip'

function Write-Utf8Lf([string] $Path, [string] $Text) {
    [IO.File]::WriteAllText($Path, ($Text.TrimEnd("`r", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
}

function Invoke-RemoteJson([string] $Script, [string] $Operation) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))
    $prior = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = @(& ssh.exe -T $SshHost powershell.exe -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand $encoded 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prior
    }
    if ($exitCode -ne 0) { throw "$Operation failed over SSH" }
    $jsonLines = @($lines | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_.StartsWith('{', [StringComparison]::Ordinal) -and $_.EndsWith('}', [StringComparison]::Ordinal) })
    if ($jsonLines.Count -ne 1) { throw "$Operation did not return exactly one JSON record" }
    return ($jsonLines[0] | ConvertFrom-Json)
}

$auditFunctions = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Get-TextSha256([string]$Text) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))|ForEach-Object{$_.ToString('x2')}) }
    finally { $sha.Dispose() }
}
function Get-DirectoryIdentity([string]$Root,[string]$PortableRoot) {
    $item=Get-Item -LiteralPath $Root
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'protected root is not a direct directory'}
    $files=@(Get-ChildItem -LiteralPath $Root -Recurse -File -Force|Sort-Object FullName)
    $lines=@();[int64]$aggregate=0
    foreach($file in $files){
        if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'protected root contains a linked file'}
        $relative=$file.FullName.Substring($Root.Length+1).Replace('\','/')
        $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines += "$relative|$($file.Length)|$hash"
        $aggregate += [int64]$file.Length
    }
    return [ordered]@{root=$PortableRoot;file_count=$files.Count;aggregate_bytes=$aggregate;set_sha256=(Get-TextSha256 ($lines -join "`n"))}
}
function Get-ProtectedIdentities {
    return @(
        (Get-DirectoryIdentity 'C:\AI\services\cantor-attention-mcp' 'C:/AI/services/cantor-attention-mcp'),
        (Get-DirectoryIdentity 'C:\AI\services\cantor-needle-runtime' 'C:/AI/services/cantor-needle-runtime'),
        (Get-DirectoryIdentity 'C:\AI\services\sop-agent' 'C:/AI/services/sop-agent')
    )
}
function Get-ProviderIdentity {
    $listeners=@(Get-NetTCPConnection -State Listen -LocalPort 8081 -ErrorAction Stop)
    if($listeners.Count -ne 1 -or $listeners[0].LocalAddress -cne '127.0.0.1'){throw 'loopback provider listener identity changed'}
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$($listeners[0].OwningProcess)"
    if($null -eq $process){throw 'loopback provider process is absent'}
    $exe=Get-Item -LiteralPath $process.ExecutablePath
    $modelPath='C:\AI\models\validation\Qwen3.5-0.8B-GGUF\Qwen3.5-0.8B-Q4_0.gguf'
    $model=Get-Item -LiteralPath $modelPath
    return [ordered]@{
        pid=[int]$process.ProcessId
        creation_utc=$process.CreationDate.ToUniversalTime().ToString('o')
        command_sha256=(Get-TextSha256 ([string]$process.CommandLine))
        executable_bytes=[int64]$exe.Length
        executable_sha256=(Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        model_bytes=[int64]$model.Length
        model_sha256=(Get-FileHash -LiteralPath $model.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        listener='127.0.0.1:8081'
    }
}
function Get-PilotProcessCount([string]$Root) {
    return @(Get-CimInstance Win32_Process|Where-Object{$null -ne $_.ExecutablePath -and $_.ExecutablePath.StartsWith($Root+'\',[StringComparison]::OrdinalIgnoreCase)}).Count
}
'@

$auditTemplate = @'
__FUNCTIONS__
$final='__FINAL__'
$stage='__STAGE__'
$protected=Get-ProtectedIdentities
$provider=Get-ProviderIdentity
$drive=Get-PSDrive -Name C
[ordered]@{
    profile='cantor-evox2-current-build-pilot-host-audit/0.1'
    host_name=$env:COMPUTERNAME
    final_exists=(Test-Path -LiteralPath $final)
    staging_exists=(Test-Path -LiteralPath $stage)
    free_bytes=[int64]$drive.Free
    protected_roots=$protected
    provider=$provider
    persistent_process_count=(Get-PilotProcessCount $final)
    listener_delta=0
}|ConvertTo-Json -Depth 20 -Compress
'@
$auditScript = $auditTemplate.Replace('__FUNCTIONS__', $auditFunctions).Replace('__FINAL__', $remoteRoot).Replace('__STAGE__', $remoteStage)
$preflight = Invoke-RemoteJson $auditScript 'remote preflight'
if ($preflight.host_name -cne 'EVO-X2' -or $preflight.final_exists -or $preflight.staging_exists -or [int64]$preflight.free_bytes -lt ([int64]$package.aggregate_bytes * 4)) { throw 'remote preflight refused host root collision or capacity' }
Write-Utf8Lf (Join-Path $evidencePath 'preflight.json') (($preflight | ConvertTo-Json -Depth 30 -Compress))

try {
    Compress-Archive -Path (Join-Path $packageRootPath '*') -DestinationPath $transportZip -CompressionLevel Optimal
    $zipItem = Get-Item -LiteralPath $transportZip
    $zipHash = (Get-FileHash -LiteralPath $transportZip -Algorithm SHA256).Hash.ToLowerInvariant()
    & scp.exe $transportZip "${SshHost}:$($remoteZip.Replace('\','/'))"
    if ($LASTEXITCODE -ne 0) { throw 'transport archive transfer failed' }

    $installTemplate = @'
__FUNCTIONS__
$final='__FINAL__'
$finalPortable='__FINAL_PORTABLE__'
$stage='__STAGE__'
$zip='__ZIP__'
$expectedZipBytes=[int64]__ZIP_BYTES__
$expectedZipSha='__ZIP_SHA__'
$expectedManifestSha='__MANIFEST_SHA__'
$expectedSource='8e37e3e701d41d61328f89296ae77b8ea3707812'
$started=[DateTime]::UtcNow.ToString('o')
function Write-Utf8Lf([string]$Path,[string]$Text){[IO.File]::WriteAllText($Path,($Text.TrimEnd("`r","`n")+"`n"),[Text.UTF8Encoding]::new($false))}
function Get-PackageMembership([string]$Root,$Manifest) {
    $rows=@()
    foreach($artifact in @($Manifest.artifacts)){
        $relative=[string]$artifact.relative_path
        if($relative -cnotmatch '^[A-Za-z0-9._/-]{1,256}$' -or $relative.StartsWith('/') -or $relative -match '(^|/)\.\.(/|$)'){throw 'manifest path refused'}
        $path=Join-Path $Root $relative
        $item=Get-Item -LiteralPath $path
        if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'package artifact type refused'}
        $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if($item.Length -ne [int64]$artifact.bytes -or $hash -cne [string]$artifact.sha256){throw 'package artifact identity changed'}
        $rows += [ordered]@{relative_path=$relative;role=[string]$artifact.role;bytes=[int64]$item.Length;sha256=$hash}
    }
    return $rows
}
$installed=$false
try {
    if($env:COMPUTERNAME -cne 'EVO-X2'){throw 'wrong remote host'}
    if(Test-Path -LiteralPath $final){throw 'final root collision'}
    if(Test-Path -LiteralPath $stage){throw 'staging root collision'}
    $zipItem=Get-Item -LiteralPath $zip
    if($zipItem.Length -ne $expectedZipBytes -or (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedZipSha){throw 'transport archive identity changed'}
    Expand-Archive -LiteralPath $zip -DestinationPath $stage
    $manifestPath=Join-Path $stage 'deployment_manifest.json'
    $manifestRaw=Get-Content -LiteralPath $manifestPath -Raw
    $manifest=$manifestRaw|ConvertFrom-Json
    if($manifest.profile -cne 'cantor-evox2-current-build-pilot-deployment-manifest/0.1' -or $manifest.source_commit -cne $expectedSource -or $manifest.target_host -cne 'EVO-X2' -or $manifest.remote_root -cne $finalPortable -or $manifest.manifest_sha256 -cne $expectedManifestSha){throw 'manifest coordinates changed'}
    $provided=[string]$manifest.manifest_sha256
    $manifest.manifest_sha256=''
    $canonical=$manifest|ConvertTo-Json -Depth 20 -Compress
    if((Get-TextSha256 ('cantor-evox2-current-build-pilot-deployment-manifest-v1'+[char]0+$canonical)) -cne $provided){throw 'manifest self digest changed'}
    $manifest.manifest_sha256=$provided
    $membershipBefore=@(Get-PackageMembership $stage $manifest)
    if($membershipBefore.Count -ne 36){throw 'package artifact count changed'}
    $allBefore=@(Get-ChildItem -LiteralPath $stage -Recurse -File)
    if($allBefore.Count -ne 37){throw 'package contains extra or missing files'}
    $protectedBefore=Get-ProtectedIdentities
    $providerBefore=Get-ProviderIdentity
    Rename-Item -LiteralPath $stage -NewName (Split-Path -Leaf $final)
    $installed=$true
    Remove-Item -LiteralPath $zip -Force

    $runRoot=Join-Path $final 'runs'
    New-Item -ItemType Directory -Path $runRoot|Out-Null
    $verifier=Join-Path $final 'bin\cantor-b1-production-broker-projection-evidence-verify.exe'
    $input=Join-Path $final 'evidence\a8'
    $replays=@()
    for($ordinal=1;$ordinal -le 2;$ordinal++){
        $timer=[Diagnostics.Stopwatch]::StartNew()
        $lines=@(& $verifier $input 2>&1)
        $exitCode=$LASTEXITCODE
        $timer.Stop()
        if($exitCode -ne 0){throw 'A8 replay failed'}
        $outputPath=Join-Path $runRoot "a8_replay_$ordinal.stdout.json"
        Write-Utf8Lf $outputPath (($lines|ForEach-Object{$_.ToString()}) -join "`n")
        $output=Get-Item -LiteralPath $outputPath
        $replays += [ordered]@{
            ordinal=$ordinal
            executable_relative_path='bin/cantor-b1-production-broker-projection-evidence-verify.exe'
            input_relative_path='evidence/a8'
            duration_ms=[int64]$timer.ElapsedMilliseconds
            exit_code=0
            stdout_bytes=[int64]$output.Length
            stdout_sha256=(Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
            status='passed'
        }
    }
    if($replays[0].stdout_bytes -ne $replays[1].stdout_bytes -or $replays[0].stdout_sha256 -cne $replays[1].stdout_sha256){throw 'fresh A8 replay outputs differ'}
    $membershipAfter=@(Get-PackageMembership $final $manifest)
    $protectedAfter=Get-ProtectedIdentities
    $providerAfter=Get-ProviderIdentity
    $protectedEqual=(($protectedBefore|ConvertTo-Json -Depth 20 -Compress) -ceq ($protectedAfter|ConvertTo-Json -Depth 20 -Compress))
    $providerEqual=(($providerBefore|ConvertTo-Json -Depth 20 -Compress) -ceq ($providerAfter|ConvertTo-Json -Depth 20 -Compress))
    $memberEqual=(($membershipBefore|ConvertTo-Json -Depth 20 -Compress) -ceq ($membershipAfter|ConvertTo-Json -Depth 20 -Compress))
    $processCount=Get-PilotProcessCount $final
    if(-not $protectedEqual -or -not $providerEqual -or -not $memberEqual -or $processCount -ne 0){throw 'post-replay conservation failed'}
    $receipt=[ordered]@{
        profile='cantor-evox2-current-build-pilot-receipt/0.1'
        receipt_uuid=[guid]::NewGuid().Guid
        manifest_sha256=$provided
        source_commit=$expectedSource
        host_name=$env:COMPUTERNAME
        remote_root=$finalPortable
        started_utc=$started
        completed_utc=[DateTime]::UtcNow.ToString('o')
        install_status='installed_exact'
        membership_before=$membershipBefore
        membership_after=$membershipAfter
        protected_before=$protectedBefore
        protected_after=$protectedAfter
        provider_before=$providerBefore
        provider_after=$providerAfter
        replay_count=2
        replays=$replays
        optional_query_status='skipped_incompatible'
        optional_query_measurement=$null
        configuration_changed=$false
        persistent_process_count=0
        listener_delta=0
        refusal=$null
        receipt_sha256=''
    }
    $receiptCanonical=$receipt|ConvertTo-Json -Depth 30 -Compress
    $receipt.receipt_sha256=Get-TextSha256 ('cantor-evox2-current-build-pilot-receipt-v1'+[char]0+$receiptCanonical)
    $receiptPath=Join-Path $final 'pilot_receipt.json'
    Write-Utf8Lf $receiptPath ($receipt|ConvertTo-Json -Depth 30 -Compress)
    [ordered]@{profile='cantor-evox2-current-build-pilot-live-run/0.1';status='passed';receipt_path=$receiptPath;receipt_sha256=$receipt.receipt_sha256;replay_1_path=(Join-Path $runRoot 'a8_replay_1.stdout.json');replay_2_path=(Join-Path $runRoot 'a8_replay_2.stdout.json')}|ConvertTo-Json -Compress
} catch {
    if(-not $installed -and (Test-Path -LiteralPath $stage) -and $stage.StartsWith('C:\AI\services\cantor-current-pilot-staging-',[StringComparison]::OrdinalIgnoreCase)){Remove-Item -LiteralPath $stage -Recurse -Force}
    throw
} finally {
    if(Test-Path -LiteralPath $zip){Remove-Item -LiteralPath $zip -Force}
}
'@
    $installScript = $installTemplate.Replace('__FUNCTIONS__', $auditFunctions).Replace('__FINAL__', $remoteRoot).Replace('__FINAL_PORTABLE__', $remoteRootPortable).Replace('__STAGE__', $remoteStage).Replace('__ZIP__', $remoteZip).Replace('__ZIP_BYTES__', [string]$zipItem.Length).Replace('__ZIP_SHA__', $zipHash).Replace('__MANIFEST_SHA__', [string]$package.manifest_sha256)
    $live = Invoke-RemoteJson $installScript 'remote install and replay'
    if ($live.status -cne 'passed') { throw 'remote live run did not pass' }
    if (Test-Path -LiteralPath $transportZip) { Remove-Item -LiteralPath $transportZip -Force }

    foreach ($entry in @(
        @($live.receipt_path, 'pilot_receipt.json'),
        @($live.replay_1_path, 'a8_replay_1.stdout.json'),
        @($live.replay_2_path, 'a8_replay_2.stdout.json')
    )) {
        & scp.exe "${SshHost}:$(([string]$entry[0]).Replace('\','/'))" (Join-Path $evidencePath ([string]$entry[1]))
        if ($LASTEXITCODE -ne 0) { throw 'remote evidence retrieval failed' }
    }

    $finalAudit = Invoke-RemoteJson $auditScript 'remote final audit'
    if ($finalAudit.host_name -cne 'EVO-X2' -or -not $finalAudit.final_exists -or $finalAudit.staging_exists -or [int]$finalAudit.persistent_process_count -ne 0) { throw 'remote final audit refused closure' }
    Write-Utf8Lf (Join-Path $evidencePath 'final_audit.json') (($finalAudit | ConvertTo-Json -Depth 30 -Compress))
    $verification = & (Join-Path $PSScriptRoot 'verify_cantor_evox2_current_build_host_pilot_p0_evidence.ps1') -PackageRoot $packageRootPath -EvidenceRoot $evidencePath | ConvertFrom-Json
    [pscustomobject]@{
        profile = 'cantor-evox2-current-build-pilot-deployment/0.1'
        status = 'passed'
        host = 'EVO-X2'
        remote_root = $remoteRootPortable
        local_evidence_root = $evidencePath
        manifest_sha256 = $package.manifest_sha256
        receipt_sha256 = $verification.receipt_sha256
        artifact_count = $verification.artifacts
        retained_evidence = $verification.retained_evidence
        replays = $verification.replays
        replay_stdout_bytes = $verification.replay_stdout_bytes
        replay_stdout_sha256 = $verification.replay_stdout_sha256
        optional_query = $verification.optional_query
        protected_state_unchanged = $verification.protected_state_unchanged
        provider_state_unchanged = $verification.provider_state_unchanged
        persistent_processes = $verification.persistent_processes
        listener_delta = $verification.listener_delta
    } | ConvertTo-Json -Depth 8
} finally {
    if (Test-Path -LiteralPath $transportZip) { Remove-Item -LiteralPath $transportZip -Force }
}
