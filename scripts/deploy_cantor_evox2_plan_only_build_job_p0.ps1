[CmdletBinding()]
param(
    [string] $SshHost = 'evo-x2',
    [string] $PackageRoot = 'D:\CantorBuilds\evox2-plan-only-build-job-p0-package-4fdd29cb',
    [string] $LocalEvidenceRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($SshHost -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$') { throw 'SshHost is outside the closed alias grammar' }
$packagePath = (Resolve-Path -LiteralPath $PackageRoot).Path
$package = & (Join-Path $PSScriptRoot 'verify_cantor_evox2_plan_only_build_job_p0_package.ps1') -PackageRoot $packagePath | ConvertFrom-Json
if ($package.status -cne 'passed' -or [int64] $package.authority_grants -ne 0 -or [int64] $package.effects -ne 0) { throw 'local package verification failed' }
$manifest = Get-Content -LiteralPath (Join-Path $packagePath 'deployment_manifest.json') -Raw | ConvertFrom-Json
$runId = [guid]::NewGuid().Guid
$localParent = [IO.Path]::GetFullPath('D:\CantorBuilds')
if ([string]::IsNullOrWhiteSpace($LocalEvidenceRoot)) { $LocalEvidenceRoot = Join-Path $localParent "evox2-plan-only-build-job-p0-live-$runId" }
$evidencePath = [IO.Path]::GetFullPath($LocalEvidenceRoot)
if (-not $evidencePath.StartsWith($localParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'LocalEvidenceRoot must remain beneath D:\CantorBuilds' }
if (Test-Path -LiteralPath $evidencePath) { throw 'LocalEvidenceRoot already exists' }
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$head = (& git.exe -C $repositoryRoot rev-parse HEAD).Trim()
$tracking = (& git.exe -C $repositoryRoot rev-parse origin/codex/self-hosted-corpus).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $tracking) { throw 'local and fetched canonical lineage differ' }
& git.exe -C $repositoryRoot merge-base --is-ancestor '4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271' $head
if ($LASTEXITCODE -ne 0) { throw 'deployment lineage does not descend from the pinned core bookend' }
$status = @(& git.exe -C $repositoryRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) { throw 'deployment requires a clean published worktree' }
$direct = @(& git.exe -C $repositoryRoot ls-remote --exit-code origin refs/heads/codex/self-hosted-corpus)
if ($LASTEXITCODE -ne 0 -or $direct.Count -ne 1 -or ([string] $direct[0]).Substring(0, 40) -cne $head) { throw 'direct canonical remote lineage differs' }
New-Item -ItemType Directory -Path $evidencePath | Out-Null

$remoteRoot = 'C:\AI\services\cantor-build-planner-d805681d'
$remoteRootPortable = 'C:/AI/services/cantor-build-planner-d805681d'
$remoteStage = "C:\AI\services\cantor-build-planner-staging-$runId"
$remoteRun = "C:\AI\services\cantor-build-planner-run-$runId"
$remoteZip = "$remoteStage.zip"
$transportZip = Join-Path $evidencePath 'transport.zip'

function Write-Utf8Lf([string] $Path, [string] $Text) {
    [IO.File]::WriteAllText($Path, ($Text.TrimEnd("`r", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
}

function Invoke-RemoteJson([string] $Script, [string] $Operation) {
    $prior = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = @($Script | & ssh.exe -T $SshHost powershell.exe -NoProfile -NonInteractive -OutputFormat Text -Command '[scriptblock]::Create([Console]::In.ReadToEnd()).Invoke()' 2>&1)
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prior }
    if ($exitCode -ne 0) { throw "$Operation failed over SSH" }
    $json = @($lines | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_.StartsWith('{', [StringComparison]::Ordinal) -and $_.EndsWith('}', [StringComparison]::Ordinal) })
    if ($json.Count -ne 1) { throw "$Operation did not return exactly one JSON record" }
    return ($json[0] | ConvertFrom-Json)
}

$auditFunctions = @'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
function Get-TextSha256([string]$Text){$sha=[Security.Cryptography.SHA256]::Create();try{return -join($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))|ForEach-Object{$_.ToString('x2')})}finally{$sha.Dispose()}}
function Get-DirectoryIdentity([string]$Root,[string]$Portable){
    $item=Get-Item -LiteralPath $Root
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'protected root boundary changed'}
    $files=@(Get-ChildItem -LiteralPath $Root -Recurse -File -Force|Sort-Object FullName);$rows=@();[int64]$bytes=0
    foreach($file in $files){if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'protected root link changed'};$relative=$file.FullName.Substring($Root.Length+1).Replace('\','/');$hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant();$rows+="$relative|$($file.Length)|$hash";$bytes+=[int64]$file.Length}
    return [ordered]@{root=$Portable;file_count=$files.Count;aggregate_bytes=$bytes;set_sha256=(Get-TextSha256($rows -join "`n"))}
}
function Get-ProtectedIdentities{return @(
    (Get-DirectoryIdentity 'C:\AI\services\cantor-current-pilot-48479932' 'C:/AI/services/cantor-current-pilot-48479932'),
    (Get-DirectoryIdentity 'C:\AI\services\cantor-attention-mcp' 'C:/AI/services/cantor-attention-mcp'),
    (Get-DirectoryIdentity 'C:\AI\services\cantor-needle-runtime' 'C:/AI/services/cantor-needle-runtime'),
    (Get-DirectoryIdentity 'C:\AI\services\sop-agent' 'C:/AI/services/sop-agent'))}
function Get-ProviderIdentity{
    $listeners=@(Get-NetTCPConnection -State Listen -LocalPort 8081 -ErrorAction Stop)
    if($listeners.Count -ne 1 -or $listeners[0].LocalAddress -cne '127.0.0.1'){throw 'provider listener identity changed'}
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$($listeners[0].OwningProcess)";$exe=Get-Item -LiteralPath $process.ExecutablePath
    $model=Get-Item -LiteralPath 'C:\AI\models\validation\Qwen3.5-0.8B-GGUF\Qwen3.5-0.8B-Q4_0.gguf'
    return [ordered]@{pid=[int]$process.ProcessId;creation_utc=$process.CreationDate.ToUniversalTime().ToString('o');command_sha256=(Get-TextSha256([string]$process.CommandLine));executable_bytes=[int64]$exe.Length;executable_sha256=(Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash.ToLowerInvariant();model_bytes=[int64]$model.Length;model_sha256=(Get-FileHash -LiteralPath $model.FullName -Algorithm SHA256).Hash.ToLowerInvariant();listener='127.0.0.1:8081'}
}
function Get-PlannerProcessCount([string]$Root){return @(Get-CimInstance Win32_Process|Where-Object{$null-ne$_.ExecutablePath -and $_.ExecutablePath.StartsWith($Root+'\',[StringComparison]::OrdinalIgnoreCase)}).Count}
'@

$auditTemplate = @'
__FUNCTIONS__
$final='__FINAL__';$stage='__STAGE__';$run='__RUN__';$drive=Get-PSDrive -Name C
[ordered]@{profile='cantor-evox2-plan-only-build-job-host-audit/0.1';host_name=$env:COMPUTERNAME;final_exists=(Test-Path -LiteralPath $final);staging_exists=(Test-Path -LiteralPath $stage);run_exists=(Test-Path -LiteralPath $run);free_bytes=[int64]$drive.Free;protected_roots=(Get-ProtectedIdentities);provider=(Get-ProviderIdentity);persistent_process_count=(Get-PlannerProcessCount $final)}|ConvertTo-Json -Depth 20 -Compress
'@
$auditScript = $auditTemplate.Replace('__FUNCTIONS__', $auditFunctions).Replace('__FINAL__', $remoteRoot).Replace('__STAGE__', $remoteStage).Replace('__RUN__', $remoteRun)
$preflight = Invoke-RemoteJson $auditScript 'remote preflight'
if ($preflight.host_name -cne 'EVO-X2' -or $preflight.final_exists -or $preflight.staging_exists -or $preflight.run_exists -or [int64] $preflight.free_bytes -lt ([int64] $package.aggregate_bytes * 4)) { throw 'remote preflight refused host root collision or capacity' }
Write-Utf8Lf (Join-Path $evidencePath 'preflight.json') ($preflight | ConvertTo-Json -Depth 30 -Compress)

try {
    Compress-Archive -Path (Join-Path $packagePath '*') -DestinationPath $transportZip -CompressionLevel Optimal
    $zip = Get-Item -LiteralPath $transportZip
    $zipSha = (Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    & scp.exe $transportZip "${SshHost}:$($remoteZip.Replace('\','/'))"
    if ($LASTEXITCODE -ne 0) { throw 'transport archive transfer failed' }

    $installTemplate = @'
__FUNCTIONS__
$final='__FINAL__';$finalPortable='__FINAL_PORTABLE__';$stage='__STAGE__';$run='__RUN__';$zip='__ZIP__'
$expectedZipBytes=[int64]__ZIP_BYTES__;$expectedZipSha='__ZIP_SHA__';$expectedManifest='__MANIFEST_SHA__';$expectedSource='4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271'
function Write-Utf8([string]$Path,[string]$Text){[IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false))}
try{
    if($env:COMPUTERNAME -cne 'EVO-X2' -or (Test-Path -LiteralPath $final) -or (Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $run)){throw 'remote target boundary refused'}
    $zipItem=Get-Item -LiteralPath $zip;if($zipItem.Length-ne$expectedZipBytes -or (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()-cne$expectedZipSha){throw 'transport identity changed'}
    Expand-Archive -LiteralPath $zip -DestinationPath $stage
    $manifestPath=Join-Path $stage 'deployment_manifest.json';$remoteManifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    if($remoteManifest.profile-cne'cantor-evox2-plan-only-build-job-deployment-manifest/0.1' -or $remoteManifest.source_commit-cne$expectedSource -or $remoteManifest.manifest_sha256-cne$expectedManifest -or [int]$remoteManifest.artifact_count-ne9 -or @($remoteManifest.artifacts).Count-ne9 -or @($remoteManifest.authority_grants).Count-ne0){throw 'remote manifest coordinates changed'}
    $provided=[string]$remoteManifest.manifest_sha256;$remoteManifest.manifest_sha256='';$manifestCanonical=$remoteManifest|ConvertTo-Json -Depth 20 -Compress
    if((Get-TextSha256('cantor-evox2-plan-only-build-job-deployment-manifest-v1'+[char]0+$manifestCanonical))-cne$provided){throw 'remote manifest self digest changed'};$remoteManifest.manifest_sha256=$provided
    $seen=@{};[int64]$remoteAggregate=0
    foreach($artifact in @($remoteManifest.artifacts)){$relative=[string]$artifact.relative_path;if($relative-cnotmatch'^[A-Za-z0-9._/-]{1,256}$' -or $relative.StartsWith('/') -or $relative-match'(^|/)\.\.(/|$)'){throw 'remote artifact path refused'};$key=$relative.ToUpperInvariant();if($seen.ContainsKey($key)){throw 'remote duplicate artifact'};$seen[$key]=$true;$path=Join-Path $stage $relative;$item=Get-Item -LiteralPath $path;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length-ne[int64]$artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()-cne[string]$artifact.sha256){throw 'remote artifact identity changed'};$remoteAggregate+=[int64]$item.Length}
    if($remoteAggregate-ne[int64]$remoteManifest.aggregate_bytes -or @(Get-ChildItem -LiteralPath $stage -Recurse -File -Force).Count-ne10){throw 'remote package account changed'}
    $remoteRequest=Get-Content -LiteralPath (Join-Path $stage 'request.json') -Raw|ConvertFrom-Json
    $remoteVerification=[ordered]@{status='passed';source_commit=$expectedSource;source_archive_sha256=[string]$remoteRequest.source_archive_sha256;manifest_sha256=$provided}
    $protectedBefore=Get-ProtectedIdentities;$providerBefore=Get-ProviderIdentity
    Rename-Item -LiteralPath $stage -NewName (Split-Path -Leaf $final)
    New-Item -ItemType Directory -Path $run|Out-Null
    $compiler=Join-Path $final 'bin\cantor-evox2-plan-only-build-job.exe';$verifier=Join-Path $final 'bin\cantor-evox2-plan-only-build-job-verify.exe'
    Push-Location -LiteralPath $final
    try{
        $timer=[Diagnostics.Stopwatch]::StartNew();$plan1=(& $compiler request.json|Out-String).TrimEnd("`r","`n");$exit1=$LASTEXITCODE;$timer.Stop();$compile1=[int64]$timer.ElapsedMilliseconds
        $timer.Restart();$plan2=(& $compiler request.json|Out-String).TrimEnd("`r","`n");$exit2=$LASTEXITCODE;$timer.Stop();$compile2=[int64]$timer.ElapsedMilliseconds
        if($exit1-ne0 -or $exit2-ne0 -or $plan1-cne$plan2){throw 'compiler double run changed'}
        Write-Utf8 (Join-Path $run 'plan-1.json') $plan1;Write-Utf8 (Join-Path $run 'plan-2.json') $plan2
        Copy-Item -LiteralPath (Join-Path $final 'request.json') -Destination (Join-Path $run 'request.json')
        Copy-Item -LiteralPath (Join-Path $run 'plan-1.json'),(Join-Path $run 'plan-2.json') -Destination $final
        try{
            $timer.Restart();$verify1=(& $verifier request.json plan-1.json|Out-String).TrimEnd("`r","`n");$verifyExit1=$LASTEXITCODE;$timer.Stop();$verifyMs1=[int64]$timer.ElapsedMilliseconds
            $timer.Restart();$verify2=(& $verifier request.json plan-2.json|Out-String).TrimEnd("`r","`n");$verifyExit2=$LASTEXITCODE;$timer.Stop();$verifyMs2=[int64]$timer.ElapsedMilliseconds
        }finally{Remove-Item -LiteralPath (Join-Path $final 'plan-1.json'),(Join-Path $final 'plan-2.json') -Force -ErrorAction SilentlyContinue}
        if($verifyExit1-ne0 -or $verifyExit2-ne0){throw 'verifier double run changed'}
        Write-Utf8 (Join-Path $run 'verification-1.json') $verify1;Write-Utf8 (Join-Path $run 'verification-2.json') $verify2
    }finally{Pop-Location}
    foreach($artifact in @($remoteManifest.artifacts)){$path=Join-Path $final ([string]$artifact.relative_path);$item=Get-Item -LiteralPath $path;if($item.Length-ne[int64]$artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()-cne[string]$artifact.sha256){throw 'post-run package artifact identity changed'}}
    if(@(Get-ChildItem -LiteralPath $final -Recurse -File -Force).Count-ne10){throw 'post-run package file account changed'}
    $protectedAfter=Get-ProtectedIdentities;$providerAfter=Get-ProviderIdentity;$processCount=Get-PlannerProcessCount $final
    if(($protectedBefore|ConvertTo-Json -Depth 20 -Compress)-cne($protectedAfter|ConvertTo-Json -Depth 20 -Compress) -or ($providerBefore|ConvertTo-Json -Depth 20 -Compress)-cne($providerAfter|ConvertTo-Json -Depth 20 -Compress) -or $processCount-ne0){throw 'remote conservation changed'}
    $planItem=Get-Item -LiteralPath (Join-Path $run 'plan-1.json');$v1=(Get-Content -LiteralPath (Join-Path $run 'verification-1.json') -Raw|ConvertFrom-Json)
    $receipt=[ordered]@{profile='cantor-evox2-plan-only-build-job-live-receipt/0.1';receipt_uuid=[guid]::NewGuid().Guid;manifest_sha256=$expectedManifest;source_commit=$expectedSource;source_archive_sha256=[string]$remoteVerification.source_archive_sha256;host_name=$env:COMPUTERNAME;remote_root=$finalPortable;install_status='installed_exact';compiler_processes=2;verifier_processes=2;compile_duration_ms=@($compile1,$compile2);verify_duration_ms=@($verifyMs1,$verifyMs2);plan_bytes=[int64]$planItem.Length;plan_sha256=(Get-FileHash -LiteralPath $planItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant();semantic_plan_sha256=[string]$v1.plan_sha256;operation_count=[int]$v1.operation_count;authority_grants=[int]$v1.authority_grant_count;unresolved=[int]$v1.unresolved_count;effects=[int]$v1.effects;protected_before=$protectedBefore;protected_after=$protectedAfter;provider_before=$providerBefore;provider_after=$providerAfter;persistent_process_count=$processCount;physical_build_performed=$false;receipt_sha256=''}
    $receipt.receipt_sha256=Get-TextSha256('cantor-evox2-plan-only-build-job-live-receipt-v1'+[char]0+($receipt|ConvertTo-Json -Depth 30 -Compress));Write-Utf8 (Join-Path $run 'receipt.json') ($receipt|ConvertTo-Json -Depth 30 -Compress)
    [ordered]@{profile='cantor-evox2-plan-only-build-job-live-run/0.1';status='passed';run_root=$run;receipt_path=(Join-Path $run 'receipt.json');request_path=(Join-Path $run 'request.json');plan_1_path=(Join-Path $run 'plan-1.json');plan_2_path=(Join-Path $run 'plan-2.json');verification_1_path=(Join-Path $run 'verification-1.json');verification_2_path=(Join-Path $run 'verification-2.json')}|ConvertTo-Json -Compress
}finally{if(Test-Path -LiteralPath $zip){Remove-Item -LiteralPath $zip -Force};if((Test-Path -LiteralPath $stage) -and $stage.StartsWith('C:\AI\services\cantor-build-planner-staging-',[StringComparison]::OrdinalIgnoreCase)){Remove-Item -LiteralPath $stage -Recurse -Force}}
'@
    $installScript = $installTemplate.Replace('__FUNCTIONS__', $auditFunctions).Replace('__FINAL__', $remoteRoot).Replace('__FINAL_PORTABLE__', $remoteRootPortable).Replace('__STAGE__', $remoteStage).Replace('__RUN__', $remoteRun).Replace('__ZIP__', $remoteZip).Replace('__ZIP_BYTES__', [string] $zip.Length).Replace('__ZIP_SHA__', $zipSha).Replace('__MANIFEST_SHA__', [string] $package.manifest_sha256)
    $live = Invoke-RemoteJson $installScript 'remote install and plan compilation'
    if ($live.status -cne 'passed') { throw 'remote live run did not pass' }
    if (Test-Path -LiteralPath $transportZip) { Remove-Item -LiteralPath $transportZip -Force }
    foreach ($entry in @(
        @($live.receipt_path, 'receipt.json'), @($live.request_path, 'request.json'), @($live.plan_1_path, 'plan-1.json'), @($live.plan_2_path, 'plan-2.json'), @($live.verification_1_path, 'verification-1.json'), @($live.verification_2_path, 'verification-2.json')
    )) {
        & scp.exe "${SshHost}:$(([string] $entry[0]).Replace('\','/'))" (Join-Path $evidencePath ([string] $entry[1]))
        if ($LASTEXITCODE -ne 0) { throw 'remote evidence retrieval failed' }
    }
    $cleanup = "`$path='$remoteRun';if((Test-Path -LiteralPath `$path)-and `$path.StartsWith('C:\AI\services\cantor-build-planner-run-',[StringComparison]::OrdinalIgnoreCase)){Remove-Item -LiteralPath `$path -Recurse -Force};[ordered]@{status='passed'}|ConvertTo-Json -Compress"
    [void](Invoke-RemoteJson $cleanup 'remote run-root cleanup')
    $finalAudit = Invoke-RemoteJson $auditScript 'remote final audit'
    if ($finalAudit.host_name -cne 'EVO-X2' -or -not $finalAudit.final_exists -or $finalAudit.staging_exists -or $finalAudit.run_exists -or [int] $finalAudit.persistent_process_count -ne 0) { throw 'remote final audit refused closure' }
    Write-Utf8Lf (Join-Path $evidencePath 'final_audit.json') ($finalAudit | ConvertTo-Json -Depth 30 -Compress)
    $liveEvidence = & (Join-Path $PSScriptRoot 'verify_cantor_evox2_plan_only_build_job_p0_live_evidence.ps1') -EvidenceRoot $evidencePath -PackageRoot $packagePath | ConvertFrom-Json
    if ($liveEvidence.status -cne 'passed' -or [int] $liveEvidence.authority_grants -ne 0 -or [int] $liveEvidence.effects -ne 0) { throw 'independent live evidence verification failed' }
    [pscustomobject]@{profile='cantor-evox2-plan-only-build-job-deployment/0.1';status='passed';host='EVO-X2';remote_root=$remoteRootPortable;local_evidence_root=$evidencePath;manifest_sha256=[string]$package.manifest_sha256;source_archive_sha256=[string]$package.source_archive_sha256;compiler_processes=2;verifier_processes=2;live_evidence_verified=$true;protected_state_unchanged=$true;provider_state_unchanged=$true;persistent_processes=0;physical_build_performed=$false} | ConvertTo-Json -Compress
} finally {
    if (Test-Path -LiteralPath $transportZip) { Remove-Item -LiteralPath $transportZip -Force }
}
