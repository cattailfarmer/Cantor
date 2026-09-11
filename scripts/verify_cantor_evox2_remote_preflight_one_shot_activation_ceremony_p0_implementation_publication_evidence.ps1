[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [switch]$RequireBookend
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$path = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/implementation_publication_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-evox2-remote-preflight-one-shot-activation-ceremony-implementation-publication-evidence/0.1' -or
    $manifest.manifest_uuid -cne 'df10f5c4-a4be-4a67-bf6a-8cbb64944f8a' -or
    $manifest.canonical_uuid -cne 'd2724a39-56bd-47ae-8787-064a6196dbfb' -or
    $manifest.publication_proof_uuid -cne 'f7255ff3-9433-43cb-8c5c-211f8dd2635f' -or
    $manifest.implementation_commit -cne '2726ea188b93e70ab8da48d77ec7c43278b64238' -or
    $manifest.implementation_parent -cne '169c7720914b53c7800293f8352e1ede84846013' -or
    $manifest.branch -cne 'codex/self-hosted-corpus') { throw 'activation implementation publication identity differs' }
if (@($manifest.artifacts).Count -ne 14) { throw 'activation implementation publication artifact count differs' }
$seen=@{}
foreach($artifact in $manifest.artifacts){
    $relative=[string]$artifact.path
    if([IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or $relative -match '(^|/)[.][.](/|$)'){throw 'activation implementation publication coordinate differs'}
    $key=$relative.ToUpperInvariant(); if($seen.ContainsKey($key)){throw 'activation implementation publication duplicate coordinate'}; $seen[$key]=$true
    $item=Get-Item -LiteralPath (Join-Path $rootPath $relative) -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne [int64]$artifact.bytes -or (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash -cne [string]$artifact.sha256){throw "activation implementation publication artifact differs: $relative"}
}
$v=$manifest.verification
$counts=@{artifact_count=14;workspace_result_groups=325;workspace_tests_passed=1975;workspace_tests_failed=0;workspace_tests_ignored=22;provider_requests=0;remote_calls=0;effects=0;permits_minted=0;runner_invocations=0}
foreach($key in $counts.Keys){if([int64]$v.$key -ne [int64]$counts[$key]){throw "activation implementation publication count differs: $key"}}
foreach($key in @('implementation_remote_equal','exact_workspace_gates_passed','bridge_formation_eligible_after_bookend')){if(-not [bool]$v.$key){throw "activation implementation publication required truth absent: $key"}}
foreach($key in @('live_authority_created','live_invocation_authorized')){if([bool]$v.$key){throw "activation implementation publication authority promoted: $key"}}
if ($RequireBookend) {
    $head = (& git -C $rootPath rev-parse HEAD).Trim()
    $parent = (& git -C $rootPath rev-parse HEAD^).Trim()
    $tracking = (& git -C $rootPath rev-parse origin/codex/self-hosted-corpus).Trim()
    $directLine = & git -C $rootPath ls-remote origin refs/heads/codex/self-hosted-corpus
    if ($LASTEXITCODE -ne 0) { throw 'activation bookend direct remote query failed' }
    $direct = ($directLine -split '\s+')[0]
    if ($parent -cne [string]$manifest.implementation_commit -or $head -cne $tracking -or $head -cne $direct) { throw 'activation implementation bookend lineage or remote equality differs' }
}
"cantor_evox2_remote_preflight_activation_implementation_publication_evidence_verified=true artifacts=14 implementation_commit=$($manifest.implementation_commit) bookend_required=$([bool]$RequireBookend) permits=0 runner_invocations=0 provider_requests=0 remote_calls=0 effects=0 live_authority=false"
