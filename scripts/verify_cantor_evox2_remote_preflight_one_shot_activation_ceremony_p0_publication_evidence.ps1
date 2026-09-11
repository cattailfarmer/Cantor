param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$path = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/formation_publication_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-evox2-remote-preflight-one-shot-activation-ceremony-formation-publication-evidence/0.1') { throw 'profile mismatch' }
if ($manifest.canonical_uuid -cne 'd2724a39-56bd-47ae-8787-064a6196dbfb') { throw 'canonical mismatch' }
if ($manifest.publication_proof_uuid -cne '9efc0c9a-6703-43a0-8dd7-29b68c9d504c') { throw 'proof mismatch' }
if ($manifest.formation_commit -cne '7b508b67a7b16c091e4dbea512c691b885e33a2f' -or $manifest.formation_parent -cne '0674395c78a998ce1c36c714e52bae68d0f83f58') { throw 'lineage mismatch' }
if (@($manifest.artifacts).Count -ne 12) { throw 'artifact count mismatch' }
$seen=@{}
foreach($artifact in $manifest.artifacts){
    $relative=[string]$artifact.path
    if([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)'){throw 'nonportable path'}
    $key=$relative.ToUpperInvariant(); if($seen.ContainsKey($key)){throw 'duplicate artifact'}; $seen[$key]=$true
    $item=Get-Item -LiteralPath (Join-Path $rootPath $relative)
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "linked artifact $relative"}
    if($item.Length -ne [int64]$artifact.bytes){throw "byte mismatch $relative"}
    if((Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash -cne [string]$artifact.sha256){throw "hash mismatch $relative"}
}
$v=$manifest.verification
$counts=@{artifact_count=12;formation_artifacts=21;formation_bindings=20;isolated_refusals=10;provider_requests=0;remote_calls=0;effects=0;permits_minted=0;runner_invocations=0}
foreach($key in $counts.Keys){if([int64]$v.$key -ne [int64]$counts[$key]){throw "count mismatch $key"}}
foreach($key in @('powershell7_passed','windows_powershell51_passed','pure_implementation_authorized_after_bookend')){if($v.$key -ne $true){throw "required true missing $key"}}
foreach($key in @('live_authority_created','permit_bridge_authorized','live_invocation_authorized')){if($v.$key -ne $false){throw "authority promotion $key"}}
'cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_publication_evidence_verified=true artifacts=12 formation_artifacts=21 formation_bindings=20 isolated_refusals=10 permits=0 runner_invocations=0 provider_requests=0 remote_calls=0 effects=0'
