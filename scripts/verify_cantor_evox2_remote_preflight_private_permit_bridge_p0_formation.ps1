param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_formation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
function Assert-Equal($Actual, $Expected, [string]$Name) { if ($Actual -cne $Expected) { throw "$Name differs" } }
Assert-Equal $manifest.profile 'cantor-evox2-remote-preflight-private-permit-bridge-formation-evidence/0.1' 'profile'
Assert-Equal $manifest.manifest_uuid 'ff7acb22-f491-491a-9b1e-c0c3a46d7c23' 'manifest_uuid'
Assert-Equal $manifest.canonical_uuid '06d82d16-143a-4abb-9c70-c03163285842' 'canonical_uuid'
Assert-Equal $manifest.source_snapshot_uuid '750fbbb5-f72f-4816-882f-d8b0ebf1acc7' 'source_snapshot_uuid'
Assert-Equal $manifest.formation_signature_uuid '3f7d776d-e012-4efc-9426-d40cf6af7fcb' 'formation_signature_uuid'
Assert-Equal $manifest.predecessor_bookend '40b20537cbe8fbd143bb3298ea92ca8b77f46c33' 'predecessor_bookend'
if (@($manifest.artifacts).Count -ne 23) { throw 'artifact count differs' }
$seen=@{}
foreach ($artifact in $manifest.artifacts) {
    $relative=[string]$artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or $relative -match '(^|/)[.][.](/|$)') { throw 'artifact coordinate differs' }
    $key=$relative.ToUpperInvariant(); if($seen.ContainsKey($key)){throw 'duplicate artifact coordinate'}; $seen[$key]=$true
    $item=Get-Item -LiteralPath (Join-Path $rootPath $relative) -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne [int64]$artifact.bytes -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -cne [string]$artifact.sha256){throw "formation artifact differs: $relative"}
    if($relative -like 'crates/*' -or $relative -like '*.rs'){throw 'implementation artifact admitted into formation'}
}
$signatureRelative='narrative/registries/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Satisfaction_Signature.sop'
$bindingPattern='^  \+ \[artifact_binding\] (?<path>.+) bytes(?<bytes>\d+) SHA256 (?<sha>[A-F0-9]{64})$'
$bindings=@{}
foreach($line in (Get-Content -LiteralPath (Join-Path $rootPath $signatureRelative))){if($line -match $bindingPattern){if($bindings.ContainsKey($Matches.path)){throw 'duplicate signature binding'};$bindings[$Matches.path]=@([int64]$Matches.bytes,$Matches.sha)}}
if($bindings.Count -ne 22){throw 'signature binding count differs'}
foreach($artifact in $manifest.artifacts){if($artifact.path -ceq $signatureRelative){continue};if(-not $bindings.ContainsKey([string]$artifact.path)){throw "signature binding absent: $($artifact.path)"};$b=$bindings[[string]$artifact.path];if($b[0] -ne [int64]$artifact.bytes -or $b[1] -cne [string]$artifact.sha256){throw "signature binding differs: $($artifact.path)"}}
$v=$manifest.verification
$counts=@{artifact_count=23;signature_binding_count=22;requirements=24;acceptance=5;bridge_stages=6;terminal_dispositions=4;maximum_admissions=1;maximum_permit_issuances=1;maximum_permits=1;maximum_runner_entries=1;maximum_processes=1;retry_count=0;argument_atoms=19;timeout_millis=30000;maximum_stdout_bytes=65536;maximum_stderr_bytes=65536;formation_permit_constructors=0;formation_permit_issuances=0;formation_runner_invocations=0;process_spawns=0;provider_requests=0;remote_calls=0;effects=0;synthetic_trials=0}
foreach($key in $counts.Keys){if([int64]$v.$key -ne [int64]$counts[$key]){throw "formation count differs: $key"}}
foreach($key in @('bridge_module_crate_private','bridge_entry_crate_private','runner_issuer_crate_private','all_pure_validation_before_issuance','admission_consumed_by_issuer','permit_consumed_before_runner','runner_entry_is_fn_once','implementation_eligible_only_after_bookend')){if(-not [bool]$v.$key){throw "required invariant absent: $key"}}
foreach($key in @('production_admission_constructor_present','public_bridge_export_present','admission_serializable','admission_cloneable','terminal_capability_bearing','terminal_has_outgoing_edge','correspondence_is_live_admission','work_slice_language_is_live_admission','publication_is_invocation_authority','live_initiation_authorized_by_formation')){if([bool]$v.$key){throw "forbidden invariant promoted: $key"}}
$texts=@{target_host='EVO-X2';ssh_host='evo-x2';executable_path='C:/Windows/System32/OpenSSH/ssh.exe';activation_implementation_commit='2726ea188b93e70ab8da48d77ec7c43278b64238';activation_bookend_commit='80f2ef9f6eed3c797b911ba3c7f45e8d28130841';runner_implementation_commit='0eb334670d825ea7123beb445df1a47e1bc81349';runner_bookend_commit='0674395c78a998ce1c36c714e52bae68d0f83f58';producer_implementation_commit='606588a6dd542b31816d116abf909f50d0881937';producer_bookend_commit='b48c4d7ac48e51aaf70f179cc7b1cdd15e9d5bd0'}
foreach($key in $texts.Keys){Assert-Equal $v.$key $texts[$key] $key}
$source='source_documents/2026-09-11_evox2_remote_preflight_private_permit_bridge_p0/EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Source.sop'
$sourceItem=Get-Item -LiteralPath (Join-Path $rootPath $source);if($sourceItem.Length -ne 3892 -or (Get-FileHash -LiteralPath $sourceItem.FullName -Algorithm SHA256).Hash -cne '0DF57E27D2F6EC1F7777CE68D313101DCA1E22CFFF9B710EC4D616435EE3A8CD'){throw 'source identity differs'}
$specPath=Join-Path $rootPath 'specifications/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0.sop'
$spec=Get-Content -LiteralPath $specPath
if(@($spec|Where-Object{$_ -match '^  \+ \[EPRPPB-\d{3}\]'}).Count -ne 24){throw 'spec requirement count differs'}
if(@($spec|Where-Object{$_ -match '^  \+ \[EPRPPB-A\d{2}\]'}).Count -ne 5){throw 'spec acceptance count differs'}
$specRaw=$spec -join "`n"
foreach($token in @('pub(crate) module declaration','no pub mod no pub use','no production admission constructor exists','moves the opaque admission into the one runner issuer','moves that permit into one FnOnce runner call','completed_available completed_provider_unavailable abandoned_after_consumption or receipt_refused','formation and provider-free implementation tests perform runner invocations0 process spawns0 provider requests0 remote calls0 effects0','remain locked')){if(-not $specRaw.Contains($token)){throw "spec invariant absent: $token"}}
$signatureRaw=Get-Content -LiteralPath (Join-Path $rootPath $signatureRelative) -Raw
if(-not $signatureRaw.Contains('this SJS signature is not live admission operator consent invocation authority or a runner receipt')){throw 'signature nonauthority absent'}
'cantor_evox2_remote_preflight_private_permit_bridge_formation_verified=true artifacts=23 bindings=22 requirements=24 acceptance=5 stages=6 terminals=4 admissions=1 permit_issuances=1 permits=1 runner_entries=1 retries=0 formation_constructors=0 formation_runner_invocations=0 process_spawns=0 provider_requests=0 remote_calls=0 effects=0'
