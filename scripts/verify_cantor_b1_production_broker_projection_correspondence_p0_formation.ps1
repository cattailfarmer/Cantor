param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$rootPath=(Resolve-Path -LiteralPath $Root).Path
$manifestPath=Join-Path $rootPath 'experiments/b1_production_broker_projection_correspondence_p0/formation_evidence_manifest.json'
$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
function Assert-Equal($Actual,$Expected,[string]$Name){if($Actual -cne $Expected){throw "$Name mismatch"}}
Assert-Equal $manifest.profile 'cantor-b1-production-broker-projection-correspondence-formation-evidence/0.1' 'profile'
Assert-Equal $manifest.canonical_uuid '6a0ee327-1235-4d4c-8a0d-fb1b47f525c1' 'canonical_uuid'
Assert-Equal $manifest.source_snapshot_uuid '3a14ad38-fca5-4528-9a56-ccda97d7f158' 'source_snapshot_uuid'
Assert-Equal $manifest.formation_signature_uuid '2943ebdb-7e37-4203-a99f-dbd6b7fea798' 'formation_signature_uuid'
if(@($manifest.artifacts).Count -ne 21){throw 'artifact_count mismatch'}
$seen=@{}
foreach($artifact in $manifest.artifacts){
 $relative=[string]$artifact.path
 if([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)'){throw 'nonportable artifact path'}
 if($seen.ContainsKey($relative)){throw 'duplicate artifact path'};$seen[$relative]=$true
 $path=Join-Path $rootPath $relative
 if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "missing artifact $relative"}
 $item=Get-Item -LiteralPath $path
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "linked artifact $relative"}
 if($item.Length -ne [int64]$artifact.bytes){throw "byte mismatch $relative"}
 $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
 if($hash -cne [string]$artifact.sha256){throw "hash mismatch $relative"}
 if($relative -like 'crates/*' -or $relative -like '*.rs'){throw 'implementation artifact admitted into formation'}
}
$signatureRelative='narrative/registries/Cantor_B1_Production_Broker_Projection_Correspondence_P0_Satisfaction_Signature.sop'
$signature=Get-Content -LiteralPath (Join-Path $rootPath $signatureRelative)
$bindingPattern='^  \+ \[artifact_binding\] (?<path>.+) bytes(?<bytes>\d+) SHA256 (?<sha>[A-F0-9]{64})$'
$bindings=@{}
foreach($line in $signature){if($line -match $bindingPattern){$bindings[$Matches.path]=@([int64]$Matches.bytes,$Matches.sha)}}
if($bindings.Count -ne 20){throw 'signature binding count mismatch'}
foreach($artifact in $manifest.artifacts){
 if($artifact.path -ceq $signatureRelative){continue}
 if(-not $bindings.ContainsKey([string]$artifact.path)){throw "missing signature binding $($artifact.path)"}
 $binding=$bindings[[string]$artifact.path]
 if($binding[0] -ne [int64]$artifact.bytes -or $binding[1] -cne [string]$artifact.sha256){throw "signature binding mismatch $($artifact.path)"}
}
$v=$manifest.verification
$expected=@{artifact_count=21;signature_binding_count=20;requirements=32;acceptance=5;declaration_fields=24;request_fields=44;receipt_fields=68;evidence_fields=16;comparison_fields=28;primitive_comparisons=26;artifact_fields=3;effect_fields=22;evidence_files=34;explicit_inputs=30;false_authorities=15;selected_ordinal=8;dependency_ordinal=7;effect_count=0}
foreach($key in $expected.Keys){if([int]$v.$key -ne $expected[$key]){throw "verification count mismatch $key"}}
if($v.activation_requested -ne $false -or $v.production_broker_projection_present -ne $false -or $v.execution_authorized -ne $false -or $v.live_broker_authorized -ne $false){throw 'authority promotion admitted'}
if($v.implementation_authorized_after_publication -ne $true){throw 'publication phase missing'}
$specPath=Join-Path $rootPath 'specifications/Cantor_B1_Production_Broker_Projection_Correspondence_P0.sop'
$spec=Get-Content -LiteralPath $specPath
if(@($spec|Where-Object{$_ -match '^  \+ \[PBPC-\d{3}\]'}).Count -ne 32){throw 'spec requirement count mismatch'}
if(@($spec|Where-Object{$_ -match '^  \+ \[PBPC-A\d{2}\]'}).Count -ne 5){throw 'spec acceptance count mismatch'}
$specRaw=$spec -join "`n"
foreach($token in @('declaration24 request44 receipt68 evidence16 comparison28 primitive26 artifact3 effect22 evidence34 explicit30 statuses2 classes2 false15','requires_private_permit=true','activation_requested=false','no dynamic consumer or endpoint','provider_unavailable zero trials')){if(-not $specRaw.Contains($token)){throw "spec token missing $token"}}
$sourcePath=Join-Path $rootPath 'source_documents/2026-09-07_b1_production_broker_projection_correspondence_p0/Derived_B1_Production_Broker_Projection_Correspondence_P0_Source.sop'
$sourceHash=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
if((Get-Item $sourcePath).Length -ne 16553 -or $sourceHash -cne 'BD8140A77CAE809A1E9E0C4FE35C51973174D8E54EDD27B6D92FCE6BCE00A47B'){throw 'source drift'}
"cantor_b1_production_broker_projection_correspondence_p0_formation_verified=true artifacts=21 signature_bindings=20 requirements=32 acceptance=5 declaration=24 request=44 receipt=68 comparison=28 primitives=26 evidence_files=34 explicit_inputs=30 selected=8 dependency=7 false_authorities=15 effects=0"
