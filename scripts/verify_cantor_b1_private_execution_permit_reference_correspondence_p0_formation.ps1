param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert-True([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Assert-Equal($Actual,$Expected,[string]$Message){if($Actual -cne $Expected){throw "$Message expected=$Expected actual=$Actual"}}
$manifestPath=Join-Path $Root 'experiments/b1_private_execution_permit_reference_correspondence_p0/formation_evidence_manifest.json'
Assert-True (Test-Path -LiteralPath $manifestPath -PathType Leaf) 'formation manifest missing'
$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
Assert-Equal $manifest.profile 'cantor-b1-private-execution-permit-reference-correspondence-formation-evidence/0.1' 'profile'
Assert-Equal $manifest.source_snapshot_uuid 'cdbd323b-c260-415e-9473-d32604242e54' 'snapshot'
Assert-Equal $manifest.canonical_uuid '35543ac8-934f-4e0d-9549-8930f0af7e92' 'canonical'
Assert-Equal $manifest.signature_uuid '31d86973-d52b-4c8d-9711-b36ed85f4f18' 'signature'
Assert-Equal ([int]$manifest.file_ref_count) 21 'artifact count'
Assert-Equal ([int]$manifest.artifacts.Count) 21 'artifact list'
foreach($artifact in $manifest.artifacts){$path=Join-Path $Root ([string]$artifact.path);Assert-True (Test-Path -LiteralPath $path -PathType Leaf) ('missing '+$artifact.path);Assert-Equal ([int64](Get-Item -LiteralPath $path).Length) ([int64]$artifact.bytes) ('bytes '+$artifact.path);Assert-Equal (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash ([string]$artifact.sha256) ('hash '+$artifact.path)}
$sourcePath=Join-Path $Root 'source_documents/2026-09-04_b1_private_execution_permit_reference_correspondence_p0/Derived_B1_Private_Execution_Permit_Reference_Correspondence_P0_Source.sop'
Assert-Equal ([int64](Get-Item -LiteralPath $sourcePath).Length) 15829 'source bytes'
Assert-Equal (Get-FileHash -Algorithm SHA256 -LiteralPath $sourcePath).Hash '24162BB322DDA9CE5D376D7DBE9F592272EF2D9E51FA8EE1F3B49D0D73F20A06' 'source hash'
$spec=Get-Content -LiteralPath (Join-Path $Root 'specifications/Cantor_B1_Private_Execution_Permit_Reference_Correspondence_P0.sop') -Raw
$requirements=@([regex]::Matches($spec,'(?m)^  \+ \[(PERC-[0-9]{3})\] '))
$acceptance=@([regex]::Matches($spec,'(?m)^  \+ \[(PERC-A[0-9]{2})\] '))
Assert-Equal $requirements.Count 32 'requirements'
Assert-Equal $acceptance.Count 5 'acceptance'
$data=Get-Content -LiteralPath (Join-Path $Root 'narrative/research/Cantor_B1_Private_Execution_Permit_Reference_Correspondence_P0_Data_Design_2026-09-04.sop') -Raw
foreach($shape in @(@('envelope',16),@('request',34),@('comparison',19),@('receipt',63),@('manifest',16),@('effect',22))){$count=@([regex]::Matches($data,('(?m)^  \+ \['+$shape[0]+'\.[^\]]+\] ordinal='))).Count;Assert-Equal $count ([int]$shape[1]) ($shape[0]+' fields')}
Assert-Equal @([regex]::Matches($data,'(?m)^  \+ \[reason\.[^\]]+\] ordinal=')).Count 17 'reasons'
Assert-Equal @([regex]::Matches($data,'(?m)^  \+ \[evidence\.[^\]]+\] ordinal=')).Count 30 'evidence'
$signature=Get-Content -LiteralPath (Join-Path $Root 'narrative/registries/Cantor_B1_Private_Execution_Permit_Reference_Correspondence_P0_Satisfaction_Signature.sop') -Raw
Assert-True ($signature -match 'ad10f10f-d506-48ef-a805-f8b0a133766c') 'protocol'
Assert-True ($signature -match '(?m)^  \+ \[implementation_authorized\] true$') 'implementation authorization'
Assert-True ($signature -match '(?m)^  \+ \[private_execution_permit_present\] false$') 'permit false'
Assert-True ($signature -match '(?m)^  \+ \[execution_authorized\] false$') 'execution false'
Assert-Equal ([int]$manifest.verification.requirement_count) 32 'manifest requirements'
Assert-Equal ([int]$manifest.verification.acceptance_gate_count) 5 'manifest acceptance'
Assert-Equal ([int]$manifest.verification.selected_coordinate) 7 'selected'
Assert-Equal ([int]$manifest.verification.dependency_coordinate) 6 'dependency'
Assert-Equal ([int]$manifest.verification.global_false_authority_field_count) 18 'false fields'
Assert-Equal ([int]$manifest.verification.formation_effect_count) 0 'effects'
Assert-True (-not [bool]$manifest.verification.private_execution_permit_present) 'permit promoted'
Assert-True (-not [bool]$manifest.verification.execution_authorized) 'execution promoted'
'cantor_b1_private_execution_permit_reference_correspondence_p0_formation_verified=true artifacts=21 signature_bindings=20 requirements=32 acceptance=5 evidence_files=30 explicit_inputs=27 selected=7 dependency=6 false_authorities=18 effects=0'
