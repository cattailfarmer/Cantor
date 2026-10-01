param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
& (Join-Path $PSScriptRoot 'verify_cantor_inspection_runtime_seed_p0_formation.ps1') | Out-Null
$signature=Get-Content -Raw -LiteralPath (Join-Path $root 'narrative/registries/Cantor_Inspection_Seed_Local_Link_Refinement_P0_Satisfaction_Signature.sop')
foreach($identity in @('@ [signature_uuid] 5ef0374a-67b5-4972-87de-7508c9f1bb08','@ [specification_uuid] 9b6b789d-f0b4-478b-a1d5-af979e6ee42b','@ [source_snapshot_uuid] fc972e12-3d1c-4ba9-a50e-abaeb0c9103f','@ [satisfaction_signature_protocol_uuid] ad10f10f-d506-48ef-a805-f8b0a133766c')){if($signature -notmatch [regex]::Escape($identity)){throw 'link_refinement_identity'}}
$expected=@('source_documents/2026-10-01_cantor_inspection_seed_link_refinement/Observed_Local_Link_Metadata_Source.sop','specifications/Cantor_Inspection_Seed_Local_Link_Refinement_P0.sop','justifications/Cantor_Inspection_Seed_Local_Link_Refinement_P0_Justification.sop','plans/Cantor_Inspection_Seed_Local_Link_Refinement_P0_Plan.sop','solutions/Cantor_Inspection_Seed_Local_Link_Refinement_P0_Solution.sop','feature_support/Cantor_Inspection_Seed_Local_Link_Refinement_P0_Requirement_Matrix.sop','proofs/Cantor_Inspection_Seed_Local_Link_Refinement_P0_Artifact_Phase_Lock_Proof.sop','scripts/verify_cantor_inspection_seed_link_refinement_formation.ps1','narrative/registries/Cantor_Inspection_Runtime_Seed_P0_Satisfaction_Signature.sop','specifications/Cantor_Inspection_Runtime_Seed_P0.sop')
$bindings=[regex]::Matches($signature,'(?m)^  \+ \[artifact_binding\] (\S+) bytes([0-9]+) SHA256 ([0-9A-F]{64})$')
if($bindings.Count -ne 10){throw 'link_refinement_count'}
$seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach($binding in $bindings){$relative=$binding.Groups[1].Value;if($relative -cnotin $expected -or -not $seen.Add($relative)){throw 'link_refinement_membership'};$file=Get-Item -LiteralPath (Join-Path $root $relative);if($file.Length -ne [int64]$binding.Groups[2].Value -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne $binding.Groups[3].Value){throw 'link_refinement_artifact'}}
Write-Output 'cantor_seed_link_refinement_formation_verified=true bindings=10 parent_bindings=14 implementation_claims=0'
