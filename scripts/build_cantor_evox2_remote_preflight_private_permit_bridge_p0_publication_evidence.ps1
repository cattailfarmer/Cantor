param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$rootPath=(Resolve-Path -LiteralPath $Root).Path
$paths=@(
  'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_formation_evidence_manifest.json',
  'proofs/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Formation_Proof.sop',
  'feature_support/reviews/CantorEVOX2RemotePreflightPrivatePermitBridgeP0FormationCompletionReview.sop',
  'narrative/registries/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Formation_Phase_Checkpoint.sop',
  'narrative/turns/1789170200000_evox2_remote_preflight_private_permit_bridge_formation.sop',
  'narrative/file_changes/1789170200000_evox2_remote_preflight_private_permit_bridge_formation.sop',
  'narrative/change_sets/22d7c0bc-f370-4c21-8e49-90f5c113a1bc.sop',
  'narrative/operational_faults/1789169300000_private_permit_bridge_bookend_staging_guard_fault.sop',
  'narrative/operational_faults/1789170081275_private_permit_bridge_mutable_evidence_signature_fault.sop',
  'narrative/operational_faults/1789170571467_private_permit_bridge_ps51_default_root_fault.sop',
  'proofs/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Formation_Publication_Proof.sop',
  'narrative/turns/1789170414997_evox2_remote_preflight_private_permit_bridge_formation_publication.sop',
  'narrative/file_changes/1789170414997_evox2_remote_preflight_private_permit_bridge_formation_publication.sop',
  'narrative/change_sets/4ee2d599-014c-49aa-8c04-1f03f29f6fc0.sop'
)
$artifacts=@();foreach($relative in $paths){$item=Get-Item -LiteralPath (Join-Path $rootPath $relative) -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "publication artifact boundary differs: $relative"};$artifacts += [ordered]@{path=$relative;bytes=[int64]$item.Length;sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash}}
$manifest=[ordered]@{
  profile='cantor-evox2-remote-preflight-private-permit-bridge-formation-publication-evidence/0.1';manifest_uuid='894a0b3c-21a4-4e32-96cc-a82c7fb57bea';canonical_uuid='06d82d16-143a-4abb-9c70-c03163285842';publication_proof_uuid='af0f674b-8ffb-4e7e-b7e6-2ec35765559e';formation_commit='001c75ad761d6890c29db793d6d133bdcca037b8';formation_parent='40b20537cbe8fbd143bb3298ea92ca8b77f46c33';branch='codex/self-hosted-corpus';artifacts=$artifacts
  verification=[ordered]@{artifact_count=14;formation_artifacts=23;formation_bindings=22;requirements=24;acceptance=5;isolated_refusals=15;redigested_refusals=2;powershell7_passed=$true;windows_powershell51_passed=$true;formation_remote_equal=$true;permit_constructors=0;permit_issuances=0;runner_invocations=0;process_spawns=0;provider_requests=0;remote_calls=0;effects=0;live_authority_created=$false;provider_free_implementation_eligible_after_bookend=$true;production_admission_constructor_authorized=$false;live_initiation_authorized=$false}
}
$output=Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_formation_publication_evidence_manifest.json'
[IO.File]::WriteAllText($output,(($manifest|ConvertTo-Json -Depth 20 -Compress)),[Text.UTF8Encoding]::new($false))
"cantor_evox2_remote_preflight_private_permit_bridge_publication_evidence_built=true artifacts=$($artifacts.Count)"
