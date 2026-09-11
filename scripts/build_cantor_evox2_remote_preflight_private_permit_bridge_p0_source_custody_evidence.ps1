param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$paths = @(
  'source_documents/2026-09-11_evox2_remote_preflight_private_permit_bridge_p0/EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Source.sop',
  'source_documents/2026-09-11_evox2_remote_preflight_private_permit_bridge_p0/Source_Document_Manifest.sop',
  'proofs/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Source_Custody_Proof.sop',
  'narrative/turns/1789169000000_evox2_remote_preflight_private_permit_bridge_source_custody.sop',
  'narrative/file_changes/1789169000000_evox2_remote_preflight_private_permit_bridge_source_custody.sop',
  'narrative/change_sets/787068b2-e2d6-4536-a65b-e255331d7c6c.sop',
  'plans/Cantor_EVO_X2_Scratch_Build_Executor_P0_Plan.sop',
  'narrative/reentry/Cantor_EVO_X2_Scratch_Build_Executor_P0_Reentry.sop',
  'scripts/build_cantor_evox2_remote_preflight_private_permit_bridge_p0_source_custody_evidence.ps1',
  'scripts/verify_cantor_evox2_remote_preflight_private_permit_bridge_p0_source_custody_evidence.ps1'
)
$artifacts=@()
foreach($relative in $paths){$item=Get-Item -LiteralPath (Join-Path $rootPath $relative) -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "bridge source artifact boundary differs: $relative"};$artifacts += [ordered]@{path=$relative;bytes=[int64]$item.Length;sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash}}
$manifest=[ordered]@{
  profile='cantor-evox2-remote-preflight-private-permit-bridge-source-custody-evidence/0.1'
  manifest_uuid='afe8dd4d-a923-4c5d-8889-a997a7bba928'
  source_uuid='a28dc152-1260-4cfa-a8e8-6379f087d7a1'
  source_snapshot_uuid='750fbbb5-f72f-4816-882f-d8b0ebf1acc7'
  predecessor_bookend='80f2ef9f6eed3c797b911ba3c7f45e8d28130841'
  artifacts=$artifacts
  verification=[ordered]@{artifact_count=10;source_bytes=3892;permit_constructors=0;runner_invocations=0;process_spawns=0;provider_requests=0;remote_calls=0;effects=0;implementation_authorized=$false;live_initiation_authorized=$false}
}
$output=Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_source_custody_evidence_manifest.json'
[IO.File]::WriteAllText($output,(($manifest|ConvertTo-Json -Depth 20 -Compress)),[Text.UTF8Encoding]::new($false))
"cantor_evox2_remote_preflight_private_permit_bridge_source_custody_evidence_built=true artifacts=$($artifacts.Count)"
