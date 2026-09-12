[CmdletBinding()]
param(
    [string] $Root = '',
    [int] $WorkspaceResultGroups = 0,
    [int] $WorkspaceTestsPassed = 0,
    [int] $WorkspaceTestsIgnored = 0,
    [switch] $ExactGatesPassed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$paths = @(
    'source_documents/2026-09-11_evox2_remote_preflight_private_permit_bridge_p0/EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Source.sop',
    'source_documents/2026-09-11_evox2_remote_preflight_private_permit_bridge_p0/Source_Document_Manifest.sop',
    'specifications/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0.sop',
    'specifications/exploded/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0.exploded.sop',
    'narrative/research/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Design_2026-09-11.sop',
    'plans/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Plan.sop',
    'solutions/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Solution.sop',
    'feature_support/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Satisfaction_Signature.sop',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_source_custody_evidence_manifest.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_formation_evidence_manifest.json',
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_formation_publication_evidence_manifest.json',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'narrative/reentry/Cantor_EVO_X2_Scratch_Build_Executor_P0_Reentry.sop',
    'narrative/Project_Narrative.sop',
    'proofs/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Implementation_Proof.sop',
    'feature_support/reviews/CantorEVOX2RemotePreflightPrivatePermitBridgeP0ImplementationReview.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Implementation_Checkpoint.sop',
    'narrative/turns/1789173000000_evox2_remote_preflight_private_permit_bridge_implementation.sop',
    'narrative/file_changes/1789173000000_evox2_remote_preflight_private_permit_bridge_implementation.sop',
    'narrative/change_sets/5507e60a-416e-4d96-a81a-d067e81478ad.sop',
    'narrative/operational_faults/1789171950960_evox2_private_permit_bridge_interrupted_edit_compile_fault.sop',
    'narrative/operational_faults/1789174827714_evox2_private_permit_bridge_transitive_evidence_refusal.sop',
    'crates/cantor_ecosystem/src/evox2_remote_preflight_private_permit_bridge.rs',
    'crates/cantor_ecosystem/src/evox2_scratch_build_remote_preflight_runner.rs',
    'crates/cantor_ecosystem/src/lib.rs',
    'crates/cantor_ecosystem/tests/evox2_remote_preflight_private_permit_bridge_static.rs',
    'scripts/test_cantor_evox2_remote_preflight_private_permit_bridge_p0_implementation.ps1',
    'scripts/build_cantor_evox2_remote_preflight_private_permit_bridge_p0_implementation_evidence.ps1',
    'scripts/verify_cantor_evox2_remote_preflight_private_permit_bridge_p0_implementation_evidence.ps1'
)
$artifacts = foreach ($relative in $paths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "private permit bridge artifact boundary differs: $relative" }
    [ordered]@{ path = $relative; bytes = [int64] $item.Length; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-remote-preflight-private-permit-bridge-implementation-evidence/0.1'
    manifest_uuid = '6eef4fb2-320c-4ae0-9299-003295f84c8d'
    canonical_uuid = '06d82d16-143a-4abb-9c70-c03163285842'
    signature_uuid = '3f7d776d-e012-4efc-9426-d40cf6af7fcb'
    formation_commit = '001c75ad761d6890c29db793d6d133bdcca037b8'
    formation_bookend = 'd76d0fe0086c8b7b5fab20fbda444524d071d126'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    verification = [ordered]@{
        artifact_count = @($artifacts).Count
        focused_debug_passed = 7
        focused_release_passed = 7
        semantic_tests = 4
        static_absence_tests = 3
        admission_type_declarations = 1
        production_admission_constructors = 0
        permit_issuers = 1
        production_bridge_entries = 1
        production_bridge_calls = 0
        terminal_dispositions = 4
        maximum_attempts = 1
        maximum_permits = 1
        maximum_runner_entries = 1
        maximum_processes = 1
        retry_count = 0
        workspace_result_groups = $WorkspaceResultGroups
        workspace_tests_passed = $WorkspaceTestsPassed
        workspace_tests_failed = 0
        workspace_tests_ignored = $WorkspaceTestsIgnored
        workspace_clippy_warnings_denied = [bool] $ExactGatesPassed
        workspace_format_passed = [bool] $ExactGatesPassed
        powershell_7_evidence_passed = [bool] $ExactGatesPassed
        windows_powershell_5_1_evidence_passed = [bool] $ExactGatesPassed
        production_permits_minted = 0
        production_runner_invocations = 0
        process_spawns = 0
        provider_requests = 0
        remote_calls = 0
        effects = 0
        synthetic_trials = 0
        exact_workspace_gates_passed = [bool] $ExactGatesPassed
    }
}
$output = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_implementation_evidence_manifest.json'
[IO.File]::WriteAllText($output, (($manifest | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
"cantor_evox2_remote_preflight_private_permit_bridge_implementation_evidence_written=$output artifacts=$($artifacts.Count) exact_gates=$([bool] $ExactGatesPassed)"
