param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$relativePaths = @(
    'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/formation_evidence_manifest.json',
    'proofs/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Formation_Proof.sop',
    'feature_support/reviews/CantorEVOX2RemotePreflightOneShotActivationCeremonyP0FormationCompletionReview.sop',
    'narrative/registries/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Formation_Phase_Checkpoint.sop',
    'narrative/turns/1789155215176_evox2_remote_preflight_one_shot_activation_ceremony_start.sop',
    'narrative/turns/1789156063959_evox2_remote_preflight_one_shot_activation_ceremony_formation.sop',
    'narrative/file_changes/1789156063959_evox2_remote_preflight_one_shot_activation_ceremony_formation.sop',
    'narrative/change_sets/e9eb8add-c585-4b5b-b52a-e1488a18958e.sop',
    'proofs/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Formation_Publication_Proof.sop',
    'narrative/turns/1789156246016_evox2_remote_preflight_one_shot_activation_ceremony_formation_publication.sop',
    'narrative/file_changes/1789156246016_evox2_remote_preflight_one_shot_activation_ceremony_formation_publication.sop',
    'narrative/change_sets/89ab767a-848b-4b2c-81b2-0129beae9790.sop'
)
$artifacts = @()
foreach ($relative in $relativePaths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "linked artifact $relative" }
    $artifacts += [ordered]@{ path=$relative; bytes=[int64]$item.Length; sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-remote-preflight-one-shot-activation-ceremony-formation-publication-evidence/0.1'
    canonical_uuid = 'd2724a39-56bd-47ae-8787-064a6196dbfb'
    publication_proof_uuid = '9efc0c9a-6703-43a0-8dd7-29b68c9d504c'
    formation_commit = '7b508b67a7b16c091e4dbea512c691b885e33a2f'
    formation_parent = '0674395c78a998ce1c36c714e52bae68d0f83f58'
    artifacts = $artifacts
    verification = [ordered]@{
        artifact_count=12
        powershell7_passed=$true
        windows_powershell51_passed=$true
        formation_artifacts=21
        formation_bindings=20
        isolated_refusals=10
        provider_requests=0
        remote_calls=0
        effects=0
        permits_minted=0
        runner_invocations=0
        live_authority_created=$false
        pure_implementation_authorized_after_bookend=$true
        permit_bridge_authorized=$false
        live_invocation_authorized=$false
    }
}
$output = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/formation_publication_evidence_manifest.json'
$json = $manifest | ConvertTo-Json -Depth 8 -Compress
[IO.File]::WriteAllText($output, $json, [Text.UTF8Encoding]::new($false))
"cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_publication_evidence_built=true artifacts=$($artifacts.Count)"
