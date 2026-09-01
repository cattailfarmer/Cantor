[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repositoryRoot 'experiments/sjs_compiled_lookahead_stitch_capacity_revision_0_1/formation_evidence_manifest.json'
$specificationPath = Join-Path $repositoryRoot 'specifications/Cantor_SJS_Compiled_Lookahead_Stitch_Capacity_Revision_0_1.sop'
$signaturePath = Join-Path $repositoryRoot 'narrative/registries/Cantor_SJS_Compiled_Lookahead_Stitch_Capacity_Revision_0_1_Satisfaction_Signature.sop'

if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'formation evidence manifest is absent'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -ne 'cantor-sjs-compiled-lookahead-stitch-capacity-revision-0-1-formation-evidence/0.1' -or
    $manifest.manifest_uuid -ne 'd060e3e0-09cf-43f8-aa7e-861e0bec0801' -or
    $manifest.canonical_uuid -ne 'ed156338-1ab2-4e33-9fa3-72a24c899f87' -or
    $manifest.signature_uuid -ne '44bfb9a4-d9a9-4b97-9efe-cd9458056e2d' -or
    $manifest.source_snapshot_uuid -ne '47851b21-cc88-4c62-b41f-9eab692ed2e1' -or
    $manifest.parent_stitch_canonical_uuid -ne '5b57d004-0a43-4d89-9c5a-6dc671a2a05a' -or
    $manifest.source_commit -ne 'a7527b538e337ec9799f18ffea18cdbb70431c49') {
    throw 'formation manifest identity differs'
}

$artifacts = @($manifest.artifacts)
if ($manifest.file_ref_count -ne 23 -or $artifacts.Count -ne 23) {
    throw 'formation artifact count differs'
}
$seen = @{}
foreach ($artifact in $artifacts) {
    $relative = [string]$artifact.path
    if ($seen.ContainsKey($relative)) {
        throw "duplicate formation artifact: $relative"
    }
    $seen[$relative] = $true
    $absolute = Join-Path $repositoryRoot $relative
    if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) {
        throw "formation artifact absent: $relative"
    }
    $item = Get-Item -LiteralPath $absolute
    $digest = (Get-FileHash -LiteralPath $absolute -Algorithm SHA256).Hash
    if ($item.Length -ne [int64]$artifact.bytes -or $digest -ne [string]$artifact.sha256) {
        throw "formation artifact bytes or hash differ: $relative"
    }
}

$signatureText = Get-Content -LiteralPath $signaturePath -Raw
$bindingMatches = [regex]::Matches(
    $signatureText,
    '(?m)^  \+ \[artifact_binding\] (.+) SHA256 ([A-F0-9]{64})$'
)
if ($bindingMatches.Count -ne 22) {
    throw 'signature binding count differs'
}
$signatureRelative = 'narrative/registries/Cantor_SJS_Compiled_Lookahead_Stitch_Capacity_Revision_0_1_Satisfaction_Signature.sop'
foreach ($binding in $bindingMatches) {
    $relative = $binding.Groups[1].Value
    $digest = $binding.Groups[2].Value
    if (-not $seen.ContainsKey($relative) -or $relative -eq $signatureRelative) {
        throw "signature binding path differs: $relative"
    }
    $absolute = Join-Path $repositoryRoot $relative
    if ((Get-FileHash -LiteralPath $absolute -Algorithm SHA256).Hash -ne $digest) {
        throw "signature binding digest differs: $relative"
    }
}

$specification = Get-Content -LiteralPath $specificationPath -Raw
$requirements = [regex]::Matches($specification, '\[CSR-\d{3}\]')
$acceptance = [regex]::Matches($specification, '\[CSR-A\d{2}\]')
if (($requirements.Value | Sort-Object -Unique).Count -ne 18 -or
    ($acceptance.Value | Sort-Object -Unique).Count -ne 5) {
    throw 'requirement or acceptance count differs'
}

$verification = $manifest.verification
if ($verification.formation_artifact_count -ne 23 -or
    $verification.signature_bound_artifact_count -ne 22 -or
    $verification.requirement_count -ne 18 -or
    $verification.acceptance_gate_count -ne 5 -or
    $verification.old_maximum_stitch_count -ne 2 -or
    $verification.new_maximum_stitch_count -ne 16 -or
    $verification.maximum_hint_count_per_stitch -ne 8 -or
    $verification.maximum_source_count_per_stitch -ne 8 -or
    $verification.maximum_invalidator_count_per_stitch -ne 8 -or
    $verification.maximum_observation_count -ne 64 -or
    $verification.maximum_coordinate_count -ne 32 -or
    $verification.maximum_projected_bytes -ne 8192 -or
    $verification.legacy_fixture_stitch_count -ne 2 -or
    $verification.integration_fixture_stitch_count -ne 3 -or
    $verification.capacity_fixture_stitch_count -ne 16 -or
    $verification.refused_stitch_count -ne 17 -or
    $verification.production_semantic_line_change_count -ne 1 -or
    -not $verification.implementation_authorized -or
    $verification.rsp_resume_authorized -or
    $verification.execution_authorized -or
    $verification.formation_effect_count -ne 0) {
    throw 'formation verification account differs'
}

Write-Output 'sjs_compiled_lookahead_stitch_capacity_revision_0_1_formation_passed artifacts=23 bindings=22 requirements=18 acceptance=5 old_max=2 new_max=16 hints=8 sources=8 invalidators=8 observations=64 coordinates=32 projected_bytes=8192 legacy=2 integration=3 capacity=16 refused=17 production_semantic_lines=1 implementation_authorized=true rsp_resume_authorized=false execution_authorized=false formation_effects=0'
