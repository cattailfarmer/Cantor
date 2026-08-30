param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path $RepositoryRoot 'experiments/runtime_plus_sop_installation_seed_p0_revision_0_2/formation_evidence_manifest.json'

function Assert-ExactSet([object[]]$Actual, [string[]]$Expected, [string]$Label) {
    $actualStrings = @($Actual | ForEach-Object { [string]$_ })
    if ($actualStrings.Count -ne $Expected.Count -or @($actualStrings | Sort-Object -Unique).Count -ne $Expected.Count) { throw "$Label cardinality or uniqueness mismatch" }
    $delta = Compare-Object ($Expected | Sort-Object) ($actualStrings | Sort-Object)
    if ($delta) { throw "$Label membership mismatch: $($delta | Out-String)" }
}

$raw = [IO.File]::ReadAllText($manifestPath)
$manifest = $raw | ConvertFrom-Json
$top = @('profile','manifest_uuid','canonical_uuid','signature_uuid','invalidated_predecessor_signature_uuid','predecessor_formation_commit','file_ref_count','artifacts','verification','disposition')
Assert-ExactSet @($manifest.PSObject.Properties.Name) $top 'top properties'
if ($manifest.profile -cne 'cantor-runtime-plus-sop-installation-seed-revision-0.2-formation-evidence/0.2' -or
    $manifest.manifest_uuid -cne '3d8d7890-16fa-4115-8aab-58cd8ffe3e81' -or
    $manifest.canonical_uuid -cne '9f2b4613-353f-4cf2-ab66-a3bb3b97feb3' -or
    $manifest.signature_uuid -cne '8f34fed3-755e-4ae5-a129-9a09ad6dd94b' -or
    $manifest.invalidated_predecessor_signature_uuid -cne '923cce08-2c03-4ddf-97f6-d19d03838b4b' -or
    $manifest.predecessor_formation_commit -cne '4ffa063d80a10fe8c63a557d8239d9476a3442ad') { throw 'revision formation identity mismatch' }

$expectedPaths = @(
    'specifications/Cantor_Runtime_Plus_SOP_Installation_Seed_P0.sop',
    'source_documents/2026-08-30_runtime_plus_sop_installation_seed_p0_revision_0_2/Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2_Correction_Source.sop',
    'source_documents/2026-08-30_runtime_plus_sop_installation_seed_p0_revision_0_2/Source_Document_Manifest.sop',
    'narrative/operational_faults/1788104668875_runtime_plus_sop_installation_seed_p0_prerequisite_cardinality_fault.sop',
    'narrative/registries/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Predecessor_Signature_Invalidation.sop',
    'narrative/research/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2_Input_Audit_2026-08-30.sop',
    'specifications/amendments/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2.sop',
    'specifications/exploded/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2.exploded.sop',
    'feature_support/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2_Requirement_Matrix.sop',
    'justifications/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2_Justification.sop',
    'solutions/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2_Solution.sop',
    'plans/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2_Plan.sop',
    'narrative/registries/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2_Artifact_Phase_Lock.sop',
    'proofs/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2_Artifact_Phase_Lock_Proof.sop',
    'feature_support/reviews/CantorRuntimePlusSOPInstallationSeedP0Revision02SignatureReadinessReview.sop',
    'narrative/registries/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2_Satisfaction_Signature.sop'
)
if ([long]$manifest.file_ref_count -ne 16 -or @($manifest.artifacts).Count -ne 16) { throw 'artifact count mismatch' }
Assert-ExactSet @($manifest.artifacts.path) $expectedPaths 'artifact paths'
$identities = @()
foreach ($artifact in @($manifest.artifacts)) {
    Assert-ExactSet @($artifact.PSObject.Properties.Name) @('path','bytes','sha256') "artifact fields $($artifact.path)"
    $relative = [string]$artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)') { throw "nonportable path $relative" }
    $path = Join-Path $RepositoryRoot $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "missing artifact $relative" }
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ([long]$artifact.bytes -ne $item.Length -or ([string]$artifact.sha256).ToUpperInvariant() -cne $hash) { throw "artifact identity mismatch $relative" }
    $identities += "$($item.Length)|$hash"
}

$signature = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'narrative/registries/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2_Satisfaction_Signature.sop'))
$bindings = [regex]::Matches($signature, ' is ([0-9]+) bytes SHA256 ([A-F0-9]{64})')
if ($bindings.Count -ne 15) { throw 'signature binding count mismatch' }
$bindingIdentities = @($bindings | ForEach-Object { "$($_.Groups[1].Value)|$($_.Groups[2].Value)" })
Assert-ExactSet $bindingIdentities @($identities[0..14]) 'signature bindings'

$base = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'specifications/Cantor_Runtime_Plus_SOP_Installation_Seed_P0.sop'))
$baseRequirements = @([regex]::Matches($base, '\[RIS-([0-9]{3})\]') | ForEach-Object { $_.Groups[1].Value })
$baseAcceptance = @([regex]::Matches($base, '\[RIS-A([0-9]{2})\]') | ForEach-Object { $_.Groups[1].Value })
Assert-ExactSet $baseRequirements @(1..30 | ForEach-Object { $_.ToString('000') }) 'base requirements'
Assert-ExactSet $baseAcceptance @(1..5 | ForEach-Object { $_.ToString('00') }) 'base acceptance'

$revision = [IO.File]::ReadAllText((Join-Path $RepositoryRoot 'specifications/amendments/Cantor_Runtime_Plus_SOP_Installation_Seed_P0_Revision_0_2.sop'))
$revisionRequirements = @([regex]::Matches($revision, '\[RIS2-([0-9]{3})\]') | ForEach-Object { $_.Groups[1].Value })
Assert-ExactSet $revisionRequirements @(1..9 | ForEach-Object { $_.ToString('000') }) 'revision requirements'
$expectedKinds = @('host_operating_system','architecture','hardware','driver','firmware','toolchain','transport','network','artifact_reservoir','external_custody','operator_acceptance')
$kindLine = [regex]::Match($revision, '\[RIS2-002\][^\r\n]*exactly ([^\r\n]+)').Groups[1].Value
$kindTokens = @($kindLine -split ' ' | Where-Object { $_ -match '^[a-z_]+$' -and $_ -cne 'and' })
Assert-ExactSet $kindTokens $expectedKinds 'canonical prerequisite kinds'
$profiles = @([regex]::Matches($revision, 'cantor-runtime-closure-[a-z-]+/0\.2') | ForEach-Object { $_.Value } | Sort-Object -Unique)
Assert-ExactSet $profiles @('cantor-runtime-closure-request/0.2','cantor-runtime-closure-envelope/0.2','cantor-runtime-closure-verification/0.2','cantor-runtime-closure-evidence/0.2') 'revision profiles'

$v = $manifest.verification
$props = @('formation_artifact_count','signature_bound_artifact_count','imported_requirement_count','imported_acceptance_count','revision_requirement_count','profile_count','prerequisite_kind_count','prerequisite_instance_maximum','capability_denial_count','predecessor_signature_invalidated','canonical_enumeration_extracted','rust_edit_count_under_predecessor','filesystem_effect_count','process_effect_count','network_effect_count','provider_effect_count','model_effect_count','secret_effect_count','remote_effect_count','hardware_effect_count','foreign_effect_count')
Assert-ExactSet @($v.PSObject.Properties.Name) $props 'verification properties'
$counts = @{formation_artifact_count=16;signature_bound_artifact_count=15;imported_requirement_count=30;imported_acceptance_count=5;revision_requirement_count=9;profile_count=4;prerequisite_kind_count=11;prerequisite_instance_maximum=128;capability_denial_count=25;rust_edit_count_under_predecessor=0}
foreach ($entry in $counts.GetEnumerator()) { if ([long]$v.($entry.Key) -ne [long]$entry.Value) { throw "count mismatch $($entry.Key)" } }
foreach ($name in @('predecessor_signature_invalidated','canonical_enumeration_extracted')) { if ($v.$name -ne $true) { throw "required true flag mismatch $name" } }
foreach ($name in @('filesystem_effect_count','process_effect_count','network_effect_count','provider_effect_count','model_effect_count','secret_effect_count','remote_effect_count','hardware_effect_count','foreign_effect_count')) { if ([long]$v.$name -ne 0) { throw "nonzero effect $name" } }

Write-Output 'runtime_plus_sop_revision_0_2_formation_passed artifacts=16 bindings=15 imported_requirements=30 acceptance=5 revision_requirements=9 profiles=4 prerequisite_kinds=11 prerequisite_max=128 denials=25 rust_edits=0 effects=0'
