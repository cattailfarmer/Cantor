[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$manifestPath = Join-Path $root 'experiments/sjs_compiled_lookahead_repository_stitch_projection_p0/formation_evidence_manifest.json'
$signaturePath = Join-Path $root 'narrative/registries/Cantor_SJS_Compiled_Lookahead_Repository_Stitch_Projection_P0_Satisfaction_Signature.sop'
$specificationPath = Join-Path $root 'specifications/Cantor_SJS_Compiled_Lookahead_Repository_Stitch_Projection_P0.sop'

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Read-Utf8([string]$Path) {
    return [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false))
}

$manifest = Read-Utf8 $manifestPath | ConvertFrom-Json
Assert-Exact ($manifest.profile -ceq 'cantor-sjs-compiled-lookahead-repository-stitch-projection-p0-formation-evidence/0.1') 'manifest profile differs'
Assert-Exact ($manifest.manifest_uuid -ceq 'c3beeaca-1e94-48d4-96f1-11ffd657c545') 'manifest UUID differs'
Assert-Exact ($manifest.canonical_uuid -ceq 'fc3a2e9e-1fc5-4b04-a867-431c2ab0584f') 'canonical UUID differs'
Assert-Exact ($manifest.signature_uuid -ceq '0359eae5-48cc-4f84-95ee-a5c96a3cfba8') 'signature UUID differs'
Assert-Exact ($manifest.source_snapshot_uuid -ceq '2d9f052d-52d5-4a82-be77-2c32ffaecfbc') 'source UUID differs'
Assert-Exact ($manifest.parent_observation_canonical_uuid -ceq 'f1fd1689-f290-4be6-ad82-e36d58103e1b') 'parent UUID differs'
Assert-Exact ($manifest.stitch_canonical_uuid -ceq '5b57d004-0a43-4d89-9c5a-6dc671a2a05a') 'stitch UUID differs'
Assert-Exact ($manifest.source_commit -ceq '30c23f496f68ce39d705feefb5778d0c75bb1900') 'source commit differs'
Assert-Exact ([int]$manifest.file_ref_count -eq 23 -and @($manifest.artifacts).Count -eq 23) 'artifact count differs'

$artifactPaths = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string]$artifact.path
    Assert-Exact (-not $artifactPaths.ContainsKey($relative)) "duplicate artifact $relative"
    $artifactPaths[$relative] = $true
    $full = Join-Path $root $relative
    Assert-Exact (Test-Path -LiteralPath $full -PathType Leaf) "artifact absent $relative"
    $item = Get-Item -LiteralPath $full
    Assert-Exact ([long]$artifact.bytes -eq $item.Length) "artifact bytes differ $relative"
    $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
    Assert-Exact ([string]$artifact.sha256 -ceq $hash) "artifact hash differs $relative"
}

$signature = Read-Utf8 $signaturePath
$bindings = @([regex]::Matches($signature, '(?m)^\s*\+ \[artifact_binding\] (\S+) SHA256 ([0-9A-F]{64})\s*$'))
Assert-Exact ($bindings.Count -eq 22) 'signature binding count differs'
foreach ($binding in $bindings) {
    $relative = $binding.Groups[1].Value
    Assert-Exact ($artifactPaths.ContainsKey($relative)) "signature artifact absent from manifest $relative"
    $hash = (Get-FileHash -LiteralPath (Join-Path $root $relative) -Algorithm SHA256).Hash
    Assert-Exact ($binding.Groups[2].Value -ceq $hash) "signature binding differs $relative"
}

$specification = Read-Utf8 $specificationPath
$requirements = @([regex]::Matches($specification, '(?m)^\s*\+ \[RSP-(\d{3})\]'))
$acceptance = @([regex]::Matches($specification, '(?m)^\s*\+ \[RSP-A(\d{2})\]'))
Assert-Exact ($requirements.Count -eq 32) 'requirement count differs'
Assert-Exact ($acceptance.Count -eq 5) 'acceptance count differs'
Assert-Exact ((@($requirements | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)).Count -eq 32) 'requirement identity differs'
Assert-Exact ((@($acceptance | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)).Count -eq 5) 'acceptance identity differs'

foreach ($profile in @(
    'cantor-sjs-lookahead-repository-stitch-projection-request/0.1',
    'cantor-sjs-lookahead-repository-stitch-projection-envelope/0.1',
    'cantor-sjs-lookahead-repository-stitch-projection-verification/0.1',
    'cantor-sjs-lookahead-repository-stitch-projection-evidence/0.1'
)) { Assert-Exact ($specification.Contains($profile)) "profile absent $profile" }
foreach ($inputClass in @('synthetic_provider_free_fixture', 'verified_repository_selection')) {
    Assert-Exact ($specification.Contains($inputClass)) "input class absent $inputClass"
}

$v = $manifest.verification
Assert-Exact ([int]$v.formation_artifact_count -eq 23 -and [int]$v.signature_bound_artifact_count -eq 22) 'formation account differs'
Assert-Exact ([int]$v.requirement_count -eq 32 -and [int]$v.acceptance_gate_count -eq 5) 'requirement account differs'
Assert-Exact ([int]$v.profile_count -eq 4 -and [int]$v.input_class_count -eq 2) 'type account differs'
Assert-Exact ([int]$v.maximum_selected_count -eq 16 -and [int]$v.maximum_machine_form_bytes -eq 1048576 -and [int]$v.maximum_evidence_bytes -eq 8388608) 'bound account differs'
Assert-Exact ([int]$v.fixture_upstream_account_count -eq 8 -and [int]$v.fixture_selected_count -eq 3 -and [int]$v.fixture_rejected_count -eq 5 -and [int]$v.fixture_dominated_count -eq 1 -and [int]$v.fixture_uncovered_count -eq 0) 'upstream fixture account differs'
Assert-Exact ([int]$v.fixture_stitch_count -eq 3 -and [int]$v.fixture_hint_count -eq 3 -and [int]$v.fixture_source_binding_count -eq 3 -and [int]$v.fixture_observation_count -eq 3 -and [int]$v.fixture_coordinate_count -eq 1 -and [int]$v.fixture_projection_count -eq 1) 'projection fixture account differs'
Assert-Exact ([int]$v.current_repository_contact_count -eq 0 -and [int]$v.current_provider_contact_count -eq 0 -and [bool]$v.implementation_authorized -and -not [bool]$v.execution_authorized -and [int]$v.formation_effect_count -eq 0) 'authority account differs'

Write-Output 'sjs_compiled_lookahead_repository_stitch_projection_formation_passed artifacts=23 bindings=22 requirements=32 acceptance=5 profiles=4 inputs=2 selected_max=16 machine_bytes_max=1048576 evidence_bytes_max=8388608 fixture=8_accounts_selected3_rejected5_dominated1_uncovered0_stitches3_hints3_sources3_observations3_coordinates1_projections1 current_repository_contacts=0 current_provider_contacts=0 implementation_authorized=true execution_authorized=false formation_effects=0'
