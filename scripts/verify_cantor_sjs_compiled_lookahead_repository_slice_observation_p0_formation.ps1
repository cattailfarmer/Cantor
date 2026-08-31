[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$manifestPath = Join-Path $root 'experiments/sjs_compiled_lookahead_repository_slice_observation_p0/formation_evidence_manifest.json'
$signaturePath = Join-Path $root 'narrative/registries/Cantor_SJS_Compiled_Lookahead_Repository_Slice_Observation_P0_Satisfaction_Signature.sop'
$specificationPath = Join-Path $root 'specifications/Cantor_SJS_Compiled_Lookahead_Repository_Slice_Observation_P0.sop'

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Read-Utf8([string]$Path) {
    return [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false))
}

$manifest = Read-Utf8 $manifestPath | ConvertFrom-Json
Assert-Exact ($manifest.profile -ceq 'cantor-sjs-compiled-lookahead-repository-slice-observation-p0-formation-evidence/0.1') 'manifest profile differs'
Assert-Exact ($manifest.manifest_uuid -ceq '95fae985-ea3f-4ad0-9623-5d18d360e719') 'manifest UUID differs'
Assert-Exact ($manifest.canonical_uuid -ceq 'f1fd1689-f290-4be6-ad82-e36d58103e1b') 'canonical UUID differs'
Assert-Exact ($manifest.signature_uuid -ceq '7966d8e4-4944-4547-ae12-cebbc5f80383') 'signature UUID differs'
Assert-Exact ($manifest.source_snapshot_uuid -ceq 'e4ca7100-5a6f-4276-8797-e5e79395720c') 'source UUID differs'
Assert-Exact ($manifest.parent_extraction_canonical_uuid -ceq '3359fdaf-f4bf-44f0-9892-3f8d8d5e027f') 'parent UUID differs'
Assert-Exact ([int]$manifest.file_ref_count -eq 19 -and @($manifest.artifacts).Count -eq 19) 'artifact count differs'

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
Assert-Exact ($bindings.Count -eq 18) 'signature binding count differs'
foreach ($binding in $bindings) {
    $relative = $binding.Groups[1].Value
    Assert-Exact ($artifactPaths.ContainsKey($relative)) "signature artifact absent from manifest $relative"
    $hash = (Get-FileHash -LiteralPath (Join-Path $root $relative) -Algorithm SHA256).Hash
    Assert-Exact ($binding.Groups[2].Value -ceq $hash) "signature binding differs $relative"
}

$specification = Read-Utf8 $specificationPath
$requirements = @([regex]::Matches($specification, '(?m)^\s*\+ \[RSO-(\d{3})\]'))
$acceptance = @([regex]::Matches($specification, '(?m)^\s*\+ \[RSO-A(\d{2})\]'))
Assert-Exact ($requirements.Count -eq 32) 'requirement count differs'
Assert-Exact ($acceptance.Count -eq 5) 'acceptance count differs'
Assert-Exact ((@($requirements | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)).Count -eq 32) 'requirement identity differs'
Assert-Exact ((@($acceptance | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)).Count -eq 5) 'acceptance identity differs'

foreach ($profile in @(
    'cantor-sjs-lookahead-repository-slice-observation-request/0.1',
    'cantor-sjs-lookahead-repository-slice-observation-receipt/0.1',
    'cantor-sjs-lookahead-repository-slice-observation-verification/0.1',
    'cantor-sjs-lookahead-repository-slice-observation-evidence/0.1'
)) { Assert-Exact ($specification.Contains($profile)) "profile absent $profile" }
foreach ($inputClass in @('disposable_local_git_fixture', 'pinned_local_commit_tree')) {
    Assert-Exact ($specification.Contains($inputClass)) "input class absent $inputClass"
}
foreach ($mode in @('100644', '100755')) { Assert-Exact ($specification.Contains($mode)) "ordinary mode absent $mode" }

$v = $manifest.verification
Assert-Exact ([int]$v.formation_artifact_count -eq 19 -and [int]$v.signature_bound_artifact_count -eq 18) 'formation account differs'
Assert-Exact ([int]$v.requirement_count -eq 32 -and [int]$v.acceptance_gate_count -eq 5) 'requirement account differs'
Assert-Exact ([int]$v.profile_count -eq 4 -and [int]$v.input_class_count -eq 2 -and [int]$v.ordinary_blob_mode_count -eq 2) 'type account differs'
Assert-Exact ([int]$v.maximum_record_count -eq 16 -and [int]$v.maximum_obligation_count -eq 64 -and [int]$v.maximum_coverage_edge_count -eq 256 -and [int]$v.maximum_git_command_count -eq 32 -and [int]$v.maximum_machine_form_bytes -eq 1048576) 'bound account differs'
Assert-Exact ([int]$v.fixture_record_count -eq 8 -and [int]$v.fixture_obligation_count -eq 6 -and [int]$v.fixture_coverage_edge_count -eq 12 -and [int]$v.fixture_downstream_subset_count -eq 92 -and [int]$v.fixture_selected_count -eq 3 -and [int]$v.fixture_rejected_count -eq 5 -and [int]$v.fixture_dominated_count -eq 1 -and [int]$v.fixture_uncovered_count -eq 0) 'fixture account differs'
Assert-Exact ([int]$v.current_cantor_observation_count -eq 0 -and [bool]$v.implementation_authorized -and -not [bool]$v.current_cantor_observation_authorized -and [int]$v.formation_effect_count -eq 0) 'authority account differs'

Write-Output 'sjs_compiled_lookahead_repository_slice_observation_formation_passed artifacts=19 bindings=18 requirements=32 acceptance=5 profiles=4 inputs=2 ordinary_modes=2 records_max=16 obligations_max=64 edges_max=256 commands_max=32 bytes_max=1048576 fixture=8_records_6_obligations_12_edges_92_subsets_selected3_rejected5_dominated1_uncovered0 current_cantor_observations=0 implementation_authorized=true current_cantor_observation_authorized=false formation_effects=0'
