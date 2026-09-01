[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $root 'experiments/sjs_compiled_lookahead_stitch_capacity_revision_0_2/formation_evidence_manifest.json'
$specPath = Join-Path $root 'specifications/Cantor_SJS_Compiled_Lookahead_Stitch_Capacity_Revision_0_2.sop'
$signaturePath = Join-Path $root 'narrative/registries/Cantor_SJS_Compiled_Lookahead_Stitch_Capacity_Revision_0_2_Satisfaction_Signature.sop'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -ne 'cantor-sjs-compiled-lookahead-stitch-capacity-revision-0-2-formation-evidence/0.1' -or
    $manifest.manifest_uuid -ne 'eb486b03-1357-4190-a585-86fd28467414' -or
    $manifest.canonical_uuid -ne 'd439964f-e7a1-4557-acd0-14930620dbe0' -or
    $manifest.signature_uuid -ne '8a939d80-572c-43a3-80a5-6212c2431833' -or
    $manifest.source_snapshot_uuid -ne '13986b54-3817-4c3c-9c84-472f188f9b8d' -or
    $manifest.source_commit -ne '6812f745ee8b05961adab7bc94ed3fc85840e696') { throw 'formation identity differs' }
$artifacts = @($manifest.artifacts)
if ($manifest.file_ref_count -ne 22 -or $artifacts.Count -ne 22) { throw 'artifact count differs' }
$seen = @{}
foreach ($artifact in $artifacts) {
    $relative = [string]$artifact.path
    if ($seen.ContainsKey($relative)) { throw "duplicate artifact $relative" }
    $seen[$relative] = $true
    $absolute = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) { throw "missing artifact $relative" }
    $item = Get-Item -LiteralPath $absolute
    $hash = (Get-FileHash -LiteralPath $absolute -Algorithm SHA256).Hash
    if ($item.Length -ne [int64]$artifact.bytes -or $hash -ne [string]$artifact.sha256) { throw "artifact drift $relative" }
}
$signature = Get-Content -LiteralPath $signaturePath -Raw
$bindings = [regex]::Matches($signature, '(?m)^  \+ \[artifact_binding\] (.+) SHA256 ([A-F0-9]{64})$')
if ($bindings.Count -ne 21) { throw 'signature binding count differs' }
foreach ($binding in $bindings) {
    $relative = $binding.Groups[1].Value
    if (-not $seen.ContainsKey($relative)) { throw "unmanifested binding $relative" }
    if ((Get-FileHash -LiteralPath (Join-Path $root $relative) -Algorithm SHA256).Hash -ne $binding.Groups[2].Value) { throw "binding drift $relative" }
}
$spec = Get-Content -LiteralPath $specPath -Raw
if (([regex]::Matches($spec, '\[CSR2-\d{3}\]').Value | Sort-Object -Unique).Count -ne 17 -or
    ([regex]::Matches($spec, '\[CSR2-A\d{2}\]').Value | Sort-Object -Unique).Count -ne 5) { throw 'requirement count differs' }
$v = $manifest.verification
if ($v.formation_artifact_count -ne 22 -or $v.signature_bound_artifact_count -ne 21 -or
    $v.requirement_count -ne 17 -or $v.acceptance_gate_count -ne 5 -or
    $v.old_maximum_stitch_count -ne 2 -or $v.new_maximum_stitch_count -ne 8 -or
    $v.selector_maximum_selected_count -ne 8 -or $v.maximum_projected_bytes -ne 8192 -or
    $v.minimal_declaration_bytes -ne 603 -or $v.three_stitch_projected_bytes -ne 1809 -or
    $v.eight_stitch_projected_bytes -ne 4824 -or $v.refused_stitch_count -ne 9 -or
    $v.production_semantic_line_change_count -ne 1 -or -not $v.implementation_authorized -or
    $v.rsp_resume_authorized -or $v.execution_authorized -or $v.formation_effect_count -ne 0) { throw 'verification account differs' }
Write-Output 'sjs_compiled_lookahead_stitch_capacity_revision_0_2_formation_passed artifacts=22 bindings=21 requirements=17 acceptance=5 old_max=2 new_max=8 selector_max=8 projected_bytes=8192 minimal=603 three=1809 eight=4824 refused=9 production_semantic_lines=1 implementation_authorized=true rsp_resume_authorized=false execution_authorized=false formation_effects=0'
