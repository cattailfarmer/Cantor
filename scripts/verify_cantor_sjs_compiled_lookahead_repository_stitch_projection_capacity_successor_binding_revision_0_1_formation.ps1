[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $root 'experiments/sjs_compiled_lookahead_repository_stitch_projection_capacity_successor_binding_revision_0_1/formation_evidence_manifest.json'
$specPath = Join-Path $root 'specifications/Cantor_SJS_Compiled_Lookahead_Repository_Stitch_Projection_Capacity_Successor_Binding_Revision_0_1.sop'
$rspSpecPath = Join-Path $root 'specifications/Cantor_SJS_Compiled_Lookahead_Repository_Stitch_Projection_P0.sop'
$signaturePath = Join-Path $root 'narrative/registries/Cantor_SJS_Compiled_Lookahead_Repository_Stitch_Projection_Capacity_Successor_Binding_Revision_0_1_Satisfaction_Signature.sop'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -ne 'cantor-sjs-compiled-lookahead-repository-stitch-projection-capacity-successor-binding-revision-0-1-formation-evidence/0.1' -or
    $manifest.manifest_uuid -ne 'b23d48f0-8fb7-48d4-96e8-bf5a1e1f88f2' -or
    $manifest.canonical_uuid -ne 'bd6411fc-4854-4996-b1af-4e94c3abe567' -or
    $manifest.signature_uuid -ne '5fc266a1-ee01-43ad-a6ae-51779faa5b5b' -or
    $manifest.source_snapshot_uuid -ne '0a138e47-8333-455f-8831-f306ef252d2f' -or
    $manifest.source_commit -ne '970cc3a8b1d75913c1d8ce15af33b968506d0a1a') { throw 'formation identity differs' }
$artifacts = @($manifest.artifacts)
if ($manifest.file_ref_count -ne 24 -or $artifacts.Count -ne 24) { throw 'artifact count differs' }
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
$predecessors = @($manifest.predecessor_bindings)
if ($predecessors.Count -ne 4) { throw 'predecessor binding count differs' }
foreach ($artifact in $predecessors) {
    $relative = [string]$artifact.path
    $absolute = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) { throw "missing predecessor $relative" }
    $item = Get-Item -LiteralPath $absolute
    $hash = (Get-FileHash -LiteralPath $absolute -Algorithm SHA256).Hash
    if ($item.Length -ne [int64]$artifact.bytes -or $hash -ne [string]$artifact.sha256) { throw "predecessor drift $relative" }
}
$signature = Get-Content -LiteralPath $signaturePath -Raw
$bindings = [regex]::Matches($signature, '(?m)^  \+ \[artifact_binding\] (.+) SHA256 ([A-F0-9]{64})$')
if ($bindings.Count -ne 23) { throw 'signature binding count differs' }
foreach ($binding in $bindings) {
    $relative = $binding.Groups[1].Value
    if (-not $seen.ContainsKey($relative)) { throw "unmanifested binding $relative" }
    if ((Get-FileHash -LiteralPath (Join-Path $root $relative) -Algorithm SHA256).Hash -ne $binding.Groups[2].Value) { throw "binding drift $relative" }
}
$spec = Get-Content -LiteralPath $specPath -Raw
if (([regex]::Matches($spec, '\[RSB-\d{3}\]').Value | Sort-Object -Unique).Count -ne 16 -or
    ([regex]::Matches($spec, '\[RSB-A\d{2}\]').Value | Sort-Object -Unique).Count -ne 5) { throw 'requirement count differs' }
$rspSpec = Get-Content -LiteralPath $rspSpecPath -Raw
if ($rspSpec -notmatch '\[RSP-007\].*one through sixteen selected candidates' -or
    $spec -notmatch '\[RSB-003\].*one through eight selected candidates' -or
    $spec -notmatch 'candidate-pool capacity remains one through sixteen') { throw 'supersession text differs' }
$commitSet = @(
    $manifest.source_commit,
    $manifest.rsp_formation_commit,
    $manifest.rsp_formation_publication_commit,
    $manifest.capacity_implementation_commit,
    $manifest.capacity_publication_commit,
    $manifest.integrated_publication_commit
)
foreach ($commit in $commitSet) {
    & git -C $root merge-base --is-ancestor ([string]$commit) HEAD
    if ($LASTEXITCODE -ne 0) { throw "commit is not an ancestor $commit" }
}
$v = $manifest.verification
if ($v.formation_artifact_count -ne 24 -or $v.signature_bound_artifact_count -ne 23 -or
    $v.predecessor_binding_count -ne 4 -or $v.requirement_count -ne 16 -or
    $v.acceptance_gate_count -ne 5 -or $v.original_rsp_selected_maximum -ne 16 -or
    $v.candidate_pool_maximum -ne 16 -or $v.successor_selected_maximum -ne 8 -or
    $v.stitch_maximum -ne 8 -or $v.maximum_projected_bytes -ne 8192 -or
    $v.fixture_upstream_account_count -ne 8 -or $v.fixture_selected_count -ne 3 -or
    $v.fixture_rejected_count -ne 5 -or $v.refused_selected_count -ne 9 -or
    $v.superseded_requirement_count -ne 1 -or -not $v.implementation_authorized_after_publication -or
    $v.rsp_resume_authorized_before_publication -or $v.execution_authorized -or
    $v.formation_effect_count -ne 0) { throw 'verification account differs' }
Write-Output 'rsp_capacity_successor_binding_revision_0_1_formation_passed artifacts=24 bindings=23 predecessors=4 requirements=16 acceptance=5 original_selected_max=16 pool_max=16 successor_selected_max=8 stitch_max=8 projected_bytes=8192 fixture_selected=3 refused_selected=9 superseded=1 implementation_after_publication=true resume_before_publication=false execution_authorized=false formation_effects=0'
