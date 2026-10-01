param([switch]$SkipCompletion)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
& (Join-Path $PSScriptRoot 'verify_cantor_inspection_runtime_seed_p0_formation.ps1')
& (Join-Path $PSScriptRoot 'verify_cantor_inspection_seed_link_refinement_formation.ps1')
& (Join-Path $PSScriptRoot 'verify_cantor_semantic_inspection_mcp_adapter_p0_evidence.ps1')
$experiment='experiments/cantor_inspection_runtime_seed_p0'
function Assert-Identity($Artifact) {
    $relative=[string]$Artifact.path
    if([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or [string]$Artifact.sha256 -cnotmatch '^[0-9A-F]{64}$'){throw 'seed_evidence_path'}
    $file=Get-Item -LiteralPath (Join-Path $root $relative)
    if($file.PSIsContainer -or $file.Length -ne [int64]$Artifact.bytes -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne $Artifact.sha256){throw ('seed_evidence_identity:'+ $relative)}
}
function Assert-Members($Artifacts,$Expected) {
    if(@($Artifacts).Count -ne @($Expected).Count){throw 'seed_evidence_count'}
    for($index=0;$index -lt @($Expected).Count;$index++){
        if(@($Artifacts)[$index].path -cne @($Expected)[$index]){throw 'seed_evidence_membership'}
        Assert-Identity @($Artifacts)[$index]
    }
}
$component=Get-Content -Raw -LiteralPath (Join-Path $root "$experiment/inspection_seed_component.json")|ConvertFrom-Json
if($component.profile -cne 'cantor-inspection-runtime-seed/0.1' -or $component.specification_uuid -cne 'e3e7a424-c013-492a-a913-044ea17dc66d' -or $component.formation_bookend -cne '176af3579c18b3983e59c3770b9656c4cafbf06c' -or $component.rust_code_changes -ne 0){throw 'seed_component_identity'}
$componentPaths=@(
    'scripts/lib/Cantor_Inspection_Runtime_Seed_P0_Common.ps1',
    'scripts/build_cantor_inspection_runtime_seed_p0.ps1',
    'scripts/verify_cantor_inspection_runtime_seed_p0.ps1',
    'scripts/test_cantor_inspection_runtime_seed_p0.ps1',
    'scripts/test_cantor_inspection_runtime_seed_p0_native.ps1',
    'scripts/verify_cantor_inspection_runtime_seed_p0_evidence.ps1',
    'fixtures/inspection_runtime_seed_p0/seed.sop',
    'fixtures/inspection_runtime_seed_p0/inspect-seed-request.json',
    'fixtures/inspection_runtime_seed_p0/mcp-tool-arguments.json',
    'docs/INSPECTION_RUNTIME_SEED_P0.md'
)
Assert-Members $component.files $componentPaths
$manifest=Get-Content -Raw -LiteralPath (Join-Path $root "$experiment/implementation_evidence_manifest.json")|ConvertFrom-Json
if($manifest.profile -cne 'cantor-inspection-runtime-seed-evidence/0.1' -or $manifest.specification_uuid -cne 'e3e7a424-c013-492a-a913-044ea17dc66d'){throw 'seed_manifest_identity'}
$expected=@('inspection_seed_component.json','formation_evidence_manifest.json','seed_report.json','adversarial_summary.json','native_replay_summary.json','workspace_debug_summary.json','workspace_release_summary.json','gate_summary.json')|ForEach-Object {"$experiment/$_"}
Assert-Members $manifest.artifacts $expected
$seed=Get-Content -Raw -LiteralPath (Join-Path $root "$experiment/seed_report.json")|ConvertFrom-Json
if($seed.profile -cne 'cantor-inspection-runtime-seed-report/0.1' -or $seed.target -cne 'x86_64-pc-windows-msvc' -or $seed.entry_count -ne 7 -or @($seed.entries).Count -ne 7 -or $seed.archive_bytes -gt 16777216 -or $seed.source_commit -cne '2974d2782898aa0c0c39ba36ebcce079d428af74' -or $seed.formation_commit -cne $component.formation_bookend){throw 'seed_report_coordinates'}
$paths=@('GUIDE.md','bin/cantor-sop-inspect-mcp.exe','bin/cantor-sop-inspect-stdio.exe','examples/inspect-seed-request.json','examples/mcp-tool-arguments.json','seed-manifest.json','sop/seed.sop')
if($seed.rustflags -cne '-C overflow-checks=on -C link-arg=/Brepro' -or $seed.link_refinement_specification_uuid -cne '9b6b789d-f0b4-478b-a1d5-af979e6ee42b' -or $seed.link_refinement_signature_uuid -cne '5ef0374a-67b5-4972-87de-7508c9f1bb08' -or $seed.link_refinement_formation_bookend -cne '5130e4eb12765d73b2c982c71afc72e839280773'){throw 'seed_link_recipe_identity'}
for($index=0;$index -lt 7;$index++){if($seed.entries[$index].path -cne $paths[$index] -or $seed.entries[$index].bytes -gt 8388608){throw 'seed_entry_coordinates'}}
foreach($field in @('runtime_launches','installer_effects','provider_trials','remote_calls')){if($seed.$field -ne 0){throw 'seed_unexpected_effect'}}
$adversarial=Get-Content -Raw -LiteralPath (Join-Path $root "$experiment/adversarial_summary.json")|ConvertFrom-Json
if($adversarial.profile -cne 'cantor-inspection-runtime-seed-adversarial-test/0.1' -or $adversarial.refusal_count -ne 48 -or @($adversarial.refusals).Count -ne 48 -or $adversarial.same_input_generations -ne 2 -or $adversarial.archive_byte_equality -cne $true -or $adversarial.report_byte_equality -cne $true -or $adversarial.inherited_build_environment_normalized -cne $true -or $adversarial.process_build_environment_restored -cne $true -or $adversarial.positive_archive_sha256 -cne $seed.archive_sha256){throw 'seed_adversarial_coordinates'}
$seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
$expectedRefusals=@(
    'existing_output',
    'outside_output',
    'escaping_output',
    'source_bound',
    'request_bound',
    'argument_example_bound',
    'local_signature',
    'local_version',
    'local_encryption_flag',
    'local_descriptor_flag',
    'local_store_method',
    'local_timestamp',
    'local_date',
    'local_crc',
    'local_size',
    'local_extra_field',
    'central_store_method',
    'central_crc',
    'central_comment',
    'central_attributes',
    'central_local_offset',
    'end_split_disk',
    'end_entry_count',
    'end_directory_offset',
    'end_comment',
    'rooted_entry',
    'traversal_entry',
    'nonascii_entry',
    'duplicate_entry',
    'entry_order',
    'archive_trailing_octet',
    'archive_bound',
    'report_bound',
    'raw_duplicate_report_field',
    'trailing_report_json',
    'unknown_field',
    'wrong_source',
    'wrong_formation',
    'wrong_target',
    'wrong_scope',
    'wrong_lock',
    'entry_membership',
    'entry_digest',
    'archive_digest',
    'field_type',
    'field_order',
    'self_consistent_payload_drift:bin/cantor-sop-inspect-mcp.exe',
    'self_consistent_payload_drift:sop/seed.sop'
)
for($index=0;$index -lt $expectedRefusals.Count;$index++) {
    $case=$adversarial.refusals[$index]
    if($case.case -cne $expectedRefusals[$index] -or -not $seen.Add($case.case) -or $case.refused -cne $true -or $case.fault -cnotmatch '^seed_'){throw 'seed_refusal_coordinate'}
}
$native=Get-Content -Raw -LiteralPath (Join-Path $root "$experiment/native_replay_summary.json")|ConvertFrom-Json
if($native.profile -cne 'cantor-inspection-runtime-seed-native-replay/0.1' -or $native.package_archive_sha256 -cne $seed.archive_sha256 -or $native.native_process_trials -ne 2 -or $native.seed_terms -ne 5 -or $native.complete_source_excerpts -ne 5 -or $native.unique_seed_excerpt_ids -ne 5 -or $native.exact_utf8_source_span_checks -ne 5 -or $native.mcp_exact_wire_responses -ne 2 -or $native.unknown_tool_refusals -ne 1 -or $native.malformed_argument_refusals -ne 1 -or $native.after_refusal_recoveries -ne 1 -or $native.whole_exchange_deadline_ms -ne 30000){throw 'seed_native_coordinates'}
foreach($field in @('successful_children_killed','failure_kills','stdio_exit','mcp_exit','stderr_bytes','provider_trials','remote_calls','installed_application_acceptances')){if($native.$field -ne 0){throw 'seed_native_unexpected_effect'}}
$utf8=New-Object Text.UTF8Encoding($false,$true)
$wireBytes=$utf8.GetBytes([string]$native.wire_response_json)
$algorithm=[Security.Cryptography.SHA256]::Create()
try {$wireSha=([BitConverter]::ToString($algorithm.ComputeHash($wireBytes))).Replace('-','')} finally {$algorithm.Dispose()}
if($wireBytes.Length -ne $native.wire_response_bytes -or $wireSha -cne $native.wire_response_sha256 -or @($native.mcp_frames).Count -ne 6){throw 'seed_native_wire_identity'}
$wire=$native.wire_response_json|ConvertFrom-Json
if($wire.profile -cne 'cantor-sop-inspection-wire-response/0.1' -or $wire.status -cne 'succeeded' -or @($wire.result.find.items).Count -ne 5 -or @($wire.result.excerpts).Count -ne 5 -or $wire.result.find.complete -cne $true -or $null -ne $wire.result.find.next){throw 'seed_native_wire_shape'}
$source=$utf8.GetBytes((Get-Content -Raw -LiteralPath (Join-Path $root 'fixtures/inspection_runtime_seed_p0/seed.sop')))
$seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach($excerpt in $wire.result.excerpts) {
    if($excerpt.record_id -cnotin @('seed:frontier','seed:mcp','seed:runtime','seed:stdio','seed:trust') -or -not $seen.Add($excerpt.record_id) -or $excerpt.path -cne 'seed/seed.sop' -or $excerpt.span.start -lt 0 -or $excerpt.span.end -le $excerpt.span.start -or $excerpt.span.end -gt $source.Length){throw 'seed_native_excerpt_span'}
    $span=New-Object byte[] ($excerpt.span.end-$excerpt.span.start);[Array]::Copy($source,$excerpt.span.start,$span,0,$span.Length)
    if($utf8.GetString($span) -cne $excerpt.text){throw 'seed_native_excerpt_identity'}
}
for($index=0;$index -lt 6;$index++) {
    $frame=$native.mcp_frames[$index]|ConvertFrom-Json
    if($frame.id -ne $index+1){throw 'seed_native_frame_coordinate'}
    if($index -in @(2,5)) {
        if($frame.result.isError -cne $false -or $frame.result.structuredContent.wire_response_json -cne $native.wire_response_json -or $frame.result.structuredContent.response_sha256 -cne $wireSha.ToLowerInvariant()){throw 'seed_native_frame_identity'}
    }
    elseif($index -eq 3){if($frame.error.code -ne -32601){throw 'seed_native_unknown_tool'}}
    elseif($index -eq 4){if($frame.result.isError -cne $true -or $frame.result.structuredContent.fault_code -cne 'arguments'){throw 'seed_native_argument_fault'}}
}
foreach($profile in @('debug','release')){
    $workspace=Get-Content -Raw -LiteralPath (Join-Path $root "$experiment/workspace_$($profile)_summary.json")|ConvertFrom-Json
    if($workspace.cargo_profile -cne $profile -or $workspace.result_groups -ne 367 -or $workspace.tests_passed -ne 2117 -or $workspace.tests_failed -ne 0 -or $workspace.tests_ignored -ne 22 -or $workspace.locked -cne $true -or $workspace.offline -cne $true -or $workspace.serialized_test_threads -ne 1){throw 'seed_workspace_coordinates'}
}
$gates=Get-Content -Raw -LiteralPath (Join-Path $root "$experiment/gate_summary.json")|ConvertFrom-Json
if($gates.profile -cne 'cantor-inspection-runtime-seed-tests/0.1' -or $gates.workspace_clippy_warnings_denied -cne $true -or $gates.workspace_format_passed -cne $true -or $gates.powershell_parse_passed -cne $true -or $gates.production_recipe_restored_after_workspace -cne $true -or $gates.retained_candidate_verified_after_workspace -cne $true -or $gates.rust_code_changes -ne 0 -or $gates.cargo_changes -ne 0){throw 'seed_gate_coordinates'}
if(-not $SkipCompletion){
    $signature=Get-Content -Raw -LiteralPath (Join-Path $root 'narrative/registries/Cantor_Inspection_Runtime_Seed_P0_Completion_Satisfaction_Signature.sop')
    foreach($identity in @('@ [completion_signature_uuid] f11fa5aa-9b90-4b46-93d0-8d3f89d72b9d','@ [satisfaction_signature_protocol_uuid] ad10f10f-d506-48ef-a805-f8b0a133766c','@ [specification_uuid] e3e7a424-c013-492a-a913-044ea17dc66d','@ [formation_signature_uuid] f1b12f90-974d-4e0f-b110-5cb1f5ca9409')){if($signature -notmatch [regex]::Escape($identity)){throw 'seed_completion_identity'}}
    $expectedBindings=@(
        "$experiment/inspection_seed_component.json","$experiment/implementation_evidence_manifest.json",
        'proofs/Cantor_Inspection_Runtime_Seed_P0_Implementation_Proof.sop',
        'feature_support/Cantor_Inspection_Runtime_Seed_P0_Completion_Matrix.sop',
        'narrative/reviews/Cantor_Inspection_Runtime_Seed_P0_Completion_Review.sop',
        'docs/INSPECTION_RUNTIME_SEED_P0.md','narrative/reentry/Cantor_Inspection_Runtime_Seed_P0_Reentry.sop',
        'scripts/verify_cantor_inspection_runtime_seed_p0_evidence.ps1',
        'scripts/test_cantor_inspection_runtime_seed_p0.ps1','scripts/test_cantor_inspection_runtime_seed_p0_native.ps1',
        "$experiment/adversarial_summary.json","$experiment/gate_summary.json"
    )
    $bindings=[regex]::Matches($signature,'(?m)^  \+ \[artifact_binding\] (\S+) bytes([0-9]+) SHA256 ([0-9A-F]{64})$')
    if($bindings.Count -ne 12){throw 'seed_completion_count'}
    $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach($binding in $bindings){
        $relative=$binding.Groups[1].Value
        if($relative -cnotin $expectedBindings -or -not $seen.Add($relative)){throw 'seed_completion_membership'}
        Assert-Identity ([pscustomobject]@{path=$relative;bytes=[int64]$binding.Groups[2].Value;sha256=$binding.Groups[3].Value})
    }
}
Write-Output ('cantor_inspection_seed_evidence_verified=true formation=14 component=10 archive_entries=7 refusals=48 native_processes=2 terms=5 workspace=2117 completion_checked='+(-not $SkipCompletion))
