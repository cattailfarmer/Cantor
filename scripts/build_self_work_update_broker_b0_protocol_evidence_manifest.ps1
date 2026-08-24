param([switch]$VerifyOnly)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$output = Join-Path $root 'crates/cantor_ecosystem/evidence/self_work_update_broker_b0_protocol_evidence_manifest.json'
$paths = @(
    'source_documents/2026-08-23_cantor_self_work_update_broker_capability_cardinality_correction/Cantor_Self_Work_Update_Broker_Capability_Cardinality_Correction_Source.sop',
    'narrative/operational_faults/1787537567622_self_work_update_broker_capability_cardinality_conflict.sop',
    'specifications/Cantor_Self_Work_Physical_Update_Broker_Revision_0_2.sop',
    'narrative/registries/Cantor_Self_Work_Physical_Update_Broker_Revision_0_2_Formation_Satisfaction_Signature.sop',
    'specifications/Cantor_Self_Work_Update_Broker_B0_Protocol_Revision_0_2.sop',
    'narrative/registries/Cantor_Self_Work_Update_Broker_B0_Protocol_Revision_0_2_Satisfaction_Signature.sop',
    'crates/cantor_ecosystem/src/workspace_admission/update_broker_protocol.rs',
    'crates/cantor_ecosystem/src/workspace_admission.rs',
    'crates/cantor_ecosystem/tests/self_work_update_broker_b0_protocol_static.rs',
    'scripts/build_self_work_update_broker_b0_protocol_evidence_manifest.ps1'
)
$artifacts = @($paths | ForEach-Object {
    $item = Get-Item -LiteralPath (Join-Path $root $_)
    [ordered]@{
        path = $_
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
})
$manifest = [ordered]@{
    profile = 'cantor-self-work-update-broker-protocol-evidence/0.2'
    evidence_uuid = '169bbec0-95d3-4970-9691-b1adee5e97a4'
    protocol_profile = 'cantor-self-work-update-broker-protocol/0.2'
    physical_contact = $false
    capability_count = 22
    granted_capability_count = 0
    later_stage_receipt_types = 0
    production_module_count = 1
    parent_export_count = 1
    cargo_delta = $false
    effect_delta = $false
    artifacts = $artifacts
}
$json = ($manifest | ConvertTo-Json -Depth 8) + "`n"
if ($VerifyOnly) {
    if (-not (Test-Path -LiteralPath $output)) { throw 'evidence manifest is absent' }
    $actual = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 8 -Compress
    $expected = $manifest | ConvertTo-Json -Depth 8 -Compress
    if ($actual -cne $expected) { throw 'evidence manifest differs' }
    Write-Output "self_work_update_broker_b0_protocol_evidence_verified=true artifacts=$($artifacts.Count)"
    exit 0
}
[IO.File]::WriteAllText($output, $json, [Text.UTF8Encoding]::new($false))
Write-Output "self_work_update_broker_b0_protocol_evidence_written=$output artifacts=$($artifacts.Count)"
