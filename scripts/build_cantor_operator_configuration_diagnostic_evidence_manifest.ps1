[CmdletBinding()]
param(
    [string]$OutputPath = 'experiments/operator_configuration_diagnostic/artifacts/operator_configuration_diagnostic_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$evidencePath = Join-Path $root 'experiments/operator_configuration_diagnostic/artifacts/operator_configuration_diagnostic_evidence_v1.json'
$evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json

$paths = @(
    'experiments/operator_configuration_diagnostic/artifacts/operator_configuration_ready_v1.json',
    'experiments/operator_configuration_diagnostic/artifacts/operator_configuration_refused_v1.json',
    'experiments/operator_configuration_diagnostic/artifacts/operator_configuration_diagnostic_evidence_v1.json',
    'experiments/operator_configuration_diagnostic/README.md',
    'scripts/build_cantor_operator_configuration_diagnostic_evidence.ps1',
    'scripts/verify_cantor_operator_configuration_diagnostic_evidence.ps1',
    'scripts/test_cantor_operator_configuration_diagnostic_evidence.ps1',
    'scripts/build_cantor_operator_configuration_diagnostic_evidence_manifest.ps1',
    'crates/cantor_service/src/model.rs',
    'crates/cantor_service/src/artifacts.rs',
    'crates/cantor_service/src/server_main.rs',
    'crates/cantor_service/tests/configuration_diagnostics.rs',
    'docs/RESIDENT_SERVICE.md',
    'docs/OPERATOR_CONFIGURATION_DIAGNOSTIC_P0.md',
    'source_documents/2026-08-23_operator_configuration_diagnostic_p0/Cantor_Operator_Configuration_Diagnostic_P0_Source.sop',
    'source_documents/2026-08-23_operator_configuration_diagnostic_p0/manifest.sop',
    'specifications/Cantor_Operator_Configuration_Diagnostic_P0.sop',
    'specifications/exploded/Cantor_Operator_Configuration_Diagnostic_P0.exploded.sop',
    'narrative/research/Cantor_Operator_Configuration_Diagnostic_P0_SJS_Review_2026-08-23.sop',
    'plans/Cantor_Operator_Configuration_Diagnostic_P0_Plan.sop',
    'feature_support/Cantor_Operator_Configuration_Diagnostic_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_Operator_Configuration_Diagnostic_P0_Phase_Lock.sop',
    'solutions/Cantor_Operator_Configuration_Diagnostic_P0_Solution.sop',
    'proofs/Cantor_Operator_Configuration_Diagnostic_P0_Proof.sop',
    'narrative/research/Cantor_Operator_Configuration_Diagnostic_P0_Completion_Review_2026-08-23.sop',
    'narrative/reentry/Cantor_Operator_Configuration_Diagnostic_P0_Reentry.sop',
    'narrative/operational_faults/1787483000000_operator_configuration_diagnostic_p0_faults.sop',
    'narrative/turns/1787483000000_operator_configuration_diagnostic_p0_completion.sop',
    'narrative/file_changes/1787483000000_operator_configuration_diagnostic_p0_file_change.sop',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'feature_support/Cantor_Product_Readiness_2026_08_23_Requirement_Matrix.sop',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'narrative/Project_Narrative.sop',
    'README.md',
    'experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0.zip',
    'experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0-evidence.json',
    'experiments/provider_free_portable_release_bundle/artifacts/portable_release_bundle_evidence_manifest.json',
    'proofs/Cantor_Provider_Free_Portable_Release_Bundle_P0_Proof.sop'
)

$artifacts = foreach ($relativePath in $paths) {
    $fullPath = Join-Path $root $relativePath
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "manifest input is not one physical file: $relativePath"
    }
    [ordered]@{
        path = $relativePath.Replace('\', '/')
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

$manifest = [ordered]@{
    profile = 'cantor-operator-configuration-diagnostic-evidence-manifest/0.1'
    evidence_manifest_uuid = '6b46b001-4298-4131-a3e5-7dc648677b12'
    source_commit = [string]$evidence.source_commit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    non_authority_statement = 'This manifest binds provider-free no-listener configuration diagnostic evidence and grants no configuration secret repair migration service provider effect persistence operator-product or production authority.'
}

$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $root $OutputPath))
}
$parent = [IO.Path]::GetDirectoryName($outputFullPath)
if (-not [IO.Directory]::Exists($parent)) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
[IO.File]::WriteAllText(
    $outputFullPath,
    "$(($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $outputFullPath
