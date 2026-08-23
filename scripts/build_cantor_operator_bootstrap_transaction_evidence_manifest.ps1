[CmdletBinding()]
param(
    [string]$OutputPath = 'experiments/operator_bootstrap_transaction/artifacts/operator_bootstrap_transaction_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$evidence = Get-Content -LiteralPath (Join-Path $root 'experiments/operator_bootstrap_transaction/artifacts/operator_bootstrap_transaction_evidence_v1.json') -Raw | ConvertFrom-Json
$paths = @(
    'experiments/operator_bootstrap_transaction/artifacts/operator_bootstrap_transaction_evidence_v1.json',
    'experiments/operator_bootstrap_transaction/README.md',
    'scripts/initialize_cantor_service_transaction.ps1',
    'scripts/test_cantor_operator_bootstrap_transaction.ps1',
    'scripts/build_cantor_operator_bootstrap_transaction_evidence.ps1',
    'scripts/verify_cantor_operator_bootstrap_transaction_evidence.ps1',
    'scripts/test_cantor_operator_bootstrap_transaction_evidence.ps1',
    'scripts/build_cantor_operator_bootstrap_transaction_evidence_manifest.ps1',
    'docs/OPERATOR_BOOTSTRAP_TRANSACTION_P0.md',
    'docs/RESIDENT_SERVICE.md',
    'source_documents/2026-08-23_operator_bootstrap_transaction_p0/Cantor_Operator_Bootstrap_Transaction_P0_Source.sop',
    'source_documents/2026-08-23_operator_bootstrap_transaction_p0/manifest.sop',
    'specifications/Cantor_Operator_Bootstrap_Transaction_P0.sop',
    'specifications/exploded/Cantor_Operator_Bootstrap_Transaction_P0.exploded.sop',
    'narrative/research/Cantor_Operator_Bootstrap_Transaction_P0_SJS_Review_2026-08-23.sop',
    'plans/Cantor_Operator_Bootstrap_Transaction_P0_Plan.sop',
    'feature_support/Cantor_Operator_Bootstrap_Transaction_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_Operator_Bootstrap_Transaction_P0_Phase_Lock.sop',
    'solutions/Cantor_Operator_Bootstrap_Transaction_P0_Solution.sop',
    'proofs/Cantor_Operator_Bootstrap_Transaction_P0_Proof.sop',
    'narrative/research/Cantor_Operator_Bootstrap_Transaction_P0_Completion_Review_2026-08-23.sop',
    'narrative/reentry/Cantor_Operator_Bootstrap_Transaction_P0_Reentry.sop',
    'narrative/operational_faults/1787486500000_operator_bootstrap_transaction_p0_faults.sop',
    'narrative/turns/1787484500000_operator_bootstrap_transaction_p0_activation.sop',
    'narrative/turns/1787486500000_operator_bootstrap_transaction_p0_completion.sop',
    'narrative/file_changes/1787486500000_operator_bootstrap_transaction_p0_file_change.sop',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'feature_support/Cantor_Product_Readiness_2026_08_23_Requirement_Matrix.sop',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'narrative/Project_Narrative.sop',
    'README.md',
    'experiments/operator_configuration_diagnostic/artifacts/operator_configuration_diagnostic_evidence_manifest.json',
    'proofs/Cantor_Operator_Configuration_Diagnostic_P0_Proof.sop'
)
$artifacts = foreach ($relative in $paths) {
    $item = Get-Item -LiteralPath (Join-Path $root $relative) -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "manifest input is not one physical file: $relative" }
    [ordered]@{ path = $relative.Replace('\', '/'); bytes = [uint64]$item.Length; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash }
}
$manifest = [ordered]@{
    profile = 'cantor-operator-bootstrap-transaction-evidence-manifest/0.1'
    evidence_manifest_uuid = '4f2a4964-e0db-44d4-a241-4f2bd6fea51b'
    source_commit = [string]$evidence.source_commit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    non_authority_statement = 'This manifest binds disposable initial-create bootstrap evidence and grants no replacement production secret lifecycle installation delivery service provider effect operator-product or production authority.'
}
$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) { [IO.Path]::GetFullPath($OutputPath) } else { [IO.Path]::GetFullPath((Join-Path $root $OutputPath)) }
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($outputFullPath)) | Out-Null
[IO.File]::WriteAllText($outputFullPath, "$(($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
Write-Output $outputFullPath
