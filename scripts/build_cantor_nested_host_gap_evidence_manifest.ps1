[CmdletBinding()]
param(
    [string]$OutputPath = 'experiments/nested_cantor_host_gap_audit/artifacts/nested_cantor_host_gap_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$matrixPath = Join-Path $root 'experiments/nested_cantor_host_gap_audit/artifacts/nested_cantor_host_gap_matrix_v1.json'
$matrix = Get-Content -LiteralPath $matrixPath -Raw | ConvertFrom-Json
$sourceCommit = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'unable to resolve the repository source commit'
}

$fixedPaths = @(
    'experiments/nested_cantor_host_gap_audit/artifacts/nested_cantor_host_gap_matrix_v1.json',
    'scripts/verify_cantor_nested_host_gap_audit.ps1',
    'scripts/test_cantor_nested_host_gap_audit.ps1',
    'scripts/build_cantor_nested_host_gap_evidence_manifest.ps1',
    'source_documents/2026-08-23_nested_cantor_llm_host_current_thread/Cantor_Nested_LLM_Host_Vision_Source.sop',
    'source_documents/2026-08-23_nested_cantor_llm_host_current_thread/manifest.sop',
    'narrative/turns/1787494600000_nested_cantor_llm_host_vision.sop',
    'narrative/research/Cantor_Nested_LLM_Host_Gap_Audit_Activation_Review_2026-08-23.sop',
    'plans/Cantor_Nested_LLM_Host_Contract_Sequence_Plan.sop',
    'feature_support/Cantor_Nested_LLM_Host_Gap_Requirement_Matrix.sop',
    'narrative/registries/Cantor_Nested_LLM_Host_Gap_Audit_Phase_Lock.sop',
    'solutions/Cantor_Nested_LLM_Host_Gap_Audit_Solution.sop',
    'proofs/Cantor_Nested_LLM_Host_Gap_Audit_Proof.sop',
    'narrative/research/Cantor_Nested_LLM_Host_Gap_Audit_Completion_Review_2026-08-23.sop',
    'narrative/reentry/Cantor_Nested_LLM_Host_Gap_Audit_Reentry.sop',
    'narrative/operational_faults/1787496000000_nested_llm_host_gap_audit_faults.sop',
    'narrative/file_changes/1787496000000_nested_llm_host_gap_audit_file_change.sop',
    'narrative/turns/1787496000000_nested_llm_host_gap_audit.sop',
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'narrative/Project_Narrative.sop',
    'README.md'
)
$evidencePaths = @($matrix.entries | ForEach-Object { @($_.evidence_paths) } | ForEach-Object { [string]$_ })
$paths = @($fixedPaths + $evidencePaths | Sort-Object -Unique)
if ($paths.Count -ne @($fixedPaths + $evidencePaths | Select-Object -Unique).Count) {
    throw 'evidence path normalization differs'
}

$artifacts = foreach ($relativePath in $paths) {
    if ([IO.Path]::IsPathRooted($relativePath) -or $relativePath -match '(^|[\\/])\.\.([\\/]|$)') {
        throw "nonportable evidence path: $relativePath"
    }
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
    profile = 'cantor-nested-llm-host-gap-evidence-manifest/0.1'
    evidence_manifest_uuid = 'd654dd2c-0e7a-4c71-964d-1e8ca54b3ebc'
    source_uuid = '6fa07b14-4a49-495c-834f-be2b7dd0f7ea'
    source_commit = $sourceCommit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    non_authority_statement = 'This manifest binds a source-to-tracked-substrate gap audit. It grants no canonical nested-host specification, implementation, process launch, model loading, provider call, persistence, remote action, effect, FPGA, or Minecraft authority.'
}

$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
}
else {
    [IO.Path]::GetFullPath((Join-Path $root $OutputPath))
}
$parent = [IO.Path]::GetDirectoryName($outputFullPath)
if (-not [IO.Directory]::Exists($parent)) {
    [IO.Directory]::CreateDirectory($parent) | Out-Null
}
[IO.File]::WriteAllText(
    $outputFullPath,
    "$(($manifest | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $outputFullPath
