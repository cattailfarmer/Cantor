$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$artifacts = @(
    [ordered]@{ path = "source_documents/2026-09-30_cantor_composed_read_only_semantic_inspection_p0/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Source.sop"; bytes = 3730; sha256 = "5B7235B828E5312A4FBC42C8E65C629248118CF82030A1CECF389EF148EAB4BE" },
    [ordered]@{ path = "specifications/Cantor_Composed_Read_Only_Semantic_Inspection_P0.sop"; bytes = 4803; sha256 = "4D97BA7BBE6941B8159F9B4AD6B8108EBC52ED94BEFEDC933021F417ED68D424" },
    [ordered]@{ path = "justifications/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Justification.sop"; bytes = 1240; sha256 = "583B479CDCD38A7C2664536225FB1E176FD41A7BD2A8583EFA4BA03936BCAF3A" },
    [ordered]@{ path = "plans/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Plan.sop"; bytes = 1300; sha256 = "9242CFCCBD05EF755ECFA0F37485E692EA7E5CD5A2A4FB86809FF5DFC0D91268" },
    [ordered]@{ path = "solutions/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Solution.sop"; bytes = 1747; sha256 = "289CBD697AACCB8DF44BA8AB078E8C0CEDC58F7AA6B6BC319D0936F70511E235" },
    [ordered]@{ path = "feature_support/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Requirement_Matrix.sop"; bytes = 1331; sha256 = "7C0A8FBE9EFF24DE09DA91EC266AEF68D8155283168FE8D380FFF6330A361997" },
    [ordered]@{ path = "proofs/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Artifact_Phase_Lock_Proof.sop"; bytes = 1186; sha256 = "E929EBDF69D858C9120968EEFA08B66D6A05513E5FE88084CCA21D6B08C32690" }
)
foreach ($artifact in $artifacts) {
    $path = Join-Path $repositoryRoot ([string]$artifact.path)
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne [string]$artifact.sha256) { throw "formation artifact differs: $($artifact.path)" }
}
$sourceReplay = @(& (Join-Path $PSScriptRoot "verify_cantor_composed_read_only_semantic_inspection_p0_source.ps1"))
if ($sourceReplay.Count -ne 1 -or $sourceReplay[0] -cne "cantor_composed_read_only_semantic_inspection_source_verified=true files=4 bytes=57333 live_source_mutations=0 effects=0") { throw "source replay differs" }
$specification = Get-Content -LiteralPath (Join-Path $repositoryRoot "specifications/Cantor_Composed_Read_Only_Semantic_Inspection_P0.sop") -Raw
foreach ($number in 1..24) { $id = "CRSI-{0:d3}" -f $number; if ($specification -cnotmatch [regex]::Escape("[$id]")) { throw "requirement absent: $id" } }
foreach ($number in 1..5) { $id = "CRSI-A{0:d2}" -f $number; if ($specification -cnotmatch [regex]::Escape("[$id]")) { throw "acceptance absent: $id" } }
$signaturePath = Join-Path $repositoryRoot "narrative/registries/Cantor_Composed_Read_Only_Semantic_Inspection_P0_Satisfaction_Signature.sop"
$signature = Get-Content -LiteralPath $signaturePath -Raw
foreach ($artifact in $artifacts) {
    $binding = "+ [artifact_binding] $($artifact.path) bytes$($artifact.bytes) SHA256 $($artifact.sha256)"
    if (-not $signature.Contains($binding)) { throw "signature binding differs: $($artifact.path)" }
}
foreach ($needle in @("88e3b141-bd80-4d05-9015-e333aa539e9f", "ad10f10f-d506-48ef-a805-f8b0a133766c", "8e08875a-6877-4c07-9752-b96771fb0b33", "formation_complete_signature_valid_bounded_implementation_authorized")) { if (-not $signature.Contains($needle)) { throw "signature identity differs: $needle" } }
Write-Output "cantor_composed_read_only_semantic_inspection_formation_verified=true artifacts=7 requirements=24 acceptance=5 source_files=4 effects=0"
