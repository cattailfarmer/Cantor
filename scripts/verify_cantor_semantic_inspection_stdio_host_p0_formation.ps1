param(
    [string]$LiveRoot = "C:\Project\Cantor",
    [string]$RepositoryRoot = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Join-Path $PSScriptRoot ".." }
$repositoryRootPath = [IO.Path]::GetFullPath($RepositoryRoot)
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_stdio_host_p0_source.ps1") -LiveRoot $LiveRoot -RepositoryRoot $repositoryRootPath
if ($LASTEXITCODE -ne 0) { throw "source verification failed" }

$signaturePath = Join-Path $repositoryRootPath "narrative/registries/Cantor_Semantic_Inspection_Stdio_Host_P0_Satisfaction_Signature.sop"
$signature = Get-Content -LiteralPath $signaturePath -Raw
if ($signature -notmatch [regex]::Escape("@ [signature_uuid] 69432dba-7e63-49c8-aac8-05a9cbfaed2d") -or $signature -notmatch [regex]::Escape("@ [specification_uuid] 4ee53d21-ed53-4f35-bbaf-06cab3a34085")) { throw "formation signature identity differs" }
$bindingPattern = '(?m)^  \+ \[artifact_binding\] (\S+) bytes([0-9]+) SHA256 ([0-9A-F]{64})$'
$bindings = [regex]::Matches($signature, $bindingPattern)
if ($bindings.Count -ne 7) { throw "expected seven artifact bindings" }
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($binding in $bindings) {
    $relative = $binding.Groups[1].Value
    if (-not $seen.Add($relative)) { throw "duplicate artifact binding: $relative" }
    $path = Join-Path $repositoryRootPath $relative
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($item.Length -ne [int64]$binding.Groups[2].Value -or $hash -cne $binding.Groups[3].Value) { throw "artifact binding differs: $relative" }
}

$specificationPath = Join-Path $repositoryRootPath "specifications/Cantor_Semantic_Inspection_Stdio_Host_P0.sop"
$specification = Get-Content -LiteralPath $specificationPath -Raw
$requirements = [regex]::Matches($specification, '\[CSIH-[0-9]{3}\]') | ForEach-Object { $_.Value } | Sort-Object -Unique
$acceptance = [regex]::Matches($specification, '\[CSIH-A[0-9]{2}\]') | ForEach-Object { $_.Value } | Sort-Object -Unique
if (@($requirements).Count -ne 24 -or @($acceptance).Count -ne 5) { throw "requirement or acceptance cardinality differs" }
for ($number = 1; $number -le 24; $number++) {
    $expected = '[CSIH-{0:D3}]' -f $number
    if ($expected -notin @($requirements)) { throw "missing requirement $expected" }
}
for ($number = 1; $number -le 5; $number++) {
    $expected = '[CSIH-A{0:D2}]' -f $number
    if ($expected -notin @($acceptance)) { throw "missing acceptance gate $expected" }
}

$manifestPath = Join-Path $repositoryRootPath "experiments/cantor_semantic_inspection_stdio_host_p0/formation_evidence_manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne "cantor-semantic-inspection-stdio-host-formation-evidence/0.1" -or $manifest.source_snapshot_uuid -cne "83e194a8-122e-47ea-aec8-a35b5317d3b2" -or $manifest.specification_uuid -cne "4ee53d21-ed53-4f35-bbaf-06cab3a34085" -or $manifest.signature_uuid -cne "69432dba-7e63-49c8-aac8-05a9cbfaed2d") { throw "formation evidence identity differs" }
if ([int]$manifest.artifact_count -ne 7 -or [int]$manifest.requirement_count -ne 24 -or [int]$manifest.acceptance_gate_count -ne 5 -or [int]$manifest.source_file_count -ne 4 -or [int64]$manifest.source_byte_count -ne 28799) { throw "formation evidence counters differ" }
foreach ($field in @('formation_stdin_reads','formation_stdout_writes','formation_stderr_writes','formation_process_exits','filesystem_effects','network_effects','service_effects','provider_calls','model_calls','remote_calls','promoted_external_effects')) {
    if ([int]$manifest.$field -ne 0) { throw "nonzero formation effect counter: $field" }
}
Write-Output "cantor_semantic_inspection_stdio_host_formation_verified=true artifacts=7 requirements=24 acceptance=5 source_files=4 effects=0"
