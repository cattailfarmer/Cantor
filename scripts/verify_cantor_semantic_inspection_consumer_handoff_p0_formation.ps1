param([string]$RepositoryRoot = "")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Join-Path $PSScriptRoot ".." }
$selectedRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$signaturePath = Join-Path $selectedRoot "narrative/registries/Cantor_Semantic_Inspection_Consumer_Handoff_P0_Satisfaction_Signature.sop"
$signature = Get-Content -LiteralPath $signaturePath -Raw
foreach ($identity in @(
    "@ [signature_uuid] 3a2306de-7074-4e99-b72d-37f2e911302d",
    "@ [satisfaction_signature_protocol_uuid] ad10f10f-d506-48ef-a805-f8b0a133766c",
    "@ [specification_uuid] 6abf0365-921b-4d9c-a794-a65ae187ffae",
    "@ [source_snapshot_uuid] c01a09df-6494-44d9-b30a-d85e66ee30b7"
)) { if ($signature -notmatch [regex]::Escape($identity)) { throw "formation signature identity differs" } }
$bindings = [regex]::Matches($signature, '(?m)^  \+ \[artifact_binding\] (\S+) bytes([0-9]+) SHA256 ([0-9A-F]{64})$')
if ($bindings.Count -ne 12) { throw "expected twelve formation bindings" }
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($binding in $bindings) {
    $relative = $binding.Groups[1].Value
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or -not $seen.Add($relative)) { throw "invalid or duplicate formation binding" }
    $path = Join-Path $selectedRoot $relative
    if ((Get-Item -LiteralPath $path).Length -ne [int64]$binding.Groups[2].Value -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $binding.Groups[3].Value) { throw "formation artifact differs: $relative" }
}
$specification = Get-Content -LiteralPath (Join-Path $selectedRoot "specifications/Cantor_Semantic_Inspection_Consumer_Handoff_P0.sop") -Raw
$requirements = @([regex]::Matches($specification, '\[CICH-[0-9]{3}\]') | ForEach-Object { $_.Value })
$acceptance = @([regex]::Matches($specification, '\[CICH-A[0-9]{2}\]') | ForEach-Object { $_.Value })
if ($requirements.Count -ne 24 -or $acceptance.Count -ne 6) { throw "formation cardinality differs" }
for ($index = 1; $index -le 24; $index++) { if (('[CICH-{0:D3}]' -f $index) -notin $requirements) { throw "missing formation requirement" } }
for ($index = 1; $index -le 6; $index++) { if (('[CICH-A{0:D2}]' -f $index) -notin $acceptance) { throw "missing formation acceptance" } }
$protected = 'C:\Project\Cantor\narrative\turns\1786911720465_minecraftgenie_scope_handoff_negotiation.sop'
if ((Get-Item -LiteralPath $protected).Length -ne 1805 -or (Get-FileHash -LiteralPath $protected -Algorithm SHA256).Hash -cne '5B806E8D078C03D189021D0BB458EA42ADE3508E04677387D9AB9966DADC6F07') { throw "protected foreign source identity differs" }
Write-Output "cantor_consumer_handoff_formation_verified=true artifacts=12 requirements=24 acceptance=6 product_effects=0"
