[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify_cantor_b1_trusted_time_witness_receipt_verification_p0_formation.ps1'
$manifestRelative = 'experiments/b1_trusted_time_witness_receipt_verification_p0/formation_evidence_manifest.json'
$signatureRelative = 'narrative/registries/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0_Satisfaction_Signature.sop'
$specRelative = 'specifications/Cantor_B1_Trusted_Time_Witness_Receipt_Verification_P0.sop'
$utf8 = [Text.UTF8Encoding]::new($false)
$baseline = [IO.File]::ReadAllText((Join-Path $root $manifestRelative)) | ConvertFrom-Json
$testRoot = Join-Path $root ('.local/b1-twv-formation-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
$script:refusals = 0

function New-Case([string]$Name) {
    $caseRoot = Join-Path $testRoot $Name
    foreach ($relative in @($baseline.artifacts.path) + @($manifestRelative)) {
        $target = Join-Path $caseRoot $relative
        $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target)
        Copy-Item -LiteralPath (Join-Path $root $relative) -Destination $target
    }
    return $caseRoot
}
function Write-Manifest([string]$CaseRoot, $Manifest) {
    [IO.File]::WriteAllText((Join-Path $CaseRoot $manifestRelative), (($Manifest | ConvertTo-Json -Depth 50 -Compress) + "`n"), $utf8)
}
function Refuse([string]$CaseRoot, [string]$Name) {
    $refused = $false
    try { $null = & $verifier -RepositoryRoot $CaseRoot }
    catch { $refused = $true }
    if (-not $refused) { throw "formation adversary accepted: $Name" }
    $script:refusals++
}
$null = & $verifier
$valid = New-Case 'valid'
$null = & $verifier -RepositoryRoot $valid

$case = New-Case 'one-byte'
$file = Join-Path $case $baseline.artifacts[2].path
[IO.File]::AppendAllText($file, 'x', $utf8)
Refuse $case 'one-byte artifact'

foreach ($name in @('promoted-truth','string-false','missing-field','coordinate-account','reordered-artifacts')) {
    $case = New-Case $name
    $m = [IO.File]::ReadAllText((Join-Path $case $manifestRelative)) | ConvertFrom-Json
    switch ($name) {
        'promoted-truth' { $m.verification.trusted_current_time_proved = $true }
        'string-false' { $m.verification.execution_authorized = 'false' }
        'missing-field' { $m.verification.PSObject.Properties.Remove('witness_authority_proved') }
        'coordinate-account' { $m.verification.selected_coordinate = 5 }
        'reordered-artifacts' { $tmp = $m.artifacts[2]; $m.artifacts[2] = $m.artifacts[3]; $m.artifacts[3] = $tmp }
    }
    Write-Manifest $case $m
    Refuse $case $name
}
$case = New-Case 'duplicate-json'
$file = Join-Path $case $manifestRelative
$raw = [IO.File]::ReadAllText($file)
$raw = $raw.Replace('"file_ref_count":21,', '"file_ref_count":21,"file_ref_count":21,')
[IO.File]::WriteAllText($file, $raw, $utf8)
Refuse $case 'duplicate JSON property'

$case = New-Case 'path-traversal'
$m = [IO.File]::ReadAllText((Join-Path $case $manifestRelative)) | ConvertFrom-Json
$m.artifacts[0].path = '../foreign.sop'
Write-Manifest $case $m
Refuse $case 'path traversal'

$case = New-Case 'rehash-coordinate'
$file = Join-Path $case $specRelative
$raw = [IO.File]::ReadAllText($file).Replace('select exactly ordinal four current_time', 'select exactly ordinal five current_time')
[IO.File]::WriteAllText($file, $raw, $utf8)
# The adversary may recompute untrusted manifests and binding text; semantic coordinates must still refuse.
$sigPath = Join-Path $case $signatureRelative
$sig = [IO.File]::ReadAllText($sigPath)
foreach ($artifact in @($baseline.artifacts | Select-Object -First 20)) {
    $newHash = (Get-FileHash -LiteralPath (Join-Path $case $artifact.path) -Algorithm SHA256).Hash
    $sig = $sig.Replace($artifact.path + ' SHA256 ' + $artifact.sha256, $artifact.path + ' SHA256 ' + $newHash)
}
[IO.File]::WriteAllText($sigPath, $sig, $utf8)
$m = [IO.File]::ReadAllText((Join-Path $case $manifestRelative)) | ConvertFrom-Json
foreach ($artifact in $m.artifacts) {
    $full = Join-Path $case $artifact.path
    $artifact.bytes = (Get-Item -LiteralPath $full).Length
    $artifact.sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
}
Write-Manifest $case $m
Refuse $case 'rehashed semantic coordinate'
if ($script:refusals -ne 9) { throw 'refusal count differs' }
Write-Output "b1_trusted_time_witness_formation_adversaries_passed valid=2 refusals=$script:refusals isolated_root=$testRoot"
