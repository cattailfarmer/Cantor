[CmdletBinding()]
param()
# Test-owned isolated copies only; never mutates the governed baseline.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify_cantor_b1_operator_decision_chain_verification_p0_formation.ps1'
$manifestRelative = 'experiments/b1_operator_decision_chain_verification_p0/formation_evidence_manifest.json'
$signatureRelative = 'narrative/registries/Cantor_B1_Operator_Decision_Chain_Verification_P0_Satisfaction_Signature.sop'
$specRelative = 'specifications/Cantor_B1_Operator_Decision_Chain_Verification_P0.sop'
$designRelative = 'narrative/research/Cantor_B1_Operator_Decision_Chain_Verification_P0_Data_Design_2026-09-03.sop'
$utf8 = [Text.UTF8Encoding]::new($false)
$baseline = [IO.File]::ReadAllText((Join-Path $root $manifestRelative)) | ConvertFrom-Json
$testRoot = Join-Path $root ('.local/b1-odcv-formation-' + [guid]::NewGuid().ToString('N'))
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
function Rehash-UntrustedBindings([string]$CaseRoot) {
    $sigPath = Join-Path $CaseRoot $signatureRelative
    $sig = [IO.File]::ReadAllText($sigPath)
    foreach ($artifact in @($baseline.artifacts | Select-Object -First 20)) {
        $newHash = (Get-FileHash -LiteralPath (Join-Path $CaseRoot $artifact.path) -Algorithm SHA256).Hash
        $sig = $sig.Replace($artifact.path + ' SHA256 ' + $artifact.sha256, $artifact.path + ' SHA256 ' + $newHash)
    }
    [IO.File]::WriteAllText($sigPath, $sig, $utf8)
    $m = [IO.File]::ReadAllText((Join-Path $CaseRoot $manifestRelative)) | ConvertFrom-Json
    foreach ($artifact in $m.artifacts) {
        $full = Join-Path $CaseRoot $artifact.path
        $artifact.bytes = (Get-Item -LiteralPath $full).Length
        $artifact.sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
    }
    Write-Manifest $CaseRoot $m
}
$null = & $verifier
$valid = New-Case 'valid'
$null = & $verifier -RepositoryRoot $valid
$case = New-Case 'one-byte'
[IO.File]::AppendAllText((Join-Path $case $baseline.artifacts[2].path), 'x', $utf8)
Refuse $case 'one-byte'

foreach ($name in @('promoted-truth','string-false','missing-field','coordinate-account','reordered-artifacts','signed-a4-context','profile-count')) {
    $case = New-Case $name
    $m = [IO.File]::ReadAllText((Join-Path $case $manifestRelative)) | ConvertFrom-Json
    switch ($name) {
        'promoted-truth' { $m.verification.live_authorization_admitted = $true }
        'string-false' { $m.verification.execution_authorized = 'false' }
        'missing-field' { $m.verification.PSObject.Properties.Remove('decision_authority_proved') }
        'coordinate-account' { $m.verification.selected_coordinate = 6 }
        'reordered-artifacts' { $tmp = $m.artifacts[2]; $m.artifacts[2] = $m.artifacts[3]; $m.artifacts[3] = $tmp }
        'signed-a4-context' { $m.verification.decision_signature_binds_a4_lineage = $true }
        'profile-count' { $m.verification.new_profile_count = 8 }
    }
    Write-Manifest $case $m
    Refuse $case $name
}
$case = New-Case 'duplicate-json'
$file = Join-Path $case $manifestRelative
$raw = [IO.File]::ReadAllText($file).Replace('"file_ref_count":21,', '"file_ref_count":21,"file_ref_count":21,')
[IO.File]::WriteAllText($file, $raw, $utf8)
Refuse $case 'duplicate-json'
$case = New-Case 'path-traversal'
$m = [IO.File]::ReadAllText((Join-Path $case $manifestRelative)) | ConvertFrom-Json
$m.artifacts[0].path = '../foreign.sop'
Write-Manifest $case $m
Refuse $case 'path-traversal'

foreach ($name in @('rehash-coordinate','rehash-expiry','rehash-signature-coverage','rehash-imported-shape','rehash-source')) {
    $case = New-Case $name
    $relative = $specRelative
    $before = ''
    $after = ''
    switch ($name) {
        'rehash-coordinate' { $before = 'select exactly ordinal five live_decision'; $after = 'select exactly ordinal six live_decision' }
        'rehash-expiry' { $before = 'after_decision_interval iff observed >= expires'; $after = 'after_decision_interval iff observed > expires' }
        'rehash-signature-coverage' { $before = 'leave decision_signature_binds_a4_lineage false'; $after = 'leave decision_signature_binds_a4_lineage true' }
        'rehash-imported-shape' {
            $relative = $designRelative
            $before = 'profile policy_uuid principal role subject verifying_key_hex key_fingerprint_sha256'
            $after = 'profile policy_uuid principal role subject key_fingerprint_sha256 verifying_key_hex'
        }
        'rehash-source' { $relative = $baseline.artifacts[0].path }
    }
    $file = Join-Path $case $relative
    $raw = [IO.File]::ReadAllText($file)
    if ($name -eq 'rehash-source') { $changed = $raw + 'x' }
    else {
        if (-not $raw.Contains($before)) { throw "adversarial target missing: $name" }
        $changed = $raw.Replace($before, $after)
    }
    [IO.File]::WriteAllText($file, $changed, $utf8)
    Rehash-UntrustedBindings $case
    Refuse $case $name
}
if ($script:refusals -ne 15) { throw 'refusal count differs' }
Write-Output "b1_operator_decision_chain_formation_adversaries_passed valid=2 refusals=$script:refusals isolated_root=$testRoot"
