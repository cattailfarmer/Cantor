[CmdletBinding()]
param()
# Explicitly test-owned isolated copies only; never modifies the governed baseline.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify_cantor_b1_expected_observation_correspondence_p0_formation.ps1'
$manifestRelative = 'experiments/b1_expected_observation_correspondence_p0/formation_evidence_manifest.json'
$signatureRelative = 'narrative/registries/Cantor_B1_Expected_Observation_Correspondence_P0_Satisfaction_Signature.sop'
$specRelative = 'specifications/Cantor_B1_Expected_Observation_Correspondence_P0.sop'
$designRelative = 'narrative/research/Cantor_B1_Expected_Observation_Correspondence_P0_Data_Design_2026-09-03.sop'
$utf8 = [Text.UTF8Encoding]::new($false)
$baseline = [IO.File]::ReadAllText((Join-Path $root $manifestRelative)) | ConvertFrom-Json
$testRoot = Join-Path $root ('.local/b1-eocv-formation-' + [guid]::NewGuid().ToString('N'))
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

foreach ($name in @('promoted-truth','string-false','missing-field','coordinate-account','reordered-artifacts','signed-a6-context','profile-count','comparison-count','nested-account','receipt-count')) {
    $case = New-Case $name
    $m = [IO.File]::ReadAllText((Join-Path $case $manifestRelative)) | ConvertFrom-Json
    switch ($name) {
        'promoted-truth' { $m.verification.fresh_observation_proved = $true }
        'string-false' { $m.verification.execution_authorized = 'false' }
        'missing-field' { $m.verification.PSObject.Properties.Remove('expected_carrier_authority_proved') }
        'coordinate-account' { $m.verification.selected_coordinate = 7 }
        'reordered-artifacts' { $tmp = $m.artifacts[2]; $m.artifacts[2] = $m.artifacts[3]; $m.artifacts[3] = $tmp }
        'signed-a6-context' { $m.verification.decision_signature_binds_a6_observation = $true }
        'profile-count' { $m.verification.new_profile_count = 8 }
        'comparison-count' { $m.verification.comparison_field_count = 9 }
        'nested-account' { $m.verification.inherited_a5_false_authority_field_count = 0 }
        'receipt-count' { $m.verification.receipt_field_count = 68 }
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

foreach ($name in @('rehash-coordinate','rehash-historical-pin','rehash-currentness-promotion','rehash-capacity-floor','rehash-mismatch-status','rehash-nested-shape','rehash-reason-order','rehash-nullable-shape','rehash-source','rehash-acceptance')) {
    $case = New-Case $name
    $relative = $specRelative
    $before = ''
    $after = ''
    switch ($name) {
        'rehash-coordinate' { $before = 'select exactly ordinal six fresh_observation'; $after = 'select exactly ordinal seven fresh_observation' }
        'rehash-historical-pin' { $before = '98683316ff8735026dded1838c88e84edf7288f5'; $after = '98683316ff8735026dded1838c88e84edf7288f6' }
        'rehash-currentness-promotion' { $before = 'with no signed expectation authority'; $after = 'with signed expectation authority' }
        'rehash-capacity-floor' { $before = 'observed >= minimum comparison'; $after = 'observed > minimum comparison' }
        'rehash-mismatch-status' { $before = 'supplied_observation_expectations_mismatched_execution_unresolved'; $after = 'supplied_observation_expectations_matched_freshness_and_execution_unresolved' }
        'rehash-nested-shape' {
            $relative = $designRelative
            $before = 'profile status authority source_snapshot_uuid canonical_uuid signature_uuid'
            $after = 'profile authority status source_snapshot_uuid canonical_uuid signature_uuid'
        }
        'rehash-reason-order' {
            $relative = $designRelative
            $before = 'mismatch reasons in exact order carrier_commit_mismatch branch_mismatch'
            $after = 'mismatch reasons in exact order branch_mismatch carrier_commit_mismatch'
        }
        'rehash-nullable-shape' {
            $relative = $designRelative
            $before = 'Some iff junction and otherwise None serialized null'
            $after = 'Some iff junction or unknown and otherwise None serialized null'
        }
        'rehash-source' { $relative = $baseline.artifacts[0].path }
        'rehash-acceptance' { $before = 'exact locked-offline serialized workspace debug'; $after = 'partial unlocked workspace debug' }
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
if ($script:refusals -ne 23) { throw 'refusal count differs' }
Write-Output "b1_expected_observation_formation_adversaries_passed valid=2 refusals=$script:refusals isolated_root=$testRoot"
