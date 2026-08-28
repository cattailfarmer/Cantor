param(
    [switch]$Release,
    [string]$TargetDirectory = 'D:\CantorBuilds\cantor-nhma-p0-target',
    [string]$ArtifactDirectory = 'experiments/nested_inner_model_admission_p0/artifacts'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $root $ArtifactDirectory
$expectedNames = @('envelope.json', 'evidence_manifest.json', 'request.json', 'verification.json')
$actualNames = @(Get-ChildItem -LiteralPath $artifactRoot -File | ForEach-Object Name | Sort-Object)
if (Compare-Object $expectedNames $actualNames) {
    throw 'retained artifact directory membership differs from the exact four-file set'
}

function Invoke-NhmaCli {
    param(
        [Parameter(Mandatory = $true)][string]$Binary,
        [Parameter(Mandatory = $true)][string]$InputText,
        [Parameter(Mandatory = $true)][bool]$ExpectSuccess
    )
    $arguments = @('run', '--quiet', '--locked', '--offline', '--target-dir', $TargetDirectory, '-p', 'cantor_core')
    if ($Release) { $arguments += '--release' }
    $arguments += @('--bin', $Binary)
    $prior = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $lines = @($InputText | & cargo @arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $prior
    $output = $lines -join [Environment]::NewLine
    if ($ExpectSuccess -and $exitCode -ne 0) { throw "$Binary failed with exit $exitCode`: $output" }
    if (-not $ExpectSuccess -and $exitCode -eq 0) { throw "$Binary accepted adversarial input" }
    return $output
}

$bundle = [ordered]@{
    request_file = [IO.File]::ReadAllText((Join-Path $artifactRoot 'request.json'))
    envelope_file = [IO.File]::ReadAllText((Join-Path $artifactRoot 'envelope.json'))
    verification_file = [IO.File]::ReadAllText((Join-Path $artifactRoot 'verification.json'))
    manifest_file = [IO.File]::ReadAllText((Join-Path $artifactRoot 'evidence_manifest.json'))
}
$bundleJson = $bundle | ConvertTo-Json -Compress
$receiptJson = Invoke-NhmaCli -Binary 'cantor-nested-inner-model-admission-evidence-verify' -InputText $bundleJson -ExpectSuccess $true
$receipt = $receiptJson | ConvertFrom-Json
if ($receipt.status -ne 'verified_provider_free_descriptor_and_authorization_correspondence' -or
    $receipt.upstream_operational_identity_count -ne 7 -or
    $receipt.operational_identity_count -ne 8 -or
    $receipt.bound_identity_count -ne 10 -or
    $receipt.capability_denial_count -ne 15 -or
    $receipt.unresolved_truth_count -ne 10 -or
    $receipt.signature_correspondence_verified -ne $true) {
    throw 'verification receipt semantic account differs'
}
$effectValues = @($receipt.effects.PSObject.Properties.Value)
if (@($effectValues | Where-Object { $_ -ne 0 -and $_ -ne $false }).Count -ne 0) {
    throw 'verification receipt contains a physical effect'
}

$replayedBundleJson = Invoke-NhmaCli -Binary 'cantor-nested-inner-model-admission-fixture' -InputText $bundle.request_file -ExpectSuccess $true
$replayed = $replayedBundleJson | ConvertFrom-Json
foreach ($name in @('request_file', 'envelope_file', 'verification_file', 'manifest_file')) {
    if ([string]$replayed.$name -cne [string]$bundle.$name) {
        throw "fixture replay differs at $name"
    }
}

$refusals = 0
$unknown = $bundleJson -replace '^\{', '{"unknown":true,'
Invoke-NhmaCli -Binary 'cantor-nested-inner-model-admission-evidence-verify' -InputText $unknown -ExpectSuccess $false | Out-Null
$refusals++

$rawRequest = [ordered]@{} + $bundle
$rawRequest.request_file = $rawRequest.request_file + ' '
Invoke-NhmaCli -Binary 'cantor-nested-inner-model-admission-evidence-verify' -InputText ($rawRequest | ConvertTo-Json -Compress) -ExpectSuccess $false | Out-Null
$refusals++

$manifestCount = [ordered]@{} + $bundle
$manifestCount.manifest_file = $manifestCount.manifest_file -replace '"bound_identity_count":10', '"bound_identity_count":9'
Invoke-NhmaCli -Binary 'cantor-nested-inner-model-admission-evidence-verify' -InputText ($manifestCount | ConvertTo-Json -Compress) -ExpectSuccess $false | Out-Null
$refusals++

$envelopeDenial = [ordered]@{} + $bundle
$envelopeDenial.envelope_file = $envelopeDenial.envelope_file -replace '"model_load_attempt",', ''
Invoke-NhmaCli -Binary 'cantor-nested-inner-model-admission-evidence-verify' -InputText ($envelopeDenial | ConvertTo-Json -Compress) -ExpectSuccess $false | Out-Null
$refusals++

$verificationEffect = [ordered]@{} + $bundle
$verificationEffect.verification_file = $verificationEffect.verification_file -replace '"model_load_attempt_count":0', '"model_load_attempt_count":1'
Invoke-NhmaCli -Binary 'cantor-nested-inner-model-admission-evidence-verify' -InputText ($verificationEffect | ConvertTo-Json -Compress) -ExpectSuccess $false | Out-Null
$refusals++

Write-Output "nested_inner_model_admission_evidence_passed release=$Release files=3 replays=2 upstream_identities=7 operational_identities=8 bound_identities=10 denials=15 unresolved=10 refusals=$refusals effects=0"
$global:LASTEXITCODE = 0
