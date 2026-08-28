param(
    [switch]$Release,
    [string]$TargetDirectory = 'D:\CantorBuilds\cantor-nhil-p0-target',
    [string]$ArtifactDirectory = 'experiments/nested_inner_process_lineage_p0/artifacts'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$artifactRoot = Join-Path $root $ArtifactDirectory
$requestPath = Join-Path $artifactRoot 'request.json'
$envelopePath = Join-Path $artifactRoot 'envelope.json'
$verificationPath = Join-Path $artifactRoot 'verification.json'
$manifestPath = Join-Path $artifactRoot 'evidence_manifest.json'
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

if (-not (Test-Path -LiteralPath $requestPath -PathType Leaf)) {
    throw "retained request fixture is absent: $requestPath"
}

function Invoke-LineageCli {
    param(
        [Parameter(Mandatory = $true)][string]$Binary,
        [Parameter(Mandatory = $true)][string]$InputText,
        [Parameter(Mandatory = $true)][bool]$ExpectSuccess
    )

    $arguments = @('run', '--quiet', '--locked', '--target-dir', $TargetDirectory, '-p', 'cantor_core')
    if ($Release) {
        $arguments += '--release'
    }
    $arguments += @('--bin', $Binary)
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $lines = @($InputText | & cargo @arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $priorPreference
    $output = $lines -join [Environment]::NewLine
    if ($ExpectSuccess -and $exitCode -ne 0) {
        throw "$Binary failed with exit $exitCode`: $output"
    }
    if (-not $ExpectSuccess -and $exitCode -eq 0) {
        throw "$Binary accepted an adversarial fixture"
    }
    return $output
}

$requestInput = [System.IO.File]::ReadAllText($requestPath)
$bundleJson = Invoke-LineageCli -Binary 'cantor-nested-inner-process-lineage-fixture' -InputText $requestInput -ExpectSuccess $true
$bundle = $bundleJson | ConvertFrom-Json

[System.IO.Directory]::CreateDirectory($artifactRoot) | Out-Null
[System.IO.File]::WriteAllText($requestPath, [string]$bundle.request_file, $utf8NoBom)
[System.IO.File]::WriteAllText($envelopePath, [string]$bundle.envelope_file, $utf8NoBom)
[System.IO.File]::WriteAllText($verificationPath, [string]$bundle.verification_file, $utf8NoBom)
[System.IO.File]::WriteAllText($manifestPath, [string]$bundle.manifest_file, $utf8NoBom)

$retainedBundle = [ordered]@{
    request_file = [System.IO.File]::ReadAllText($requestPath)
    envelope_file = [System.IO.File]::ReadAllText($envelopePath)
    verification_file = [System.IO.File]::ReadAllText($verificationPath)
    manifest_file = [System.IO.File]::ReadAllText($manifestPath)
}
$retainedBundleJson = $retainedBundle | ConvertTo-Json -Compress
$receiptJson = Invoke-LineageCli -Binary 'cantor-nested-inner-process-lineage-evidence-verify' -InputText $retainedBundleJson -ExpectSuccess $true
$receipt = $receiptJson | ConvertFrom-Json
if ($receipt.profile -ne 'cantor-nested-inner-process-lineage-verification/0.1' -or
    $receipt.status -ne 'verified_provider_free_lineage_correspondence' -or
    $receipt.operational_identity_count -ne 7 -or
    $receipt.capability_denial_count -ne 10 -or
    $receipt.unresolved_truth_count -ne 6 -or
    $receipt.lineage_depth -ne 1 -or
    $receipt.child_ordinal -ne 1 -or
    $receipt.effects.process_count -ne 0 -or
    $receipt.effects.provider_trial_count -ne 0 -or
    $receipt.effects.model_turn_count -ne 0 -or
    $receipt.effects.mcp_call_count -ne 0 -or
    $receipt.effects.workspace_mutation_count -ne 0 -or
    $receipt.effects.network_contact_count -ne 0 -or
    $receipt.effects.remote_contact_count -ne 0 -or
    $receipt.effects.persistence_count -ne 0 -or
    $receipt.effects.activation_count -ne 0 -or
    $receipt.effects.cleanup_effect_count -ne 0 -or
    $receipt.effects.foreign_effect_count -ne 0) {
    throw 'verification receipt differs from the exact zero-effect NHC-02 account'
}

foreach ($coordinate in 'request_file', 'envelope_file', 'verification_file', 'manifest_file') {
    $adversarial = [ordered]@{
        request_file = $retainedBundle.request_file
        envelope_file = $retainedBundle.envelope_file
        verification_file = $retainedBundle.verification_file
        manifest_file = $retainedBundle.manifest_file
    }
    $adversarial[$coordinate] = [string]$adversarial[$coordinate] + ' '
    $adversarialJson = $adversarial | ConvertTo-Json -Compress
    Invoke-LineageCli -Binary 'cantor-nested-inner-process-lineage-evidence-verify' -InputText $adversarialJson -ExpectSuccess $false | Out-Null
}

$unknown = [ordered]@{
    request_file = $retainedBundle.request_file
    envelope_file = $retainedBundle.envelope_file
    verification_file = $retainedBundle.verification_file
    manifest_file = $retainedBundle.manifest_file
    unexpected = $true
} | ConvertTo-Json -Compress
Invoke-LineageCli -Binary 'cantor-nested-inner-process-lineage-evidence-verify' -InputText $unknown -ExpectSuccess $false | Out-Null

$manifest = [System.IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
$fileCount = @($manifest.files.PSObject.Properties).Count
Write-Output "nested_inner_process_lineage_evidence_passed release=$($Release.IsPresent) files=$fileCount replays=$($manifest.replay_count) identities=$($manifest.operational_identity_count) denials=$($manifest.capability_denial_count) unresolved=$($manifest.unresolved_truth_count) refusals=5 effects=0"
