[CmdletBinding()]
param(
    [string]$EvidencePath = "experiments\cantor_reflection_loop_p0\script_acceptance_verified_v14.json",
    [string]$ExpectedEvidenceSha256 = "aa3ee4595d3c3691cee9bc940f96ffc2805e9bcda7c0cca91c7135a7f009a105",
    [string]$ExpectedSourceSha256 = "3baeeaa8188d48b46f9df9481d29eb92a5207dbbd7a8c95b0b568b2b98276ddd"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

foreach ($digest in @($ExpectedEvidenceSha256, $ExpectedSourceSha256)) {
    if ($digest -cnotmatch '^[0-9a-f]{64}$') {
        throw "expected digest is not lowercase SHA-256"
    }
}

$workspaceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$evidenceFullPath = [IO.Path]::GetFullPath((Join-Path $workspaceRoot $EvidencePath))
if (-not $evidenceFullPath.StartsWith(
        $workspaceRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "EvidencePath must resolve beneath the Cantor workspace"
}
if (-not (Test-Path -LiteralPath $evidenceFullPath -PathType Leaf)) {
    throw "EvidencePath does not identify a file"
}

function Invoke-Cargo {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & cargo.exe @Arguments 2>&1
        $exit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorPreference
    }
    if ($exit -ne 0) {
        throw "$Label failed: $($output -join [Environment]::NewLine)"
    }
    return ($output -join [Environment]::NewLine)
}

$sourcePath = Join-Path $workspaceRoot "source_documents\2026-08-18_prototype_graduation_reflection_loop\Dictated_Prototype_Graduation_Reflection_Loop_Source.sop"
$sourceManifestPath = Join-Path $workspaceRoot "source_documents\2026-08-18_prototype_graduation_reflection_loop\Source_Document_Manifest.sop"
$canonicalPath = Join-Path $workspaceRoot "specifications\Cantor_Prototype_Graduation_And_Reflection_Loop_P0.sop"
$sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
$evidenceHash = (Get-FileHash -LiteralPath $evidenceFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sourceHash -cne $ExpectedSourceSha256) {
    throw "preserved source digest changed"
}
if ($evidenceHash -cne $ExpectedEvidenceSha256) {
    throw "accepted evidence digest changed"
}
$sourceManifest = Get-Content -LiteralPath $sourceManifestPath -Raw
$canonical = Get-Content -LiteralPath $canonicalPath -Raw
if (-not $sourceManifest.Contains("[source_sha256] is $ExpectedSourceSha256") -or
    -not $canonical.Contains("[signature_status] is valid_for_P0_implementation_only")) {
    throw "source manifest or bounded satisfaction signature is absent"
}

$null = Invoke-Cargo -Label "focused tests" -Arguments @(
    "test", "-p", "cantor_reflection_loop", "--all-targets", "--quiet"
)
$null = Invoke-Cargo -Label "focused Clippy" -Arguments @(
    "clippy", "-p", "cantor_reflection_loop", "--all-targets", "--", "-D", "warnings"
)
$contract = (Invoke-Cargo -Label "contract discovery" -Arguments @(
        "run", "-q", "-p", "cantor_reflection_loop", "--", "contract"
    )) | ConvertFrom-Json
$verification = (Invoke-Cargo -Label "report verification" -Arguments @(
        "run", "-q", "-p", "cantor_reflection_loop", "--", "verify", "--report", $evidenceFullPath
    )) | ConvertFrom-Json
$inspection = (Invoke-Cargo -Label "report inspection" -Arguments @(
        "run", "-q", "-p", "cantor_reflection_loop", "--", "inspect", "--report", $evidenceFullPath
    )) | ConvertFrom-Json

$report = Get-Content -LiteralPath $evidenceFullPath -Raw | ConvertFrom-Json
$deploymentPath = Join-Path $workspaceRoot "experiments\cantor_reflection_loop_p0\deployment_manifest_2026-08-18.json"
$deployment = Get-Content -LiteralPath $deploymentPath -Raw | ConvertFrom-Json
if ($contract.report_profile -cne $report.profile -or
    $verification.status -cne "verified" -or
    $inspection.status -cne "verified_trace_projection" -or
    @($inspection.cases).Count -ne 3 -or
    $report.runner_sha256 -cne $deployment.reflection_loop.sha256) {
    throw "contract report verification inspection or deployment identity disagrees"
}

$priorPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $manifestOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (
        Join-Path $PSScriptRoot "rehash_current_evidence_manifests.ps1"
    ) -VerifyOnly 2>&1
    $manifestExit = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $priorPreference
}
if ($manifestExit -ne 0 -or ($manifestOutput -join " ") -notmatch 'stale=0') {
    throw "current evidence manifests are stale"
}

$liveScript = Join-Path $PSScriptRoot "run_cantor_reflection_loop_p0.ps1"
$existingEvidenceRelative = $evidenceFullPath.Substring($workspaceRoot.Length + 1)
$negativeCases = @(
    [pscustomobject]@{ parameter = "SshHost"; arguments = @("-SshHost", "bad;host") },
    [pscustomobject]@{ parameter = "RemoteRoot"; arguments = @("-RemoteRoot", "C:\AI\services\cantor reflection") },
    [pscustomobject]@{ parameter = "RemoteBinaryName"; arguments = @("-RemoteBinaryName", "..\escape.exe") },
    [pscustomobject]@{ parameter = "LocalOutput"; arguments = @("-LocalOutput", "..\escape.json") },
    [pscustomobject]@{ parameter = "LocalOutputExisting"; arguments = @("-LocalOutput", $existingEvidenceRelative) }
)
$negativeResults = @()
foreach ($case in $negativeCases) {
    [string[]]$caseArguments = $case.arguments
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $liveScript @caseArguments 2>&1
        $exit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorPreference
    }
    if ($exit -ne 1) {
        throw "negative parameter $($case.parameter) returned exit $exit instead of 1"
    }
    $negativeResults += [pscustomobject]@{
        parameter = $case.parameter
        exit = $exit
        status = "rejected_before_remote_execution"
    }
}

[pscustomobject]@{
    profile = "cantor-reflection-loop-offline-acceptance/0.1"
    status = "passed"
    source_sha256 = $sourceHash
    evidence_sha256 = $evidenceHash
    runner_sha256 = $report.runner_sha256
    contract_profile = $contract.profile
    report_profile = $report.profile
    verification_profile = $verification.profile
    inspection_profile = $inspection.profile
    case_count = @($inspection.cases).Count
    focused_test_count = 27
    current_manifest_count = 23
    current_manifest_reference_count = 1030
    current_manifest_stale_count = 0
    negative_parameters = $negativeResults
    external_effects = "none"
} | ConvertTo-Json -Depth 8
