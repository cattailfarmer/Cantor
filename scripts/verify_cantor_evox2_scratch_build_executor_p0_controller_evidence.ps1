[CmdletBinding()]
param([string] $Root = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\controller_implementation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-evox2-scratch-build-deployment-controller-evidence/0.1' -or $manifest.manifest_uuid -cne '3bca5072-b945-4861-85ba-542e097f64ec' -or $manifest.canonical_uuid -cne '935e020f-8c6f-49e4-b355-63eabd3b778b' -or $manifest.package_evidence_commit -cne '4dc154234cd88c192495126a4374d74616ca0c3f' -or $manifest.package_evidence_bookend_commit -cne '9e583948ea6c1f52604862c354e99d8ccb1195ba' -or $manifest.package_implementation_commit -cne 'f5b904fc8cf48b34672dead0596e9de6e706f38b' -or $manifest.package_set_sha256 -cne 'fed126ed060edfc3bccb0d3d7e6ed7dd27048a976753b5c2e23c0da45511030e' -or $manifest.controller_implementation_commit -cne 'c0fd8175a6fba0f61a53868b2660bc361dadb96c') { throw 'controller evidence identity differs' }
if (@($manifest.artifacts).Count -ne 28) { throw 'controller evidence artifact count differs' }
$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string] $artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or $relative -match '(^|/)\.\.(/|$)') { throw 'controller artifact coordinate differs' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'controller artifact duplicate coordinate' }
    $seen[$key] = $true
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [int64] $item.Length -ne [int64] $artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string] $artifact.sha256) { throw "controller artifact identity differs: $relative" }
}
function Get-TextSha256([string] $Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}
function Get-OneLine([string] $Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $raw = $utf8.GetString($bytes)
    if (-not $raw.EndsWith("`n", [StringComparison]::Ordinal) -or $raw.EndsWith("`n`n", [StringComparison]::Ordinal)) { throw 'controller fixture line framing differs' }
    $value = $raw.Substring(0, $raw.Length - 1)
    if ($value.Contains("`r") -or $value.Contains("`n")) { throw 'controller fixture is not one LF-framed line' }
    $value
}
$fixture = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\controller_fixture'
$requestRaw = Get-OneLine (Join-Path $fixture 'request.json')
$planRaw = Get-OneLine (Join-Path $fixture 'plan.json')
$verificationRaw = Get-OneLine (Join-Path $fixture 'verification.json')
$request = $requestRaw | ConvertFrom-Json
$plan = $planRaw | ConvertFrom-Json
$verification = $verificationRaw | ConvertFrom-Json
$requestDigestToken = '"request_sha256":"' + [string] $request.request_sha256 + '"'
$unsignedRequest = $requestRaw.Replace($requestDigestToken, '"request_sha256":""')
if ($unsignedRequest -ceq $requestRaw -or (Get-TextSha256 ('cantor-evox2-scratch-build-deployment-controller-request-v1' + [char]0 + $unsignedRequest)) -cne [string] $request.request_sha256) { throw 'controller request digest differs' }
$planDigestToken = '"plan_sha256":"' + [string] $plan.plan_sha256 + '"'
$unsignedPlan = $planRaw.Replace($planDigestToken, '"plan_sha256":""')
if ($unsignedPlan -ceq $planRaw -or (Get-TextSha256 ('cantor-evox2-scratch-build-deployment-controller-plan-v1' + [char]0 + $unsignedPlan)) -cne [string] $plan.plan_sha256) { throw 'controller plan digest differs' }
$run = '61927fc8-5c08-4a78-9993-df1dc975db56'
$expectedKinds = @('local_package_verify', 'publication_lineage_verify', 'remote_preflight', 'transfer_package', 'remote_package_verify', 'atomic_service_install', 'execute_commission_once', 'retrieve_evidence', 'independent_local_verify', 'cleanup_transient_transport')
if ($request.run_uuid -cne $run -or $request.package_evidence_commit -cne '4dc154234cd88c192495126a4374d74616ca0c3f' -or $request.package_evidence_bookend_commit -cne '9e583948ea6c1f52604862c354e99d8ccb1195ba' -or $request.package_implementation_commit -cne 'f5b904fc8cf48b34672dead0596e9de6e706f38b' -or $request.package_set_sha256 -cne 'fed126ed060edfc3bccb0d3d7e6ed7dd27048a976753b5c2e23c0da45511030e' -or $request.ssh_host -cne 'evo-x2' -or $request.local_evidence_root -cne "D:/CantorBuilds/evox2-scratch-build-executor-p0-live-$run" -or $request.remote_transport_archive -cne "C:/AI/transport/cantor-scratch-build-transport-$run.zip" -or $request.remote_stage_root -cne "C:/AI/services/cantor-scratch-build-staging-$run") { throw 'controller request fixture differs' }
if (@($plan.stages).Count -ne 10 -or [int] $plan.stage_count -ne 10 -or [string] $plan.request_sha256 -cne [string] $request.request_sha256 -or [string] $plan.provider_unavailable_disposition -cne 'operational_refusal_before_commission_no_receipt' -or [string] $plan.cleanup_condition -cne 'transient_transport_only_after_local_evidence_verification' -or [string] $plan.authority_disposition -cne 'descriptive_not_authorizing' -or [bool] $plan.remote_contact_authorized -or [int] $plan.effects -ne 0) { throw 'controller plan fixture differs' }
for ($index = 0; $index -lt 10; $index++) { if ([int] $plan.stages[$index].ordinal -ne ($index + 1) -or [string] $plan.stages[$index].kind -cne $expectedKinds[$index] -or -not [bool] $plan.stages[$index].stop_on_failure) { throw 'controller stage sequence differs' } }
if ($verification.status -cne 'passed' -or $verification.request_sha256 -cne $request.request_sha256 -or $verification.plan_sha256 -cne $plan.plan_sha256 -or [int] $verification.stage_count -ne 10 -or [int] $verification.effectful_stage_count -ne 7 -or [bool] $verification.remote_contact_authorized -or [int] $verification.effects -ne 0) { throw 'controller verification fixture differs' }
$expected = @{ artifact_count = 28; focused_tests = 8; stage_count = 10; effectful_stage_count = 7; isolated_successes = 1; isolated_refusals = 4; provider_requests = 0; remote_calls = 0; effects = 0 }
foreach ($name in $expected.Keys) { if ([int] $manifest.verification.$name -ne [int] $expected[$name]) { throw "controller evidence count differs: $name" } }
if ([bool] $manifest.verification.remote_contact_authorized) { throw 'controller evidence authority differs' }
if (-not [bool] $manifest.verification.controller_plan_published -or -not [bool] $manifest.verification.controller_plan_bookended -or -not [bool] $manifest.verification.effect_wrapper_implementation_authorized) { throw 'controller publication phase differs' }
"cantor_evox2_scratch_build_controller_evidence_verified=true artifacts=28 focused_tests=8 stages=10 effectful_stages=7 isolated_successes=1 isolated_refusals=4 provider_requests=0 remote_calls=0 remote_contact_authorized=false controller_plan_published=true controller_plan_bookended=true effect_wrapper_implementation_authorized=true effects=0"
