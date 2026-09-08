param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments/evox2_plan_only_build_job_p0/formation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

function Assert-Equal($Actual, $Expected, [string]$Name) {
    if ($Actual -cne $Expected) { throw "$Name mismatch" }
}

Assert-Equal $manifest.profile 'cantor-evox2-plan-only-build-job-formation-evidence/0.1' 'profile'
Assert-Equal $manifest.canonical_uuid '3482e2ce-817c-4788-b185-35adaad414f7' 'canonical_uuid'
Assert-Equal $manifest.source_snapshot_uuid 'e0045953-7c43-47bd-8c83-f40b8ff84cf5' 'source_snapshot_uuid'
Assert-Equal $manifest.formation_signature_uuid '58968a69-538e-43ee-85db-3401765d1fd4' 'formation_signature_uuid'
Assert-Equal $manifest.source_custody_commit '995174641296e1bc7b887a997905b651cb087e30' 'source_custody_commit'
Assert-Equal $manifest.source_bookend_commit '30aa91c58116727a3e285a748bd6805d71f0f7f1' 'source_bookend_commit'
if (@($manifest.artifacts).Count -ne 21) { throw 'artifact_count mismatch' }

$seen = @{}
foreach ($artifact in $manifest.artifacts) {
    $relative = [string]$artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\/])\.\.([\/]|$)') { throw 'nonportable artifact path' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'duplicate artifact path' }
    $seen[$key] = $true
    $path = Join-Path $rootPath $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "missing artifact $relative" }
    $item = Get-Item -LiteralPath $path
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "linked artifact $relative" }
    if ($item.Length -ne [int64]$artifact.bytes) { throw "byte mismatch $relative" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne [string]$artifact.sha256) { throw "hash mismatch $relative" }
    if ($relative -like 'crates/*' -or $relative -like '*.rs') { throw 'implementation artifact admitted into formation' }
}

$signatureRelative = 'narrative/registries/Cantor_EVO_X2_Plan_Only_Build_Job_P0_Satisfaction_Signature.sop'
$signature = Get-Content -LiteralPath (Join-Path $rootPath $signatureRelative)
$bindingPattern = '^  \+ \[artifact_binding\] (?<path>.+) bytes(?<bytes>\d+) SHA256 (?<sha>[A-F0-9]{64})$'
$bindings = @{}
foreach ($line in $signature) {
    if ($line -match $bindingPattern) { $bindings[$Matches.path] = @([int64]$Matches.bytes, $Matches.sha) }
}
if ($bindings.Count -ne 20) { throw 'signature binding count mismatch' }
foreach ($artifact in $manifest.artifacts) {
    if ($artifact.path -ceq $signatureRelative) { continue }
    if (-not $bindings.ContainsKey([string]$artifact.path)) { throw "missing signature binding $($artifact.path)" }
    $binding = $bindings[[string]$artifact.path]
    if ($binding[0] -ne [int64]$artifact.bytes -or $binding[1] -cne [string]$artifact.sha256) { throw "signature binding mismatch $($artifact.path)" }
}

$v = $manifest.verification
$expected = @{
    artifact_count = 21; signature_binding_count = 20; requirements = 28; acceptance = 5
    request_fields = 16; bounds_fields = 6; plan_fields = 20; cargo_environment_fields = 5
    operation_fields = 12; requested_checks = 4; operations = 7; authority_denials = 15
    authority_grants = 0; unresolved = 5; maximum_request_bytes = 65536; maximum_plan_bytes = 1048576
    maximum_archive_bytes = 536870912; maximum_files = 32768; maximum_timeout_seconds = 14400
    cargo_build_jobs = 1; provider_requests = 0; effects = 0
}
foreach ($key in $expected.Keys) {
    if ([int64]$v.$key -ne [int64]$expected[$key]) { throw "verification count mismatch $key" }
}
Assert-Equal $v.target_host 'EVO-X2' 'target_host'
Assert-Equal $v.remote_root 'C:/AI/services/cantor-build-planner-d805681d' 'remote_root'
if ($v.remote_effects_authorized_before_implementation_publication -ne $false -or $v.physical_build_authorized -ne $false -or $v.autonomous_work_authorized -ne $false) { throw 'authority promotion admitted' }
if ($v.implementation_authorized_after_publication -ne $true) { throw 'implementation publication phase missing' }

$specPath = Join-Path $rootPath 'specifications/Cantor_EVO_X2_Plan_Only_Build_Job_P0.sop'
$spec = Get-Content -LiteralPath $specPath
if (@($spec | Where-Object { $_ -match '^  \+ \[EBJP-\d{3}\]' }).Count -ne 28) { throw 'spec requirement count mismatch' }
if (@($spec | Where-Object { $_ -match '^  \+ \[EBJP-A\d{2}\]' }).Count -ne 5) { throw 'spec acceptance count mismatch' }
$specRaw = $spec -join "`n"
foreach ($token in @(
    'request16 bounds6 plan20 cargo_environment5 operation12 requested_checks4 operations7 denials15 unresolved5 authority_grants0',
    'verify_source_archive materialize_absent_workspace workspace_debug workspace_release workspace_clippy workspace_format seal_build_receipt',
    'C:/AI/services/cantor-build-planner-d805681d',
    'authority grants exact denials exact five unresolved facts and planned_effectless disposition',
    'source transfer extraction workspace toolchain dependency Cargo Git provider model service persistence self-update'
)) {
    if (-not $specRaw.Contains($token)) { throw "spec token missing $token" }
}

$sourcePath = Join-Path $rootPath 'source_documents/2026-09-08_evox2_plan_only_build_job_p0/EVO_X2_Plan_Only_Build_Job_P0_Source.sop'
if ((Get-Item $sourcePath).Length -ne 9010 -or (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -cne 'E514DA76F593C42EAF7F6FCDF4A7676B0DD257ADE5C8BA310A7929B21130627D') { throw 'source drift' }

'cantor_evox2_plan_only_build_job_p0_formation_verified=true artifacts=21 signature_bindings=20 requirements=28 acceptance=5 request=16 bounds=6 plan=20 environment=5 operation=12 checks=4 operations=7 denials=15 grants=0 unresolved=5 provider_requests=0 effects=0'
