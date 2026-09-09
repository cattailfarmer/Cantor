param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments/evox2_scratch_build_executor_p0/formation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

function Assert-Equal($Actual, $Expected, [string]$Name) {
    if ($Actual -cne $Expected) { throw "$Name mismatch" }
}

Assert-Equal $manifest.profile 'cantor-evox2-scratch-build-executor-formation-evidence/0.1' 'profile'
Assert-Equal $manifest.canonical_uuid '935e020f-8c6f-49e4-b355-63eabd3b778b' 'canonical_uuid'
Assert-Equal $manifest.source_snapshot_uuid 'dda127bc-1438-4cfa-bc81-ab05655bde68' 'source_snapshot_uuid'
Assert-Equal $manifest.formation_signature_uuid '610fe633-34ec-40a5-a95c-170d0cffb3c1' 'formation_signature_uuid'
Assert-Equal $manifest.source_custody_commit '64f5af8c79453778ef455b4d493128b95668a629' 'source_custody_commit'
Assert-Equal $manifest.source_bookend_commit 'e317cc9e7a651afe8d999db433767139e0c97460' 'source_bookend_commit'
Assert-Equal $manifest.predecessor_bookend_commit 'a49ff0b6ab8675c7cf374616a2b2f76495bba18b' 'predecessor_bookend_commit'
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

$signatureRelative = 'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Satisfaction_Signature.sop'
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
    artifact_count = 21; signature_binding_count = 20; requirements = 32; acceptance = 5
    commission_fields = 21; bounds_fields = 9; cargo_environment_fields = 6; operation_ordinals = 7
    authority_grants = 5; authority_denials = 14; requested_checks = 4; toolchain_observation_fields = 11
    operation_record_fields = 20; receipt_fields = 20; maximum_archive_bytes = 268435456; maximum_files = 16384
    minimum_free_bytes = 103079215104; maximum_target_bytes = 68719476736
    maximum_stdout_bytes = 16777216; maximum_stderr_bytes = 16777216
    maximum_process_seconds = 7200; maximum_total_seconds = 36000; cargo_build_jobs = 1; provider_requests = 0
}
foreach ($key in $expected.Keys) {
    if ([int64]$v.$key -ne [int64]$expected[$key]) { throw "verification count mismatch $key" }
}
Assert-Equal $v.target_host 'EVO-X2' 'target_host'
Assert-Equal $v.workspace_root 'C:/AI/workspaces/cantor-build-4fdd29cb' 'workspace_root'
Assert-Equal $v.target_root 'C:/AI/builds/cantor-build-4fdd29cb' 'target_root'
Assert-Equal $v.source_commit '4fdd29cb7e76ddd827bcc7ceb8ca36ab28864271' 'source_commit'
Assert-Equal $v.source_archive_sha256 '162a82f42619249a11a81ce64c29889eb5cd448a2d3d864ccb5bf26f1b0f325d' 'source_archive_sha256'
if ($v.remote_effects_authorized_before_implementation_publication -ne $false -or $v.physical_build_authorized_by_formation -ne $false -or $v.cleanup_authorized -ne $false -or $v.repeat_authorized -ne $false -or $v.autonomous_work_authorized -ne $false) { throw 'authority promotion admitted' }
if ($v.implementation_authorized_after_publication -ne $true) { throw 'implementation publication phase missing' }

$specPath = Join-Path $rootPath 'specifications/Cantor_EVO_X2_Scratch_Build_Executor_P0.sop'
$spec = Get-Content -LiteralPath $specPath
if (@($spec | Where-Object { $_ -match '^  \+ \[ESBE-\d{3}\]' }).Count -ne 32) { throw 'spec requirement count mismatch' }
if (@($spec | Where-Object { $_ -match '^  \+ \[ESBE-A\d{2}\]' }).Count -ne 5) { throw 'spec acceptance count mismatch' }
$specRaw = $spec -join "`n"
foreach ($token in @(
    'commission21 bounds9 cargo_environment6 operation_ordinals7 authority_grants5 authority_denials14 requested_checks4 toolchain_observation11 operation_record20 receipt20',
    'verify_source_archive materialize_absent_workspace workspace_debug workspace_release workspace_clippy workspace_format seal_build_receipt',
    'source_transfer source_extract toolchain_observe workspace_write process_execute',
    'C:/AI/workspaces/cantor-build-4fdd29cb',
    'C:/AI/builds/cantor-build-4fdd29cb',
    'stop before every later operation',
    'prohibit repeat execution cleanup toolchain install dependency download Git mutation provider model service policy persistence self-update production external fallback and autonomous work'
)) {
    if (-not $specRaw.Contains($token)) { throw "spec token missing $token" }
}

$sourcePath = Join-Path $rootPath 'source_documents/2026-09-08_evox2_scratch_build_executor_p0/EVO_X2_Scratch_Build_Executor_P0_Source.sop'
if ((Get-Item $sourcePath).Length -ne 9945 -or (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -cne '62FDB942F1A31E499B0B0DE2EE50940B9797DED75304F35CAF91ED974012DB8B') { throw 'source drift' }

'cantor_evox2_scratch_build_executor_p0_formation_verified=true artifacts=21 signature_bindings=20 requirements=32 acceptance=5 commission=21 bounds=9 environment=6 ordinals=7 grants=5 denials=14 checks=4 toolchain=11 operation_record=20 receipt=20 provider_requests=0 remote_effects=0'
