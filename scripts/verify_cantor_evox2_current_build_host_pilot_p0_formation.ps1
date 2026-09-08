param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments/evox2_current_build_host_pilot_p0/formation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

function Assert-Equal($Actual, $Expected, [string]$Name) {
    if ($Actual -cne $Expected) { throw "$Name mismatch" }
}

Assert-Equal $manifest.profile 'cantor-evox2-current-build-host-pilot-formation-evidence/0.1' 'profile'
Assert-Equal $manifest.canonical_uuid '4cf12917-73e8-4505-9228-f94d981143bd' 'canonical_uuid'
Assert-Equal $manifest.source_snapshot_uuid 'cd4a7cf3-dfd8-4615-bd14-d2644bc7420c' 'source_snapshot_uuid'
Assert-Equal $manifest.formation_signature_uuid 'cf0e7348-5135-41b6-9ae5-5d5bfa5c84c7' 'formation_signature_uuid'
Assert-Equal $manifest.source_custody_commit '5ec240b0713e25cc4fd59148fff7a464efabf3bb' 'source_custody_commit'
Assert-Equal $manifest.source_bookend_commit '8f6d4de59c85425645a96ad632e376adda82004a' 'source_bookend_commit'
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

$signatureRelative = 'narrative/registries/Cantor_EVO_X2_Current_Build_Host_Pilot_P0_Satisfaction_Signature.sop'
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
    artifact_count = 21; signature_binding_count = 20; requirements = 28; acceptance = 6
    deployment_manifest_fields = 12; artifact_fields = 6; remote_receipt_fields = 24
    replay_fields = 8; refusal_fields = 4; protected_roots = 3; allowed_executions = 2
    maximum_files = 128; maximum_file_bytes = 67108864; maximum_aggregate_bytes = 1073741824
    required_replays = 2; provider_requests = 0; persistent_process_count = 0; listener_delta = 0
}
foreach ($key in $expected.Keys) {
    if ([int64]$v.$key -ne [int64]$expected[$key]) { throw "verification count mismatch $key" }
}
Assert-Equal $v.target_host 'EVO-X2' 'target_host'
Assert-Equal $v.remote_root 'C:/AI/services/cantor-current-pilot-48479932' 'remote_root'
if ($v.configuration_changed -ne $false -or $v.live_effects_authorized_before_implementation_publication -ne $false -or $v.autonomous_workspace_mutation_authorized -ne $false) { throw 'authority promotion admitted' }
if ($v.implementation_authorized_after_publication -ne $true) { throw 'implementation publication phase missing' }

$specPath = Join-Path $rootPath 'specifications/Cantor_EVO_X2_Current_Build_Host_Pilot_P0.sop'
$spec = Get-Content -LiteralPath $specPath
if (@($spec | Where-Object { $_ -match '^  \+ \[ECHP-\d{3}\]' }).Count -ne 28) { throw 'spec requirement count mismatch' }
if (@($spec | Where-Object { $_ -match '^  \+ \[ECHP-A\d{2}\]' }).Count -ne 6) { throw 'spec acceptance count mismatch' }
$specRaw = $spec -join "`n"
foreach ($token in @(
    'deployment_manifest12 artifact6 remote_receipt24 replay8 refusal4 protected_roots3 allowed_executions2 maximum_files128',
    'C:/AI/services/cantor-current-pilot-48479932',
    'a8_evidence_replay and optional_cantor_public_query_replay',
    'configuration_changed=false listener_delta=0 persistent_process_count=0',
    'workspace mutation commit push self-update'
)) {
    if (-not $specRaw.Contains($token)) { throw "spec token missing $token" }
}

$sourcePath = Join-Path $rootPath 'source_documents/2026-09-08_evox2_current_build_host_pilot_p0/EVO_X2_Current_Build_Host_Pilot_P0_Source.sop'
if ((Get-Item $sourcePath).Length -ne 11071 -or (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash -cne '6F8AF368A9C6CA1B43F1CC3213AD2CC4709103AB8AC43C7A7FCD79575D9243A7') { throw 'source drift' }

'cantor_evox2_current_build_host_pilot_p0_formation_verified=true artifacts=21 signature_bindings=20 requirements=28 acceptance=6 manifest=12 artifact=6 receipt=24 replay=8 refusal=4 protected_roots=3 executions=2 replays=2 provider_requests=0 persistent_processes=0 listener_delta=0'
