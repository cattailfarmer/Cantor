param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/formation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

function Assert-Equal($Actual, $Expected, [string]$Name) {
    if ($Actual -cne $Expected) { throw "$Name mismatch" }
}

Assert-Equal $manifest.profile 'cantor-evox2-remote-preflight-one-shot-activation-ceremony-formation-evidence/0.1' 'profile'
Assert-Equal $manifest.canonical_uuid 'd2724a39-56bd-47ae-8787-064a6196dbfb' 'canonical_uuid'
Assert-Equal $manifest.source_snapshot_uuid 'e4929ffa-1c10-451e-ad4d-ddbccc992c52' 'source_snapshot_uuid'
Assert-Equal $manifest.formation_signature_uuid '1feeedea-716a-4b47-ac28-d7e5b7045842' 'formation_signature_uuid'
Assert-Equal $manifest.predecessor_bookend '0674395c78a998ce1c36c714e52bae68d0f83f58' 'predecessor_bookend'
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

$signatureRelative = 'narrative/registries/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0_Satisfaction_Signature.sop'
$bindingPattern = '^  \+ \[artifact_binding\] (?<path>.+) bytes(?<bytes>\d+) SHA256 (?<sha>[A-F0-9]{64})$'
$bindings = @{}
foreach ($line in (Get-Content -LiteralPath (Join-Path $rootPath $signatureRelative))) {
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
$expectedCounts = @{
    artifact_count=21; signature_binding_count=20; requirements=24; acceptance=5; profiles=6; roles=8; stages=8; argument_atoms=19
    timeout_millis=30000; maximum_stdout_bytes=65536; maximum_stderr_bytes=65536; maximum_attempts=1; maximum_permits=1
    maximum_active_processes=1; maximum_total_processes=1; retry_count=0; formation_permits_minted=0; formation_runner_invocations=0
    provider_requests=0; remote_calls=0; effects=0; synthetic_trials=0
}
foreach ($key in $expectedCounts.Keys) {
    if ([int64]$v.$key -ne [int64]$expectedCounts[$key]) { throw "verification count mismatch $key" }
}
foreach ($key in @('work_slice_language_is_operator_decision','formation_publication_is_operator_decision','fixture_success_is_operator_decision','permit_returned_after_failure','terminal_has_outgoing_edge','permit_bridge_authorized_by_formation','live_invocation_authorized_by_formation')) {
    if ($v.$key -ne $false) { throw "false invariant promoted $key" }
}
foreach ($key in @('permit_consumed_before_runner','pure_implementation_only_after_bookend')) {
    if ($v.$key -ne $true) { throw "true invariant missing $key" }
}
$expectedText = @{
    target_host='EVO-X2'; ssh_host='evo-x2'; executable_path='C:/Windows/System32/OpenSSH/ssh.exe'
    runner_implementation_commit='0eb334670d825ea7123beb445df1a47e1bc81349'; runner_bookend_commit='0674395c78a998ce1c36c714e52bae68d0f83f58'
    producer_implementation_commit='606588a6dd542b31816d116abf909f50d0881937'; producer_bookend_commit='b48c4d7ac48e51aaf70f179cc7b1cdd15e9d5bd0'
    controller_request_sha256='e7dffae6d82cda84e9dd13d77d7d95ba2e403561e511dc7bfb9299b25ae79c8d'
    controller_plan_sha256='975e1dc17d8f0b678f76c5f8d74bb795c3f09b3cff31a57a0c3af29b39981c97'
    controller_program_sha256='b8a832656aa3739ac87daffa81858b184b2eddf8c849d2a7f439926611521992'
}
foreach ($key in $expectedText.Keys) { Assert-Equal $v.$key $expectedText[$key] $key }

$specPath = Join-Path $rootPath 'specifications/Cantor_EVO_X2_Remote_Preflight_One_Shot_Activation_Ceremony_P0.sop'
$spec = Get-Content -LiteralPath $specPath
if (@($spec | Where-Object { $_ -match '^  \+ \[ERPAOC-\d{3}\]' }).Count -ne 24) { throw 'spec requirement count mismatch' }
if (@($spec | Where-Object { $_ -match '^  \+ \[ERPAOC-A\d{2}\]' }).Count -ne 5) { throw 'spec acceptance count mismatch' }
$specRaw = $spec -join "`n"
foreach ($token in @(
    'proposal_compiler publication_verifier operator_principal decision_verifier permit_issuer runner_executor receipt_verifier terminal_recorder',
    'AC1 none AC2 AC1 AC3 AC2 AC4 AC3 AC5 AC4 AC6 AC5 AC7 AC6 AC8 AC7',
    'consume that permit before entering the existing runner exactly once',
    'attempts1 permits1 processes1 retries0',
    'completed_available completed_provider_unavailable rejected refused expired abandoned_after_consumption and receipt_refused',
    'this SJS signature is not operator consent'
)) {
    if (-not $specRaw.Contains($token) -and $token -ne 'this SJS signature is not operator consent') { throw "spec token missing $token" }
}
$signatureRaw = Get-Content -LiteralPath (Join-Path $rootPath $signatureRelative) -Raw
if (-not $signatureRaw.Contains('this SJS signature is not operator consent')) { throw 'signature nonauthority missing' }

'cantor_evox2_remote_preflight_one_shot_activation_ceremony_p0_formation_verified=true artifacts=21 bindings=20 requirements=24 acceptance=5 profiles=6 roles=8 stages=8 attempts=1 permits=1 processes=1 retries=0 formation_permits=0 runner_invocations=0 provider_requests=0 remote_calls=0 effects=0 synthetic_trials=0'
