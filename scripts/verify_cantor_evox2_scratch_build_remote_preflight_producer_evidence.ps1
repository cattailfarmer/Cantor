[CmdletBinding()]
param(
    [string] $Root = '',
    [switch] $RequireExactGates
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$manifestPath = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\preflight_producer_implementation_evidence_manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne 'cantor-evox2-scratch-build-remote-preflight-producer-evidence/0.1' -or $manifest.manifest_uuid -cne 'af086146-9dab-4519-b1ba-26f370cb7e28' -or $manifest.canonical_uuid -cne '935e020f-8c6f-49e4-b355-63eabd3b778b' -or $manifest.source_uuid -cne 'fa3dbac1-04b8-4f10-a8a4-bb382bf1201f' -or $manifest.design_uuid -cne 'd762e7c4-f8da-4cce-86e1-0f1cf7544ec9' -or $manifest.predecessor_bookend -cne '047674f26b4f9cb576fd93524d710d91e0e48b51' -or $manifest.observation_compiler_implementation_commit -cne '000fef93cadce29b2e0ce59e668ac72ca2e2a9ad' -or $manifest.observation_compiler_bookend_commit -cne '047674f26b4f9cb576fd93524d710d91e0e48b51') { throw 'producer evidence identity differs' }
if (@($manifest.artifacts).Count -ne 25) { throw 'producer evidence artifact count differs' }
$seen = @{}
foreach ($artifact in @($manifest.artifacts)) {
    $relative = [string] $artifact.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or $relative -match '(^|/)\.\.(/|$)') { throw 'producer artifact coordinate differs' }
    $key = $relative.ToUpperInvariant()
    if ($seen.ContainsKey($key)) { throw 'producer artifact duplicate coordinate' }
    $seen[$key] = $true
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [int64] $item.Length -ne [int64] $artifact.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string] $artifact.sha256) { throw "producer artifact identity differs: $relative" }
}
function Get-TextSha256([string] $Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}
function Get-OneLine([string] $Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    if (-not $raw.EndsWith("`n", [StringComparison]::Ordinal) -or $raw.EndsWith("`n`n", [StringComparison]::Ordinal)) { throw 'producer fixture line framing differs' }
    $value = $raw.Substring(0, $raw.Length - 1)
    if ($value.Contains("`r") -or $value.Contains("`n")) { throw 'producer fixture is not one LF-framed line' }
    $value
}
$producerPlanRaw = Get-OneLine (Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\preflight_producer_fixture\producer_plan.json')
$producerPlan = $producerPlanRaw | ConvertFrom-Json
$digest = [string] $producerPlan.producer_plan_sha256
$unsigned = $producerPlanRaw.Replace(('"producer_plan_sha256":"' + $digest + '"'), '"producer_plan_sha256":""')
if ($unsigned -ceq $producerPlanRaw -or (Get-TextSha256 ('cantor-evox2-scratch-build-remote-preflight-producer-plan-v1' + [char]0 + $unsigned)) -cne $digest) { throw 'producer plan digest differs' }
if ($producerPlan.profile -cne 'cantor-evox2-scratch-build-remote-preflight-producer-plan/0.1' -or $producerPlan.observation_compiler_implementation_commit -cne '000fef93cadce29b2e0ce59e668ac72ca2e2a9ad' -or $producerPlan.observation_compiler_bookend_commit -cne '047674f26b4f9cb576fd93524d710d91e0e48b51' -or $producerPlan.target_host -cne 'EVO-X2' -or $producerPlan.ssh_host -cne 'evo-x2' -or $producerPlan.transport -cne 'openssh_native_bounded_single_call' -or $producerPlan.executable_path -cne 'C:/Windows/System32/OpenSSH/ssh.exe' -or $producerPlan.executable_sha256 -cne ('a' * 64) -or [int] $producerPlan.argument_count -ne 19 -or @($producerPlan.argument_atoms).Count -ne 19 -or [int64] $producerPlan.timeout_ms -ne 30000 -or [int] $producerPlan.stdout_limit_bytes -ne 65536 -or [int] $producerPlan.stderr_limit_bytes -ne 65536 -or [int] $producerPlan.provider_request_limit -ne 0 -or [int] $producerPlan.remote_call_limit -ne 1 -or [int] $producerPlan.effect_limit -ne 1 -or $producerPlan.authority_disposition -cne 'producer_contract_only_live_invocation_not_authorized' -or [bool] $producerPlan.remote_contact_authorized) { throw 'producer plan semantics differ' }
$expectedPrefix = @('-o','BatchMode=yes','-o','ConnectTimeout=15','-o','ConnectionAttempts=1','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','evo-x2','powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-EncodedCommand')
for ($index = 0; $index -lt $expectedPrefix.Count; $index++) { if ([string] $producerPlan.argument_atoms[$index] -cne $expectedPrefix[$index]) { throw "producer argument atom differs: $index" } }
$payload = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String([string] $producerPlan.argument_atoms[18]))
foreach ($required in @("`$env:COMPUTERNAME -ne 'EVO-X2'", 'target_host_mismatch', '127.0.0.1', 'Qwen3.5-0.8B-Q4_0.gguf', 'cantor-evox2-scratch-build-remote-probe-result-v1', '[Console]::Out.Write')) { if (-not $payload.Contains($required)) { throw "producer payload surface differs: $required" } }
foreach ($forbidden in @('Invoke-WebRequest', 'Invoke-RestMethod', 'Start-Process', 'New-Item', 'Set-Content', 'Remove-Item', 'Copy-Item', 'Move-Item', 'Expand-Archive')) { if ($payload.Contains($forbidden)) { throw "producer payload effect boundary differs: $forbidden" } }
$moduleRaw = Get-Content -LiteralPath (Join-Path $rootPath 'crates\cantor_core\src\evox2_scratch_build_remote_preflight_producer.rs') -Raw
$cliRaw = Get-Content -LiteralPath (Join-Path $rootPath 'crates\cantor_core\src\bin\cantor-evox2-scratch-build-preflight-producer-verify.rs') -Raw
$testsRaw = Get-Content -LiteralPath (Join-Path $rootPath 'crates\cantor_core\tests\evox2_scratch_build_remote_preflight_producer.rs') -Raw
foreach ($required in @('Evox2ScratchBuildRemotePreflightProducerPlan', 'Evox2ScratchBuildRemotePreflightProcessRecord', 'compile_evox2_scratch_build_remote_preflight_observation_from_process_record', 'producer_contract_only_live_invocation_not_authorized')) { if ($moduleRaw -cnotmatch [regex]::Escape($required)) { throw "producer module surface differs: $required" } }
foreach ($forbidden in @('std::process', 'std::fs', 'std::env', 'TcpStream', 'Command::new', 'SshSession', 'reqwest')) { if ($moduleRaw.Contains($forbidden)) { throw "producer pure-module boundary differs: $forbidden" } }
if ($cliRaw -cnotmatch 'compile' -or $cliRaw -cnotmatch 'verify' -or $testsRaw -cnotmatch 'fresh_process_cli_replays_plan_compile_and_verify' -or $testsRaw -cnotmatch 'executable_identity_and_each_argument_atom_are_bound' -or $testsRaw -cnotmatch 'timeout_exit_truncation_and_accounting_drift_refuse_before_compilation' -or $testsRaw -cnotmatch 'raw_stream_argument_and_nested_probe_tamper_refuse') { throw 'producer executable evidence differs' }
$expected = @{ artifact_count = 25; focused_tests = 9; argument_atoms = 19; timeout_ms = 30000; stdout_limit_bytes = 65536; stderr_limit_bytes = 65536; provider_requests_performed = 0; remote_calls_performed = 0; effects_performed = 0 }
foreach ($name in $expected.Keys) { if ([int64] $manifest.verification.$name -ne [int64] $expected[$name]) { throw "producer evidence count differs: $name" } }
if ([bool] $manifest.verification.remote_contact_authorized -or -not [bool] $manifest.verification.evidence_is_fixture) { throw 'producer evidence authority differs' }
if ($RequireExactGates -and -not [bool] $manifest.verification.exact_workspace_gates_passed) { throw 'producer exact workspace gates remain open' }
"cantor_evox2_scratch_build_remote_preflight_producer_evidence_verified=true artifacts=25 focused_tests=9 argument_atoms=19 provider_requests_performed=0 remote_calls_performed=0 effects_performed=0 remote_contact_authorized=false exact_gates=$([bool] $manifest.verification.exact_workspace_gates_passed)"
