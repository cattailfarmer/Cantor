[CmdletBinding()]
param(
    [string] $Root = '',
    [string] $CargoTargetDir = 'D:\CantorBuilds\evox2-preflight-producer-target',
    [switch] $ExactGatesPassed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
$rootPath = (Resolve-Path -LiteralPath $Root).Path
if (-not (Test-Path -LiteralPath $CargoTargetDir)) { New-Item -ItemType Directory -Path $CargoTargetDir | Out-Null }
$targetPath = (Resolve-Path -LiteralPath $CargoTargetDir).Path
$fixtureRoot = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\preflight_producer_fixture'
if (-not (Test-Path -LiteralPath $fixtureRoot)) { New-Item -ItemType Directory -Path $fixtureRoot | Out-Null }
$temporaryRoot = Join-Path $targetPath ('preflight-producer-input-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
function Get-CanonicalBody([string] $Relative) {
    $raw = [IO.File]::ReadAllText((Join-Path $rootPath $Relative), [Text.UTF8Encoding]::new($false, $true))
    if (-not $raw.EndsWith("`n", [StringComparison]::Ordinal) -or $raw.EndsWith("`n`n", [StringComparison]::Ordinal)) { throw "producer input line framing differs: $Relative" }
    $body = $raw.Substring(0, $raw.Length - 1)
    if ($body.EndsWith("`r", [StringComparison]::Ordinal)) { $body = $body.Substring(0, $body.Length - 1) }
    if ($body.Contains("`r") -or $body.Contains("`n")) { throw "producer input cardinality differs: $Relative" }
    $body
}
try {
    $requestInput = Join-Path $temporaryRoot 'request.json'
    $planInput = Join-Path $temporaryRoot 'plan.json'
    $programInput = Join-Path $temporaryRoot 'program.json'
    [IO.File]::WriteAllText($requestInput, (Get-CanonicalBody 'experiments/evox2_scratch_build_executor_p0/controller_fixture/request.json'), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($planInput, (Get-CanonicalBody 'experiments/evox2_scratch_build_executor_p0/controller_fixture/plan.json'), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($programInput, (Get-CanonicalBody 'experiments/evox2_scratch_build_executor_p0/effect_wrapper_fixture/program.json'), [Text.UTF8Encoding]::new($false))
    $savedTarget = $env:CARGO_TARGET_DIR
    try {
        $env:CARGO_TARGET_DIR = $targetPath
        $arguments = @('run', '--quiet', '--locked', '--offline', '-p', 'cantor_core', '--bin', 'cantor-evox2-scratch-build-preflight-producer-verify', '--', 'plan', $requestInput, $planInput, $programInput, ('a' * 64))
        $planOutput = @(& cargo @arguments)
        if ($LASTEXITCODE -ne 0 -or $planOutput.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string] $planOutput[0])) { throw 'producer plan fixture generation failed' }
    } finally {
        $env:CARGO_TARGET_DIR = $savedTarget
    }
    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'producer_plan.json'), ([string] $planOutput[0] + "`n"), [Text.UTF8Encoding]::new($false))
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}

$paths = @(
    'source_documents/2026-09-11_evox2_scratch_build_remote_preflight_producer/EVO_X2_Scratch_Build_Remote_Preflight_Producer_Source.sop',
    'source_documents/2026-09-11_evox2_scratch_build_remote_preflight_producer/Source_Document_Manifest.sop',
    'narrative/research/Cantor_EVO_X2_Scratch_Build_Remote_Preflight_Producer_Design_2026-09-11.sop',
    'plans/Cantor_EVO_X2_Scratch_Build_Executor_P0_Plan.sop',
    'solutions/Cantor_EVO_X2_Scratch_Build_Executor_P0_Solution.sop',
    'feature_support/Cantor_EVO_X2_Scratch_Build_Executor_P0_Requirement_Matrix.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Executor_P0_Satisfaction_Signature.sop',
    'narrative/reentry/Cantor_EVO_X2_Scratch_Build_Executor_P0_Reentry.sop',
    'proofs/Cantor_EVO_X2_Scratch_Build_Remote_Preflight_Producer_Contract_Proof.sop',
    'feature_support/reviews/CantorEVOX2ScratchBuildRemotePreflightProducerContractReview.sop',
    'narrative/registries/Cantor_EVO_X2_Scratch_Build_Remote_Preflight_Producer_Contract_Checkpoint.sop',
    'narrative/turns/1789137487637_evox2_scratch_build_remote_preflight_producer_start.sop',
    'narrative/turns/1789143503485_evox2_scratch_build_remote_preflight_producer_contract.sop',
    'narrative/file_changes/1789143503485_evox2_scratch_build_remote_preflight_producer_contract.sop',
    'narrative/change_sets/b26b2559-3feb-4e9f-9d94-01a99c97f277.sop',
    'narrative/operational_faults/1789143748537_evox2_preflight_producer_effect_wrapper_hash_case_refresh_fault.sop',
    'crates/cantor_core/src/evox2_scratch_build_remote_preflight_producer.rs',
    'crates/cantor_core/src/bin/cantor-evox2-scratch-build-preflight-producer-verify.rs',
    'crates/cantor_core/src/lib.rs',
    'crates/cantor_core/tests/evox2_scratch_build_remote_preflight_producer.rs',
    'experiments/evox2_scratch_build_executor_p0/preflight_producer_fixture/producer_plan.json',
    'scripts/build_cantor_evox2_scratch_build_remote_preflight_producer_evidence.ps1',
    'scripts/verify_cantor_evox2_scratch_build_remote_preflight_producer_evidence.ps1',
    'scripts/test_cantor_evox2_scratch_build_remote_preflight_producer_evidence.ps1'
)
$artifacts = foreach ($relative in $paths) {
    $path = Join-Path $rootPath $relative
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "producer artifact boundary differs: $relative" }
    [ordered]@{
        path = $relative
        bytes = [int64] $item.Length
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$manifest = [ordered]@{
    profile = 'cantor-evox2-scratch-build-remote-preflight-producer-evidence/0.1'
    manifest_uuid = 'af086146-9dab-4519-b1ba-26f370cb7e28'
    canonical_uuid = '935e020f-8c6f-49e4-b355-63eabd3b778b'
    source_uuid = 'fa3dbac1-04b8-4f10-a8a4-bb382bf1201f'
    design_uuid = 'd762e7c4-f8da-4cce-86e1-0f1cf7544ec9'
    predecessor_bookend = '047674f26b4f9cb576fd93524d710d91e0e48b51'
    observation_compiler_implementation_commit = '000fef93cadce29b2e0ce59e668ac72ca2e2a9ad'
    observation_compiler_bookend_commit = '047674f26b4f9cb576fd93524d710d91e0e48b51'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($artifacts)
    verification = [ordered]@{
        artifact_count = 25
        focused_tests = 9
        argument_atoms = 19
        timeout_ms = 30000
        stdout_limit_bytes = 65536
        stderr_limit_bytes = 65536
        provider_requests_performed = 0
        remote_calls_performed = 0
        effects_performed = 0
        remote_contact_authorized = $false
        evidence_is_fixture = $true
        exact_workspace_gates_passed = [bool] $ExactGatesPassed
    }
}
$output = Join-Path $rootPath 'experiments\evox2_scratch_build_executor_p0\preflight_producer_implementation_evidence_manifest.json'
[IO.File]::WriteAllText($output, (($manifest | ConvertTo-Json -Depth 30).Replace("`r`n", "`n") + "`n"), [Text.UTF8Encoding]::new($false))
"cantor_evox2_scratch_build_remote_preflight_producer_evidence_written=$output artifacts=$($artifacts.Count) exact_gates=$([bool] $ExactGatesPassed)"
