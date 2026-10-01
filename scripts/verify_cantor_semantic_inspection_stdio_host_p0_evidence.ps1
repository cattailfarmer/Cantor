param(
    [string]$TargetDirectory = "D:\CantorBuilds\target",
    [string]$RepositoryRoot = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $RepositoryRoot = Join-Path $PSScriptRoot ".." }
$repositoryRootPath = [IO.Path]::GetFullPath($RepositoryRoot)
$env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDirectory)
$env:CARGO_BUILD_JOBS = "1"
$env:CARGO_INCREMENTAL = "0"
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_stdio_host_p0_source.ps1") -RepositoryRoot $repositoryRootPath
& (Join-Path $PSScriptRoot "verify_cantor_semantic_inspection_stdio_host_p0_formation.ps1") -RepositoryRoot $repositoryRootPath

function Assert-Artifact($Artifact) {
    $path = Join-Path $repositoryRootPath ([string]$Artifact.path)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "artifact missing: $($Artifact.path)" }
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($item.Length -ne [int64]$Artifact.bytes -or $hash -cne [string]$Artifact.sha256) { throw "artifact coordinate differs: $($Artifact.path)" }
}

$manifestPath = Join-Path $repositoryRootPath "experiments/cantor_semantic_inspection_stdio_host_p0/implementation_evidence_manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.profile -cne "cantor-semantic-inspection-stdio-host-p0-evidence/0.1" -or $manifest.evidence_manifest_uuid -cne "27fb07f9-f9ae-492f-826a-54a0b00bce40" -or $manifest.specification_uuid -cne "4ee53d21-ed53-4f35-bbaf-06cab3a34085" -or $manifest.formation_bookend -cne "a540faf4c75e8101b2dc5ac49691cbce1ac73f14") { throw "implementation evidence identity differs" }
$artifacts = @($manifest.artifacts)
if ($artifacts.Count -ne 5) { throw "implementation artifact membership differs" }
foreach ($artifact in $artifacts) { Assert-Artifact $artifact }

$component = Get-Content -LiteralPath (Join-Path $repositoryRootPath "experiments/cantor_semantic_inspection_stdio_host_p0/semantic_inspection_stdio_host_component.json") -Raw | ConvertFrom-Json
$expectedPaths = @("crates/cantor_sop_inspect_wire/Cargo.toml","crates/cantor_sop_inspect_wire/src/bin/cantor-sop-inspect-stdio.rs","crates/cantor_sop_inspect_wire/tests/stdio_host.rs","crates/cantor_sop_inspect_wire/tests/stdio_host_static.rs")
if ($component.profile -cne "cantor-semantic-inspection-stdio-host-component/0.1" -or [int]$component.file_count -ne 4 -or @($component.files).Count -ne 4 -or [int]$component.refused_exit -ne 2) { throw "component identity differs" }
for ($index = 0; $index -lt $expectedPaths.Count; $index++) {
    if (@($component.files)[$index].path -cne $expectedPaths[$index]) { throw "component membership differs" }
    Assert-Artifact @($component.files)[$index]
}

$verification = $manifest.verification
if ([int]$verification.artifact_count -ne 5 -or [int]$verification.promoted_component_files -ne 4 -or [int]$verification.focused_debug_passed -ne 21 -or [int]$verification.focused_release_passed -ne 21) { throw "focused or component counts differ" }
foreach ($prefix in @('workspace_debug','workspace_release')) {
    if ([int]$verification.("${prefix}_result_groups") -ne 356 -or [int]$verification.("${prefix}_passed") -ne 2068 -or [int]$verification.("${prefix}_failed") -ne 0 -or [int]$verification.("${prefix}_ignored") -ne 22) { throw "workspace summary differs: $prefix" }
}
if ([int]$verification.per_profile_host_process_trials -ne 15 -or [int]$verification.per_profile_stdin_sessions -ne 14 -or [int]$verification.per_profile_complete_stdout_responses -ne 6 -or [int]$verification.per_profile_public_stderr_faults -ne 8 -or [int]$verification.per_profile_closed_stdout_failures -ne 1) { throw "host effect account differs" }
foreach ($field in @('filesystem_effects','network_effects','service_effects','provider_requests','model_requests','remote_calls','installations','updates','synthetic_trials')) { if ([int]$verification.$field -ne 0) { throw "nonzero implementation effect counter: $field" } }

$completion = Get-Content -LiteralPath (Join-Path $repositoryRootPath "narrative/registries/Cantor_Semantic_Inspection_Stdio_Host_P0_Completion_Satisfaction_Signature.sop") -Raw
if ($completion -notmatch [regex]::Escape("@ [completion_signature_uuid] cdd7acae-ce19-4c93-861b-6520c97a03c1")) { throw "completion signature identity differs" }
$bindingPattern = '(?m)^  \+ \[artifact_binding\] (\S+) bytes([0-9]+) SHA256 ([0-9A-F]{64})$'
$bindings = [regex]::Matches($completion, $bindingPattern)
if ($bindings.Count -ne 9) { throw "completion binding membership differs" }
foreach ($binding in $bindings) {
    $path = Join-Path $repositoryRootPath $binding.Groups[1].Value
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($item.Length -ne [int64]$binding.Groups[2].Value -or $hash -cne $binding.Groups[3].Value) { throw "completion binding differs: $($binding.Groups[1].Value)" }
}

Push-Location $repositoryRootPath
try {
    & cargo test -p cantor_sop_inspect_wire --all-targets --locked --offline -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw "stdio host replay failed" }
} finally { Pop-Location }
Write-Output "cantor_semantic_inspection_stdio_host_evidence_verified=true artifacts=5 component_files=4 focused=21 groups=356 passed=2068 failed=0 ignored=22 completion_bindings=9 host_trials=15 stdin_sessions=14 stdout_responses=6 stderr_faults=8 closed_stdout=1 filesystem_effects=0 network_effects=0 services=0 providers=0 models=0 remote_calls=0"
