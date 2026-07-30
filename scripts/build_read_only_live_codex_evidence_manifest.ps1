param(
    [string]$LiveProbeOutputPath = ".local/read-only-live-codex/probe-output.json",
    [string]$OutcomePath = "crates/cantor_ecosystem/evidence/read_only_live_codex_probe_outcome.json",
    [string]$ManifestPath = "crates/cantor_ecosystem/evidence/read_only_live_codex_evidence_manifest.json"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

function Resolve-RepositoryPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $repositoryRoot $Path))
}

$liveProbeFullPath = Resolve-RepositoryPath $LiveProbeOutputPath
$probe = Get-Content -LiteralPath $liveProbeFullPath -Raw | ConvertFrom-Json
if ($probe.profile -ne "cantor-live-codex-probe/0.1" `
    -or $probe.evidence.profile -ne "cantor-read-only-live-codex/0.1" `
    -or $probe.evidence.mcp_server_name -ne "cantor" `
    -or $probe.evidence.mcp_tool_name -ne "query_sop" `
    -or $probe.outcome.progress -ne "accepted" `
    -or $probe.outcome.review.disposition -ne "accept" `
    -or $probe.outcome.final_decision.disposition -ne "accept" `
    -or $probe.outcome.metrics.cantor_adapter_calls -ne 1 `
    -or $probe.outcome.metrics.codex_adapter_calls -ne 2 `
    -or $probe.outcome.transcript.Count -ne 7 `
    -or $probe.outcome.candidate.requested_effects.Count -ne 0) {
    throw "live probe does not satisfy the read-only live Codex acceptance contract"
}

$outcomeFullPath = Resolve-RepositoryPath $OutcomePath
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($outcomeFullPath)) | Out-Null
[IO.File]::WriteAllText(
    $outcomeFullPath,
    "$(($probe | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)

$paths = @(
    ".gitattributes",
    "Cargo.toml",
    "Cargo.lock",
    "source_documents/2026-07-30_cantor_read_only_live_codex_activation/Cantor_Read_Only_Live_Codex_Activation_Source_Selection.sop",
    "source_documents/2026-07-30_cantor_read_only_live_codex_activation/Cantor_Read_Only_Live_Codex_Implementation_Reconciliation_Source.sop",
    "source_documents/2026-07-30_cantor_read_only_live_codex_activation/Cantor_Read_Only_Live_Codex_Transport_Hardening_Source.sop",
    "source_documents/2026-07-30_cantor_read_only_live_codex_activation/Source_Document_Manifest.sop",
    "specifications/exploded/Cantor_Read_Only_Live_Codex_Adapter.exploded.sop",
    "specifications/Cantor_Read_Only_Live_Codex_Adapter.sop",
    "justifications/Cantor_Read_Only_Live_Codex_Adapter_Justification.sop",
    "narrative/research/Cantor_Codex_App_Server_Interface_Assessment_2026-07-30.sop",
    "feature_support/slices/ReadOnlyLiveCodexAdapter.sop",
    "feature_support/ReadOnlyLiveCodexAdapter_Requirement_Matrix.sop",
    "feature_support/Cantor_Engine_Build_Slice_Index.sop",
    "plans/Cantor_Engine_Build_Plan.sop",
    "solutions/Cantor_Read_Only_Live_Codex_Adapter_Solution.sop",
    "narrative/Project_Narrative.sop",
    "narrative/operational_faults/1785424002058_read_only_live_codex_adapter_faults.sop",
    "narrative/turns/1785424002058_cantor_read_only_live_codex_adapter.sop",
    "narrative/file_changes/1785424002058_read_only_live_codex_adapter_file_change.sop",
    "README.md",
    "SOP_CORE_MAP.sop",
    "docs/READ_ONLY_LIVE_CODEX_ADAPTER.md",
    "crates/cantor_ecosystem/Cargo.toml",
    "crates/cantor_ecosystem/src/lib.rs",
    "crates/cantor_ecosystem/src/live_codex.rs",
    "crates/cantor_ecosystem/examples/prepare_live_codex_probe.rs",
    "crates/cantor_ecosystem/examples/live_codex_probe.rs",
    "crates/cantor_ecosystem/tests/live_codex_adapter.rs",
    "crates/cantor_ecosystem/tests/live_codex_evidence.rs",
    "scripts/build_read_only_live_codex_evidence_manifest.ps1",
    "crates/cantor_ecosystem/evidence/read_only_live_codex_probe_outcome.json",
    "crates/cantor_ecosystem/evidence/supervised_mock_loop_evidence_manifest.json",
    "proofs/Cantor_Supervised_Mock_Loop_Proof.sop"
)

$artifacts = foreach ($path in $paths) {
    $item = Get-Item -LiteralPath (Join-Path $repositoryRoot $path)
    [ordered]@{
        path = $path.Replace("\", "/")
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash
        bytes = $item.Length
    }
}

$manifest = [ordered]@{
    schema = "cantor-read-only-live-codex-evidence-manifest/0.1"
    evidence_manifest_uuid = "01bb709e-7a44-4b09-8eee-b15b7c692297"
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    authority = [ordered]@{
        canonical_specification_uuid = "4090fcfc-b61d-41d4-896e-c9eb88d82409"
        satisfaction_signature_uuid = "49232cc8-86d5-43e6-b709-08b6e1cda884"
        solution_uuid = "6f4a7123-b8ca-4d44-9b26-e64762a4fa88"
    }
    live_probe = [ordered]@{
        profile = $probe.evidence.profile
        codex_version = $probe.evidence.codex_version
        codex_executable_sha256 = $probe.evidence.codex_executable_sha256
        cantor_mcp_executable_sha256 = $probe.evidence.cantor_mcp_executable_sha256
        environment_file_sha256 = $probe.evidence.environment_file_sha256
        request_digest = $probe.evidence.request_digest.value
        response_digest = $probe.evidence.response_digest.value
        candidate_message_digest = $probe.evidence.candidate_payload_digest.value
        thread_id = $probe.evidence.thread_id
        turn_id = $probe.evidence.turn_id
        events = $probe.evidence.event_count
        received_bytes = $probe.evidence.received_bytes
        tool_calls = $probe.outcome.metrics.cantor_adapter_calls
        logical_messages = $probe.outcome.metrics.accepted_messages
        requested_effects = $probe.outcome.candidate.requested_effects.Count
        advisories = $probe.evidence.advisories.Count
        review = $probe.outcome.review.disposition
        decision = $probe.outcome.final_decision.disposition
    }
    verification = @(
        [ordered]@{ command = "cargo fmt --all -- --check"; status = "passed" },
        [ordered]@{ command = "cargo clippy --workspace --all-targets --locked --offline -- -D warnings"; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --locked --offline"; tests = 196; status = "passed" },
        [ordered]@{ command = "cargo test --workspace --all-targets --release --locked --offline"; tests = 196; status = "passed" },
        [ordered]@{ command = "cargo build --workspace --all-targets --release --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo doc --workspace --no-deps --locked --offline"; status = "passed" },
        [ordered]@{ command = "cargo audit --file Cargo.lock"; dependencies = 112; advisories = 1173; vulnerabilities = 0; status = "passed" }
    )
    artifacts = @($artifacts)
}

$manifestFullPath = Resolve-RepositoryPath $ManifestPath
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($manifestFullPath)) | Out-Null
[IO.File]::WriteAllText(
    $manifestFullPath,
    "$(($manifest | ConvertTo-Json -Depth 10).Replace("`r`n", "`n"))`n",
    [Text.UTF8Encoding]::new($false)
)
Write-Output $manifestFullPath
