[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifierRelative = 'scripts/verify_cantor_succeeding_sop_fixture_rollback_evidence.ps1'
$controlledRelative = 'experiments/succeeding_sop_fixture_rollback_p0/artifacts/controlled_verification.json'
$receiptRelative = 'experiments/succeeding_sop_fixture_rollback_p0/artifacts/succeeding_sop_fixture_rollback_receipt.json'
$manifestRelative = 'experiments/succeeding_sop_fixture_rollback_p0/artifacts/succeeding_sop_fixture_rollback_evidence_manifest.json'
$generatedAt = '2026-08-26T01:39:29Z'
$predecessorCommit = 'e1b31b4f555fbb2605eeeffaf60af9915c230a00'
$gateReceipt = 'cantor-succeeding-sop-fixture-rollback-wsl-gate-receipt/0.1 b2a_debug=45 combined_debug=16 rollback_debug=9 b2a_release=45 combined_release=16 rollback_release=9 clippy=pass format=pass'
$nonAuthority = 'This controlled verification proves only deterministic recovery-owned rollback inside one disposable synthetic fixture with durable Linux file and parent flush. It proves no observed boot truth, operator consent, live root, external activation, provider, model, process, network, cleanup, Windows durability success, remote, FPGA, or Minecraft authority.'
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path $tempBase "cantor-sfr-verifier-test-$PID-$([guid]::NewGuid())"))

function Ensure-Parent([string]$Path) {
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)) | Out-Null
}

function Write-LfJson([string]$Path, [object]$Value) {
    Ensure-Parent $Path
    $json = (($Value | ConvertTo-Json -Depth 64) -replace "`r`n", "`n") + "`n"
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

function File-Ref([string]$RepositoryRoot, [string]$Relative) {
    $full = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot $Relative))
    $item = Get-Item -Force -LiteralPath $full
    return [ordered]@{
        path = $Relative.Replace('\', '/')
        bytes = [int64]$item.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash
    }
}

function Read-ExpectedPaths([string]$VerifierPath) {
    $lines = Get-Content -LiteralPath $VerifierPath
    $start = ($lines | Select-String -SimpleMatch '$expectedPaths = @(').LineNumber
    if (-not $start) { throw 'verifier expected-path array is absent' }
    $end = $null
    for ($index = $start; $index -le $lines.Count; $index++) {
        if ($lines[$index - 1] -eq ')') { $end = $index; break }
    }
    if (-not $end) { throw 'verifier expected-path array is unterminated' }
    $paths = @()
    foreach ($line in $lines[$start..($end - 2)]) {
        if ($line -match "^\s*'([^']+)'[,]?$") { $paths += $Matches[1] }
    }
    return $paths
}

function Build-Manifest([string[]]$ExpectedPaths) {
    $refs = @($ExpectedPaths | Sort-Object -CaseSensitive | ForEach-Object { File-Ref $fixtureRoot $_ })
    return [ordered]@{
        profile = 'cantor-succeeding-sop-fixture-rollback-evidence-manifest/0.1'
        manifest_uuid = 'ac51906f-c9be-49f5-8f7c-b0eb5047eb44'
        generated_at_utc = $generatedAt
        predecessor_commit = $predecessorCommit
        controlled_verification_uuid = 'a72eb152-0465-4aac-94ac-d62920d0b65c'
        receipt_artifact_uuid = 'e130e754-b180-4361-a52f-2b6fb5fcf2ba'
        file_ref_count = [int64]$refs.Count
        file_refs = $refs
        non_authority_statement = $nonAuthority
    }
}

function Expect-Refusal([string]$Label, [string]$Pattern, [scriptblock]$Action) {
    try {
        & $Action
        throw "$Label was not refused"
    } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
    }
}

function Remove-FixtureRoot() {
    $resolved = [IO.Path]::GetFullPath($fixtureRoot)
    $prefix = $tempBase.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolved) -notlike 'cantor-sfr-verifier-test-*') {
        throw "refusing unsafe verifier fixture cleanup: $resolved"
    }
    if ([IO.Directory]::Exists($resolved)) { Remove-Item -Recurse -Force -LiteralPath $resolved }
}

try {
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    $expectedPaths = @(Read-ExpectedPaths (Join-Path $root $verifierRelative))
    if ($expectedPaths.Count -ne 57) { throw "verifier expected-path count differs: $($expectedPaths.Count)" }
    foreach ($relative in $expectedPaths) {
        if ($relative -in @($controlledRelative, $receiptRelative)) { continue }
        $source = [IO.Path]::GetFullPath((Join-Path $root $relative))
        if (-not [IO.File]::Exists($source)) { throw "test source is missing: $relative" }
        $destination = [IO.Path]::GetFullPath((Join-Path $fixtureRoot $relative))
        Ensure-Parent $destination
        [IO.File]::Copy($source, $destination, $true)
    }

    $zero = '0'.PadLeft(64, '0')
    $digest = { param([string]$Value) [ordered]@{ algorithm = 'sha256'; value = $Value } }
    $checks = @('atomic_replace', 'authority_boundary', 'candidate_preservation', 'deterministic_digests', 'file_flush', 'final_reopen', 'marker_correspondence', 'monotonic_generation', 'parent_flush', 'predecessor_reacquisition', 'registry_precondition', 'root_boundary', 'temp_create_new', 'trigger_correspondence', 'upstream_replay')
    $receipt = [ordered]@{
        profile = 'cantor-succeeding-sop-fixture-rollback-receipt/0.1'
        commission = [ordered]@{}
        marker = [ordered]@{}
        status = 'fixture_registry_rolled_back_awaiting_boot_validation'
        authority = 'synthetic_fixture_recovery_only'
        trigger = 'boot_validation_failed'
        trigger_evidence_ref = 'trigger-evidence:boot-validation-failed'
        current_failed_record = [ordered]@{ current = [ordered]@{ generation = 42; current_source_bytes = 93; current_source_path = 'source_documents/reviewed_succeeding_sop/Cantor_Fixture_Succeeding_SOP_Source.sop' } }
        restored_record = [ordered]@{ current = [ordered]@{ generation = 43; current_source_bytes = 93; current_source_path = 'source_documents/current_sop_fixture/Cantor_Current_SOP_Source.sop' } }
        upstream_receipt_digest = & $digest $zero
        predecessor_source_raw_digest = & $digest 'e8405fae0ee54f9fdfb39ea84b3fa6e710c5163fbc916b11a9efefddf0564a61'
        failed_candidate_source_raw_digest = & $digest '4902d55b37710df8827f981bf73a8afd9a63bd40e94ad89ba873c2311be3f554'
        failed_registry_raw_digest = & $digest $zero
        restored_registry_raw_digest = & $digest $zero
        verified_checks = $checks
        physical_contact = $true
        current_successor_observed = $true
        predecessor_source_reacquired = $true
        registry_persisted = $true
        predecessor_selected = $true
        rollback_executed = $true
        failed_candidate_preserved = $true
        temp_absent_after = $true
        boot_activation_verified = $false
        live_activation_performed = $false
        provider_contacted = $false
        model_called = $false
        process_launched = $false
        network_contacted = $false
        cleanup_performed = $false
        windows_durability_assumed = $false
        receipt_digest = & $digest $zero
    }
    $receiptFull = Join-Path $fixtureRoot $receiptRelative
    Write-LfJson $receiptFull $receipt

    $controlled = [ordered]@{
        profile = 'cantor-succeeding-sop-fixture-rollback-controlled-verification/0.1'
        verification_uuid = 'a72eb152-0465-4aac-94ac-d62920d0b65c'
        generated_at_utc = $generatedAt
        predecessor_commit = $predecessorCommit
        platform = 'linux-x86_64-wsl2'
        disposition = 'synthetic_fixture_rollback_verified_awaiting_boot_validation'
        upstream_fixture = [ordered]@{
            bytes = 49484
            sha256 = '018D955E43C13EF8CC294F3271326824443DEB56F8C5FD00730ABB05A1B85E1E'
            current_source_bytes = 93
            rollback_source_bytes = 93
            failed_candidate_source_sha256 = '4902D55B37710DF8827F981BF73A8AFD9A63BD40E94AD89BA873C2311BE3F554'
            rollback_source_sha256 = 'E8405FAE0EE54F9FDFB39EA84B3FA6E710C5163FBC916B11A9EFEFDDF0564A61'
        }
        focused = [ordered]@{ gate_receipt = $gateReceipt; b2a_debug_tests = 45; combined_debug_tests = 16; rollback_debug_tests = 9; b2a_overflow_release_tests = 45; combined_overflow_release_tests = 16; rollback_overflow_release_tests = 9; failures = 0 }
        receipt = File-Ref $fixtureRoot $receiptRelative
        result = [ordered]@{
            failed_generation = 42; restored_generation = 43; failed_source_bytes = 93; restored_source_bytes = 93
            physical_contact = $true; current_successor_observed = $true; predecessor_source_reacquired = $true; registry_persisted = $true
            predecessor_selected = $true; rollback_executed = $true; failed_candidate_preserved = $true; temp_absent_after = $true
            boot_activation_verified = $false; live_activation_performed = $false; provider_contacted = $false; process_launched = $false
            network_contacted = $false; cleanup_performed = $false
        }
        non_authority = $nonAuthority
    }
    $controlledFull = Join-Path $fixtureRoot $controlledRelative
    Write-LfJson $controlledFull $controlled
    $manifestFull = Join-Path $fixtureRoot $manifestRelative
    $manifest = Build-Manifest $expectedPaths
    Write-LfJson $manifestFull $manifest

    $copiedVerifier = Join-Path $fixtureRoot $verifierRelative
    $verified = (& $copiedVerifier | ConvertFrom-Json)
    if ($verified.status -cne 'verified' -or [int64]$verified.file_ref_count -ne 57) {
        throw 'independent verifier success receipt differs'
    }

    $firstRef = $manifest.file_refs[0]
    $manifest.file_refs[0] = $manifest.file_refs[1]
    $manifest.file_refs[1] = $firstRef
    Write-LfJson $manifestFull $manifest
    Expect-Refusal 'manifest order laundering' 'manifest evidence refs are not case-sensitive sorted' { & $copiedVerifier | Out-Null }

    $manifest = Build-Manifest $expectedPaths
    $manifest.Add('unexpected_field', 'must-be-refused')
    Write-LfJson $manifestFull $manifest
    Expect-Refusal 'manifest unknown-field laundering' 'evidence manifest properties differ' { & $copiedVerifier | Out-Null }
    $manifest = Build-Manifest $expectedPaths
    Write-LfJson $manifestFull $manifest

    $tamperRelative = 'crates/cantor_core/tests/objective_work_plan.rs'
    $tamperFull = Join-Path $fixtureRoot $tamperRelative
    [IO.File]::AppendAllText($tamperFull, "tamper", [Text.UTF8Encoding]::new($false))
    Expect-Refusal 'source tamper' 'byte count or SHA256 differs' { & $copiedVerifier | Out-Null }
    [IO.File]::Copy((Join-Path $root $tamperRelative), $tamperFull, $true)

    $receipt.provider_contacted = $true
    Write-LfJson $receiptFull $receipt
    $controlled.receipt = File-Ref $fixtureRoot $receiptRelative
    Write-LfJson $controlledFull $controlled
    $manifest = Build-Manifest $expectedPaths
    Write-LfJson $manifestFull $manifest
    Expect-Refusal 'fully rehashed provider outcome laundering' 'rollback receipt outcome differs' { & $copiedVerifier | Out-Null }

    Write-Output 'succeeding_sop_fixture_rollback_evidence_verifier_tests_passed success=1 manifest_order_laundering_refused=1 manifest_unknown_field_refused=1 source_tamper_refused=1 rehashed_outcome_laundering_refused=1'
} finally {
    Remove-FixtureRoot
}
