[CmdletBinding()]
param(
    [string]$ManifestPath = 'experiments/succeeding_sop_fixture_rollback_p0/artifacts/succeeding_sop_fixture_rollback_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $root 'experiments/succeeding_sop_fixture_rollback_p0/artifacts'))
$maxBytes = 16MB
$expectedCommit = 'e1b31b4f555fbb2605eeeffaf60af9915c230a00'
$expectedGeneratedAt = '2026-08-26T01:39:29Z'
$expectedGateReceipt = 'cantor-succeeding-sop-fixture-rollback-wsl-gate-receipt/0.1 b2a_debug=45 combined_debug=16 rollback_debug=9 b2a_release=45 combined_release=16 rollback_release=9 clippy=pass format=pass'
$expectedNonAuthority = 'This controlled verification proves only deterministic recovery-owned rollback inside one disposable synthetic fixture with durable Linux file and parent flush. It proves no observed boot truth, operator consent, live root, external activation, provider, model, process, network, cleanup, Windows durability success, remote, FPGA, or Minecraft authority.'

function Get-DescendantRelativePath([string]$Base, [string]$Path, [string]$Failure) {
    $baseFull = [IO.Path]::GetFullPath($Base).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $pathFull = [IO.Path]::GetFullPath($Path)
    if ($pathFull.Equals($baseFull, [StringComparison]::OrdinalIgnoreCase)) { return '' }
    $prefix = $baseFull + [IO.Path]::DirectorySeparatorChar
    if (-not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw $Failure }
    return $pathFull.Substring($prefix.Length)
}

function Assert-NoReparseAncestors([string]$Path) {
    $cursor = $root
    $rootItem = Get-Item -Force -LiteralPath $cursor
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'repository root is a reparse point'
    }
    $relative = Get-DescendantRelativePath $root $Path 'evidence path ancestor escapes repository root'
    foreach ($segment in @($relative -split '[\\/]' | Where-Object { $_.Length -gt 0 })) {
        $cursor = Join-Path $cursor $segment
        if ([IO.Directory]::Exists($cursor) -or [IO.File]::Exists($cursor)) {
            $item = Get-Item -Force -LiteralPath $cursor
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "evidence path ancestor is a reparse point: $cursor"
            }
        }
    }
}

function Resolve-ArtifactFile([string]$Path, [string]$Label) {
    $resolved = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $root $Path))
    }
    $relative = Get-DescendantRelativePath $artifactRoot $resolved "$Label is not one ordinary JSON file beneath the governed artifact root"
    if ($relative.Contains(':') -or [IO.Path]::GetExtension($resolved) -ine '.json') {
        throw "$Label is not one ordinary JSON file beneath the governed artifact root"
    }
    Assert-NoReparseAncestors ([IO.Path]::GetDirectoryName($resolved))
    if (-not [IO.File]::Exists($resolved)) { throw "$Label is missing" }
    $item = Get-Item -Force -LiteralPath $resolved
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or [bool]$item.PSIsContainer) {
        throw "$Label is not one ordinary file"
    }
    return $resolved
}

function Resolve-RepositoryFile([string]$Relative, [string]$Label) {
    if ($Relative.Length -eq 0 -or $Relative.Contains('\') -or $Relative.Contains(':')) {
        throw "$Label path is not one normalized repository-relative path"
    }
    $resolved = [IO.Path]::GetFullPath((Join-Path $root $Relative))
    $rootPrefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label path escapes the repository"
    }
    Assert-NoReparseAncestors ([IO.Path]::GetDirectoryName($resolved))
    if (-not [IO.File]::Exists($resolved)) { throw "$Label file is missing: $Relative" }
    $item = Get-Item -Force -LiteralPath $resolved
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or [bool]$item.PSIsContainer) {
        throw "$Label is not one ordinary file: $Relative"
    }
    return $resolved
}

function Read-StrictJson([string]$Path, [string]$Label) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0 -or $bytes.Length -gt $maxBytes) { throw "$Label byte bound differs" }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        throw "$Label contains a forbidden UTF-8 BOM"
    }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    if ($text.Contains("`r")) { throw "$Label is not LF-normalized" }
    try { return $text | ConvertFrom-Json } catch { throw "$Label strict JSON parse failed: $($_.Exception.Message)" }
}

function Assert-Properties([object]$Value, [string[]]$Expected, [string]$Label) {
    if ($null -eq $Value) { throw "$Label is absent" }
    $actual = @($Value.PSObject.Properties.Name)
    $expectedSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $Expected) { [void]$expectedSet.Add($name) }
    if ($actual.Count -ne $expectedSet.Count -or @($actual | Where-Object { -not $expectedSet.Contains($_) }).Count -ne 0) {
        throw "$Label properties differ"
    }
}

function Assert-Digest([object]$Digest, [string]$ExpectedValue, [string]$Label) {
    Assert-Properties $Digest @('algorithm', 'value') $Label
    if ($Digest.algorithm -cne 'sha256' -or $Digest.value -cne $ExpectedValue) { throw "$Label differs" }
}

function Assert-FileRef([object]$Ref, [string]$ExpectedPath, [string]$Label) {
    Assert-Properties $Ref @('path', 'bytes', 'sha256') $Label
    if ($Ref.path -cne $ExpectedPath -or [int64]$Ref.bytes -le 0 -or $Ref.sha256 -cnotmatch '^[0-9A-F]{64}$') {
        throw "$Label shape differs"
    }
    $full = Resolve-RepositoryFile $Ref.path $Label
    $item = Get-Item -Force -LiteralPath $full
    if ([int64]$Ref.bytes -ne [int64]$item.Length -or
        $Ref.sha256 -cne (Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash) {
        throw "$Label byte count or SHA256 differs"
    }
}

$expectedPaths = @(
    'crates/cantor_core/src/succeeding_sop_activation_transaction.rs',
    'crates/cantor_core/tests/objective_work_plan.rs',
    'crates/cantor_core/tests/succeeding_sop_activation_transaction.rs',
    'crates/cantor_ecosystem/examples/succeeding_sop_fixture_rollback_fixture.rs',
    'crates/cantor_ecosystem/src/lib.rs',
    'crates/cantor_ecosystem/src/succeeding_sop_fixture_persistence.rs',
    'crates/cantor_ecosystem/src/succeeding_sop_fixture_rollback.rs',
    'crates/cantor_ecosystem/tests/fixtures/succeeding_sop_activation_transaction_receipt.json',
    'crates/cantor_ecosystem/tests/succeeding_sop_fixture_persistence.rs',
    'crates/cantor_ecosystem/tests/succeeding_sop_fixture_rollback.rs',
    'docs/CANTOR_DEVELOPMENT_STATE_2026-08-23.md',
    'docs/CANTOR_PRODUCT_READINESS_2026-08-23.md',
    'experiments/succeeding_sop_fixture_rollback_p0/artifacts/controlled_verification.json',
    'experiments/succeeding_sop_fixture_rollback_p0/artifacts/succeeding_sop_fixture_rollback_receipt.json',
    'feature_support/Cantor_Engine_Build_Slice_Index.sop',
    'feature_support/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Requirement_Matrix.sop',
    'feature_support/reviews/SucceedingSOPFixtureRollbackP0CompletionReview.sop',
    'feature_support/reviews/SucceedingSOPFixtureRollbackP0SignatureReadinessReview.sop',
    'justifications/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Justification.sop',
    'narrative/Project_Narrative.sop',
    'narrative/change_sets/43be45c1-a075-4cbb-bf35-a5d8fa9ca81d.sop',
    'narrative/file_changes/1787704100001_cantor_succeeding_sop_fixture_rollback_p0_source_file_change.sop',
    'narrative/file_changes/1787708373788_cantor_succeeding_sop_fixture_rollback_p0_implementation_checkpoint_file_change.sop',
    'narrative/file_changes/1787711760374_cantor_succeeding_sop_fixture_rollback_post_reboot_recovery_file_change.sop',
    'narrative/file_changes/1787714547046_cantor_succeeding_sop_fixture_rollback_independent_verifier_continuation_file_change.sop',
    'narrative/file_changes/1787714965391_cantor_succeeding_sop_fixture_rollback_post_reboot_verifier_hardening_file_change.sop',
    'narrative/file_changes/1787755142374_cantor_succeeding_sop_fixture_rollback_p0_completion_file_change.sop',
    'narrative/operational_faults/1787708373785_succeeding_sop_fixture_rollback_upstream_fixture_fault.sop',
    'narrative/operational_faults/1787708373786_succeeding_sop_fixture_rollback_reboot_execution_lane_fault.sop',
    'narrative/operational_faults/1787715880601_succeeding_sop_fixture_rollback_exact_workspace_execution_policy_fault.sop',
    'narrative/reentry/Cantor_M2B_Current_Reentry.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Artifact_Phase_Lock.sop',
    'narrative/registries/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Satisfaction_Signature.sop',
    'narrative/research/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Data_Design_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Input_Audit_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Seven_Fold_Exhaustion_2026-08-25.sop',
    'narrative/research/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Threat_Review_2026-08-25.sop',
    'narrative/turns/1787704100000_cantor_succeeding_sop_fixture_rollback_p0_source.sop',
    'narrative/turns/1787708373787_cantor_succeeding_sop_fixture_rollback_p0_implementation_checkpoint.sop',
    'narrative/turns/1787711760373_cantor_succeeding_sop_fixture_rollback_post_reboot_recovery.sop',
    'narrative/turns/1787714547045_cantor_succeeding_sop_fixture_rollback_independent_verifier_continuation.sop',
    'narrative/turns/1787714965390_cantor_succeeding_sop_fixture_rollback_post_reboot_verifier_hardening.sop',
    'narrative/turns/1787755142373_cantor_succeeding_sop_fixture_rollback_p0_completion.sop',
    'plans/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Plan.sop',
    'proofs/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Artifact_Phase_Lock_Proof.sop',
    'proofs/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Implementation_Proof.sop',
    'proofs/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Upstream_Correction_Proof.sop',
    'scripts/build_cantor_succeeding_sop_activation_fixture.ps1',
    'scripts/build_cantor_succeeding_sop_fixture_rollback_evidence.ps1',
    'scripts/test_cantor_succeeding_sop_fixture_rollback.ps1',
    'scripts/test_cantor_succeeding_sop_fixture_rollback_evidence_verifier.ps1',
    'scripts/verify_cantor_succeeding_sop_fixture_rollback_evidence.ps1',
    'solutions/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Solution.sop',
    'source_documents/2026-08-25_cantor_succeeding_sop_fixture_rollback_p0/Cantor_Succeeding_SOP_Fixture_Rollback_P0_Source.sop',
    'source_documents/2026-08-25_cantor_succeeding_sop_fixture_rollback_p0/Source_Document_Manifest.sop',
    'specifications/Cantor_Succeeding_SOP_Fixture_Rollback_P0.sop',
    'specifications/exploded/Cantor_Succeeding_SOP_Fixture_Rollback_P0.exploded.sop'
)

$manifestFull = Resolve-ArtifactFile $ManifestPath 'evidence manifest'
$manifest = Read-StrictJson $manifestFull 'evidence manifest'
Assert-Properties $manifest @('profile', 'manifest_uuid', 'generated_at_utc', 'predecessor_commit', 'controlled_verification_uuid', 'receipt_artifact_uuid', 'file_ref_count', 'file_refs', 'non_authority_statement') 'evidence manifest'
if ($manifest.profile -cne 'cantor-succeeding-sop-fixture-rollback-evidence-manifest/0.1' -or
    $manifest.manifest_uuid -cne 'ac51906f-c9be-49f5-8f7c-b0eb5047eb44' -or
    $manifest.generated_at_utc -cne $expectedGeneratedAt -or $manifest.predecessor_commit -cne $expectedCommit -or
    $manifest.controlled_verification_uuid -cne 'a72eb152-0465-4aac-94ac-d62920d0b65c' -or
    $manifest.receipt_artifact_uuid -cne 'e130e754-b180-4361-a52f-2b6fb5fcf2ba' -or
    $manifest.non_authority_statement -cne $expectedNonAuthority -or
    [int64]$manifest.file_ref_count -ne 57 -or @($manifest.file_refs).Count -ne 57) {
    throw 'evidence manifest boundary differs'
}
$expectedSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($path in $expectedPaths) { if (-not $expectedSet.Add($path)) { throw "duplicate expected evidence path: $path" } }
$actualSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$actualRefs = @($manifest.file_refs)
$actualPaths = @($actualRefs | ForEach-Object { [string]$_.path })
$sortedPaths = @($actualPaths | Sort-Object -CaseSensitive)
for ($index = 0; $index -lt $actualPaths.Count; $index++) {
    if ($actualPaths[$index] -cne $sortedPaths[$index]) { throw 'manifest evidence refs are not case-sensitive sorted' }
}
foreach ($ref in $actualRefs) {
    if (-not $actualSet.Add([string]$ref.path)) { throw "duplicate manifest evidence path: $($ref.path)" }
    if (-not $expectedSet.Contains([string]$ref.path)) { throw "unexpected manifest evidence path: $($ref.path)" }
    Assert-FileRef $ref ([string]$ref.path) "manifest ref $($ref.path)"
}
if ($actualSet.Count -ne $expectedSet.Count -or @($expectedPaths | Where-Object { -not $actualSet.Contains($_) }).Count -ne 0) {
    throw 'manifest evidence path set differs'
}

$controlledPath = 'experiments/succeeding_sop_fixture_rollback_p0/artifacts/controlled_verification.json'
$receiptPath = 'experiments/succeeding_sop_fixture_rollback_p0/artifacts/succeeding_sop_fixture_rollback_receipt.json'
$controlledFull = Resolve-ArtifactFile $controlledPath 'controlled verification'
$receiptFull = Resolve-ArtifactFile $receiptPath 'rollback receipt'
$controlled = Read-StrictJson $controlledFull 'controlled verification'
$receipt = Read-StrictJson $receiptFull 'rollback receipt'
Assert-Properties $controlled @('profile', 'verification_uuid', 'generated_at_utc', 'predecessor_commit', 'platform', 'disposition', 'upstream_fixture', 'focused', 'receipt', 'result', 'non_authority') 'controlled verification'
if ($controlled.profile -cne 'cantor-succeeding-sop-fixture-rollback-controlled-verification/0.1' -or
    $controlled.verification_uuid -cne 'a72eb152-0465-4aac-94ac-d62920d0b65c' -or
    $controlled.generated_at_utc -cne $expectedGeneratedAt -or $controlled.predecessor_commit -cne $expectedCommit -or
    $controlled.platform -cne 'linux-x86_64-wsl2' -or
    $controlled.disposition -cne 'synthetic_fixture_rollback_verified_awaiting_boot_validation' -or
    $controlled.non_authority -cne $expectedNonAuthority) { throw 'controlled verification boundary differs' }
Assert-Properties $controlled.upstream_fixture @('bytes', 'sha256', 'current_source_bytes', 'rollback_source_bytes', 'failed_candidate_source_sha256', 'rollback_source_sha256') 'controlled upstream fixture'
if ([int64]$controlled.upstream_fixture.bytes -ne 49484 -or
    $controlled.upstream_fixture.sha256 -cne '018D955E43C13EF8CC294F3271326824443DEB56F8C5FD00730ABB05A1B85E1E' -or
    [int64]$controlled.upstream_fixture.current_source_bytes -ne 93 -or [int64]$controlled.upstream_fixture.rollback_source_bytes -ne 93 -or
    $controlled.upstream_fixture.failed_candidate_source_sha256 -cne '4902D55B37710DF8827F981BF73A8AFD9A63BD40E94AD89BA873C2311BE3F554' -or
    $controlled.upstream_fixture.rollback_source_sha256 -cne 'E8405FAE0EE54F9FDFB39EA84B3FA6E710C5163FBC916B11A9EFEFDDF0564A61') {
    throw 'controlled upstream fixture differs'
}
Assert-Properties $controlled.focused @('gate_receipt', 'b2a_debug_tests', 'combined_debug_tests', 'rollback_debug_tests', 'b2a_overflow_release_tests', 'combined_overflow_release_tests', 'rollback_overflow_release_tests', 'failures') 'controlled focused gates'
if ($controlled.focused.gate_receipt -cne $expectedGateReceipt -or
    [int64]$controlled.focused.b2a_debug_tests -ne 45 -or [int64]$controlled.focused.combined_debug_tests -ne 16 -or
    [int64]$controlled.focused.rollback_debug_tests -ne 9 -or [int64]$controlled.focused.b2a_overflow_release_tests -ne 45 -or
    [int64]$controlled.focused.combined_overflow_release_tests -ne 16 -or [int64]$controlled.focused.rollback_overflow_release_tests -ne 9 -or
    [int64]$controlled.focused.failures -ne 0) { throw 'controlled focused gate receipt differs' }
Assert-Properties $controlled.result @('failed_generation', 'restored_generation', 'failed_source_bytes', 'restored_source_bytes', 'physical_contact', 'current_successor_observed', 'predecessor_source_reacquired', 'registry_persisted', 'predecessor_selected', 'rollback_executed', 'failed_candidate_preserved', 'temp_absent_after', 'boot_activation_verified', 'live_activation_performed', 'provider_contacted', 'process_launched', 'network_contacted', 'cleanup_performed') 'controlled result'
if ([int64]$controlled.result.failed_generation -ne 42 -or [int64]$controlled.result.restored_generation -ne 43 -or
    [int64]$controlled.result.failed_source_bytes -ne 93 -or [int64]$controlled.result.restored_source_bytes -ne 93 -or
    -not [bool]$controlled.result.physical_contact -or -not [bool]$controlled.result.current_successor_observed -or
    -not [bool]$controlled.result.predecessor_source_reacquired -or -not [bool]$controlled.result.registry_persisted -or
    -not [bool]$controlled.result.predecessor_selected -or -not [bool]$controlled.result.rollback_executed -or
    -not [bool]$controlled.result.failed_candidate_preserved -or -not [bool]$controlled.result.temp_absent_after -or
    [bool]$controlled.result.boot_activation_verified -or [bool]$controlled.result.live_activation_performed -or
    [bool]$controlled.result.provider_contacted -or [bool]$controlled.result.process_launched -or
    [bool]$controlled.result.network_contacted -or [bool]$controlled.result.cleanup_performed) { throw 'controlled result differs' }
Assert-FileRef $controlled.receipt $receiptPath 'controlled receipt ref'

Assert-Properties $receipt @('profile', 'commission', 'marker', 'status', 'authority', 'trigger', 'trigger_evidence_ref', 'current_failed_record', 'restored_record', 'upstream_receipt_digest', 'predecessor_source_raw_digest', 'failed_candidate_source_raw_digest', 'failed_registry_raw_digest', 'restored_registry_raw_digest', 'verified_checks', 'physical_contact', 'current_successor_observed', 'predecessor_source_reacquired', 'registry_persisted', 'predecessor_selected', 'rollback_executed', 'failed_candidate_preserved', 'temp_absent_after', 'boot_activation_verified', 'live_activation_performed', 'provider_contacted', 'model_called', 'process_launched', 'network_contacted', 'cleanup_performed', 'windows_durability_assumed', 'receipt_digest') 'rollback receipt'
if ($receipt.profile -cne 'cantor-succeeding-sop-fixture-rollback-receipt/0.1' -or
    $receipt.status -cne 'fixture_registry_rolled_back_awaiting_boot_validation' -or
    $receipt.authority -cne 'synthetic_fixture_recovery_only' -or $receipt.trigger -cne 'boot_validation_failed' -or
    [int64]$receipt.current_failed_record.current.generation -ne 42 -or [int64]$receipt.restored_record.current.generation -ne 43 -or
    [int64]$receipt.current_failed_record.current.current_source_bytes -ne 93 -or [int64]$receipt.restored_record.current.current_source_bytes -ne 93 -or
    $receipt.current_failed_record.current.current_source_path -cne 'source_documents/reviewed_succeeding_sop/Cantor_Fixture_Succeeding_SOP_Source.sop' -or
    $receipt.restored_record.current.current_source_path -cne 'source_documents/current_sop_fixture/Cantor_Current_SOP_Source.sop' -or
    -not [bool]$receipt.physical_contact -or -not [bool]$receipt.current_successor_observed -or
    -not [bool]$receipt.predecessor_source_reacquired -or -not [bool]$receipt.registry_persisted -or
    -not [bool]$receipt.predecessor_selected -or -not [bool]$receipt.rollback_executed -or
    -not [bool]$receipt.failed_candidate_preserved -or -not [bool]$receipt.temp_absent_after -or
    [bool]$receipt.boot_activation_verified -or [bool]$receipt.live_activation_performed -or
    [bool]$receipt.provider_contacted -or [bool]$receipt.model_called -or [bool]$receipt.process_launched -or
    [bool]$receipt.network_contacted -or [bool]$receipt.cleanup_performed -or [bool]$receipt.windows_durability_assumed) {
    throw 'rollback receipt outcome differs'
}
Assert-Digest $receipt.failed_candidate_source_raw_digest '4902d55b37710df8827f981bf73a8afd9a63bd40e94ad89ba873c2311be3f554' 'failed candidate digest'
Assert-Digest $receipt.predecessor_source_raw_digest 'e8405fae0ee54f9fdfb39ea84b3fa6e710c5163fbc916b11a9efefddf0564a61' 'predecessor digest'
$expectedChecks = @('atomic_replace', 'authority_boundary', 'candidate_preservation', 'deterministic_digests', 'file_flush', 'final_reopen', 'marker_correspondence', 'monotonic_generation', 'parent_flush', 'predecessor_reacquisition', 'registry_precondition', 'root_boundary', 'temp_create_new', 'trigger_correspondence', 'upstream_replay')
$actualChecks = @($receipt.verified_checks)
$expectedCheckSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$actualCheckSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($check in $expectedChecks) { [void]$expectedCheckSet.Add($check) }
foreach ($check in $actualChecks) {
    if (-not $actualCheckSet.Add([string]$check)) { throw "duplicate rollback verified check: $check" }
}
if ($actualCheckSet.Count -ne $expectedCheckSet.Count -or @($expectedChecks | Where-Object { -not $actualCheckSet.Contains($_) }).Count -ne 0) {
    throw 'rollback receipt verified-check set differs'
}

[ordered]@{
    profile = 'cantor-succeeding-sop-fixture-rollback-independent-verification/0.1'
    status = 'verified'
    predecessor_commit = $expectedCommit
    manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestFull).Hash
    file_ref_count = [int64]$manifest.file_ref_count
    controlled_verification_uuid = [string]$manifest.controlled_verification_uuid
    receipt_artifact_uuid = [string]$manifest.receipt_artifact_uuid
    non_authority = $expectedNonAuthority
} | ConvertTo-Json -Compress
