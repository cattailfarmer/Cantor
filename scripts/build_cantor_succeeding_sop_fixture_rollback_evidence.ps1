[CmdletBinding()]
param(
    [string]$Distro = 'Ubuntu-24.04',
    [string]$ReceiptPath = 'experiments/succeeding_sop_fixture_rollback_p0/artifacts/succeeding_sop_fixture_rollback_receipt.json',
    [string]$ControlledPath = 'experiments/succeeding_sop_fixture_rollback_p0/artifacts/controlled_verification.json',
    [string]$ManifestPath = 'experiments/succeeding_sop_fixture_rollback_p0/artifacts/succeeding_sop_fixture_rollback_evidence_manifest.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $root 'experiments/succeeding_sop_fixture_rollback_p0/artifacts'))
$utf8 = [Text.UTF8Encoding]::new($false)

function Get-DescendantRelativePath([string]$Base, [string]$Path, [string]$Failure) {
    $baseFull = [IO.Path]::GetFullPath($Base).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $pathFull = [IO.Path]::GetFullPath($Path)
    if ($pathFull.Equals($baseFull, [StringComparison]::OrdinalIgnoreCase)) { return '' }
    $prefix = $baseFull + [IO.Path]::DirectorySeparatorChar
    if (-not $pathFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw $Failure }
    return $pathFull.Substring($prefix.Length)
}

function Resolve-Output([string]$Path) {
    $resolved = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $root $Path))
    }
    $artifactRelative = Get-DescendantRelativePath $artifactRoot $resolved "evidence output is not one ordinary JSON file beneath the governed artifact root: $Path"
    if ($artifactRelative.Contains(':') -or
        [IO.Path]::GetExtension($resolved) -ine '.json') {
        throw "evidence output is not one ordinary JSON file beneath the governed artifact root: $Path"
    }
    return $resolved
}

function Relative-Path([string]$Path) {
    return (Get-DescendantRelativePath $root $Path 'evidence path escapes repository root').Replace('\', '/')
}

function Assert-NoReparseAncestors([string]$Path) {
    $cursor = $root
    $rootItem = Get-Item -Force -LiteralPath $cursor
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'repository root is a reparse point'
    }
    $relative = Get-DescendantRelativePath $root $Path 'evidence ancestor escapes repository root'
    foreach ($segment in @($relative -split '[\\/]' | Where-Object { $_.Length -gt 0 })) {
        $cursor = Join-Path $cursor $segment
        if ([IO.Directory]::Exists($cursor) -or [IO.File]::Exists($cursor)) {
            $item = Get-Item -Force -LiteralPath $cursor
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "evidence output ancestor is a reparse point: $cursor"
            }
        }
    }
}

function File-Ref([string]$Relative) {
    $full = [IO.Path]::GetFullPath((Join-Path $root $Relative))
    $normalizedRelative = Get-DescendantRelativePath $root $full "evidence input escapes ordinary repository path: $Relative"
    if ($normalizedRelative.Contains(':')) {
        throw "evidence input escapes ordinary repository path: $Relative"
    }
    if (-not [IO.File]::Exists($full)) { throw "evidence input missing: $Relative" }
    Assert-NoReparseAncestors ([IO.Path]::GetDirectoryName($full))
    $item = Get-Item -Force -LiteralPath $full
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or [bool]$item.PSIsContainer) {
        throw "evidence input is not one ordinary file: $Relative"
    }
    return [ordered]@{
        path = $normalizedRelative.Replace('\', '/')
        bytes = [int64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
    }
}

function ConvertTo-LfJson([object]$Value) {
    return (($Value | ConvertTo-Json -Depth 12) -replace "`r`n", "`n") + "`n"
}

$head = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne 'e1b31b4f555fbb2605eeeffaf60af9915c230a00') {
    throw 'B2B2 evidence must be built over the published B2B1 bookend'
}

$receiptFull = Resolve-Output $ReceiptPath
$controlledFull = Resolve-Output $ControlledPath
$manifestFull = Resolve-Output $ManifestPath
$outputSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($output in @($receiptFull, $controlledFull, $manifestFull)) {
    if (-not $outputSet.Add($output)) { throw 'B2B2 evidence outputs must be three distinct paths' }
    Assert-NoReparseAncestors ([IO.Path]::GetDirectoryName($output))
}

$expectedGateReceipt = 'cantor-succeeding-sop-fixture-rollback-wsl-gate-receipt/0.1 b2a_debug=45 combined_debug=16 rollback_debug=9 b2a_release=45 combined_release=16 rollback_release=9 clippy=pass format=pass'
$gateLines = @(& (Join-Path $PSScriptRoot 'test_cantor_succeeding_sop_fixture_rollback.ps1') -Distro $Distro)
if ($LASTEXITCODE -ne 0) { throw 'focused rollback gates failed before evidence production' }
if (@($gateLines | Where-Object { $_ -ceq $expectedGateReceipt }).Count -ne 1) {
    throw 'focused rollback gate receipt differs before evidence production'
}

$command = @'
set -euo pipefail
cd /mnt/c/Project/Cantor
export CARGO_TARGET_DIR=/tmp/cantor-sfr-p0-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 LC_ALL=C
"$HOME/.cargo/bin/cargo" run -q -p cantor_ecosystem --example succeeding_sop_fixture_rollback_fixture --locked --offline
'@
$transport = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($command))
$receiptLines = @(& wsl.exe -d $Distro --cd $root -- bash -lc "set -o pipefail; printf '%s' '$transport' | base64 --decode | bash")
if ($LASTEXITCODE -ne 0) { throw 'rollback receipt fixture generation failed' }
$receiptForm = $receiptLines -join "`n"
$receipt = $receiptForm | ConvertFrom-Json
if ($receipt.profile -cne 'cantor-succeeding-sop-fixture-rollback-receipt/0.1' -or
    $receipt.status -cne 'fixture_registry_rolled_back_awaiting_boot_validation' -or
    $receipt.authority -cne 'synthetic_fixture_recovery_only' -or
    -not [bool]$receipt.physical_contact -or
    -not [bool]$receipt.current_successor_observed -or
    -not [bool]$receipt.predecessor_source_reacquired -or
    -not [bool]$receipt.registry_persisted -or
    -not [bool]$receipt.predecessor_selected -or
    -not [bool]$receipt.rollback_executed -or
    -not [bool]$receipt.failed_candidate_preserved -or
    -not [bool]$receipt.temp_absent_after -or
    [bool]$receipt.boot_activation_verified -or
    [bool]$receipt.live_activation_performed -or
    [bool]$receipt.provider_contacted -or
    [bool]$receipt.model_called -or
    [bool]$receipt.process_launched -or
    [bool]$receipt.network_contacted -or
    [bool]$receipt.cleanup_performed -or
    [bool]$receipt.windows_durability_assumed -or
    [int64]$receipt.current_failed_record.current.generation -ne 42 -or
    [int64]$receipt.restored_record.current.generation -ne 43 -or
    [int64]$receipt.current_failed_record.current.current_source_bytes -ne 93 -or
    [int64]$receipt.restored_record.current.current_source_bytes -ne 93 -or
    $receipt.current_failed_record.current.current_source_path -cne 'source_documents/reviewed_succeeding_sop/Cantor_Fixture_Succeeding_SOP_Source.sop' -or
    $receipt.restored_record.current.current_source_path -cne 'source_documents/current_sop_fixture/Cantor_Current_SOP_Source.sop' -or
    $receipt.failed_candidate_source_raw_digest.algorithm -cne 'sha256' -or
    $receipt.failed_candidate_source_raw_digest.value -cne '4902d55b37710df8827f981bf73a8afd9a63bd40e94ad89ba873c2311be3f554' -or
    $receipt.predecessor_source_raw_digest.algorithm -cne 'sha256' -or
    $receipt.predecessor_source_raw_digest.value -cne 'e8405fae0ee54f9fdfb39ea84b3fa6e710c5163fbc916b11a9efefddf0564a61') {
    throw 'rollback receipt fixture boundary differs'
}

foreach ($directory in @([IO.Path]::GetDirectoryName($receiptFull), [IO.Path]::GetDirectoryName($controlledFull), [IO.Path]::GetDirectoryName($manifestFull))) {
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    Assert-NoReparseAncestors $directory
}
[IO.File]::WriteAllText($receiptFull, "$receiptForm`n", $utf8)
$receiptRef = File-Ref (Relative-Path $receiptFull)

$controlled = [ordered]@{
    profile = 'cantor-succeeding-sop-fixture-rollback-controlled-verification/0.1'
    verification_uuid = 'a72eb152-0465-4aac-94ac-d62920d0b65c'
    generated_at_utc = '2026-08-26T01:39:29Z'
    predecessor_commit = $head
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
    focused = [ordered]@{
        gate_receipt = $expectedGateReceipt
        b2a_debug_tests = 45
        combined_debug_tests = 16
        rollback_debug_tests = 9
        b2a_overflow_release_tests = 45
        combined_overflow_release_tests = 16
        rollback_overflow_release_tests = 9
        failures = 0
    }
    receipt = $receiptRef
    result = [ordered]@{
        failed_generation = 42
        restored_generation = 43
        failed_source_bytes = 93
        restored_source_bytes = 93
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
        process_launched = $false
        network_contacted = $false
        cleanup_performed = $false
    }
    non_authority = 'This controlled verification proves only deterministic recovery-owned rollback inside one disposable synthetic fixture with durable Linux file and parent flush. It proves no observed boot truth, operator consent, live root, external activation, provider, model, process, network, cleanup, Windows durability success, remote, FPGA, or Minecraft authority.'
}
[IO.File]::WriteAllText($controlledFull, (ConvertTo-LfJson $controlled), $utf8)

$sourcePaths = @(
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
    'specifications/exploded/Cantor_Succeeding_SOP_Fixture_Rollback_P0.exploded.sop',
    (Relative-Path $controlledFull),
    (Relative-Path $receiptFull)
)
$sourceSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($sourcePath in $sourcePaths) {
    if (-not $sourceSet.Add($sourcePath.Replace('\', '/'))) {
        throw "duplicate B2B2 evidence source path: $sourcePath"
    }
}
$fileRefs = @($sourcePaths | Sort-Object -CaseSensitive | ForEach-Object { File-Ref $_ })
if ($fileRefs.Count -ne $sourcePaths.Count) { throw 'B2B2 evidence source reference count differs' }
$manifest = [ordered]@{
    profile = 'cantor-succeeding-sop-fixture-rollback-evidence-manifest/0.1'
    manifest_uuid = 'ac51906f-c9be-49f5-8f7c-b0eb5047eb44'
    generated_at_utc = '2026-08-26T01:39:29Z'
    predecessor_commit = $head
    controlled_verification_uuid = 'a72eb152-0465-4aac-94ac-d62920d0b65c'
    receipt_artifact_uuid = 'e130e754-b180-4361-a52f-2b6fb5fcf2ba'
    file_ref_count = [int64]$fileRefs.Count
    file_refs = $fileRefs
    non_authority_statement = $controlled.non_authority
}
[IO.File]::WriteAllText($manifestFull, (ConvertTo-LfJson $manifest), $utf8)
Write-Output "succeeding_sop_fixture_rollback_evidence_built receipt_sha256=$($receiptRef.sha256) manifest_sha256=$((Get-FileHash $manifestFull -Algorithm SHA256).Hash)"
