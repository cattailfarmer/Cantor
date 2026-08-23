[CmdletBinding()]
param(
    [string]$OutputDirectory = 'experiments/provider_free_release_signature_verification/artifacts',
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Distro = 'Ubuntu-24.04',
    [ValidatePattern('^/home/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+$')]
    [string]$TargetDir = '/home/pinky/.cache/cantor-release-signature-evidence-target',
    [switch]$UsePrebuilt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputFullPath = if ([IO.Path]::IsPathRooted($OutputDirectory)) { [IO.Path]::GetFullPath($OutputDirectory) } else { [IO.Path]::GetFullPath((Join-Path $root $OutputDirectory)) }
$outputParent = [IO.Path]::GetDirectoryName($outputFullPath)
$outputLeaf = [IO.Path]::GetFileName($outputFullPath)
$stagingPath = Join-Path $outputParent ('.crsv-evidence-' + [guid]::NewGuid().ToString('N'))
$stagingCreated = $false
$fixtureRoot = '/tmp/cantor-release-signature-evidence'
$archive = Join-Path $root 'experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0.zip'
$bundleEvidence = Join-Path $root 'experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0-evidence.json'
$nonAuthority = 'This checked synthetic fixture proves detached release-signature mechanics only. It does not prove policy governance publisher identity trust onboarding supported delivery installation production secret lifecycle operator acceptance or production authority.'
$names = @(
    'release_signature_policy_synthetic_v1.json',
    'release_signature_envelope_synthetic_v1.json',
    'release_signature_receipt_synthetic_v1.json',
    'cantor-release-verify-linux-x86_64',
    'release_signature_evidence_v1.json'
)

function Assert-Evidence([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Get-Identity([string]$Path, [string]$Label) {
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Evidence (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Length -gt 0) "identity is not one nonempty physical file: $Label"
    [ordered]@{ path = $Label.Replace('\', '/'); bytes = [uint64]$item.Length; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash }
}
function Write-Json([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path, "$(($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
}
function Remove-ExactStaging {
    if (-not [IO.Directory]::Exists($stagingPath)) { return }
    $item = Get-Item -LiteralPath $stagingPath -Force
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\', '/')
    Assert-Evidence ($parent.Equals([IO.Path]::GetFullPath($outputParent).TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase) -and $item.Name -cmatch '^\.crsv-evidence-[a-f0-9]{32}$' -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'staging cleanup identity differs'
    [IO.Directory]::Delete($item.FullName, $true)
}

Assert-Evidence (-not (Test-Path -LiteralPath $outputFullPath)) 'OutputDirectory must be absent'
Assert-Evidence ($outputFullPath.StartsWith($root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -and $outputLeaf -notmatch '^\.?$') 'OutputDirectory must be one contained non-root directory'
$parentItem = Get-Item -LiteralPath $outputParent -Force
Assert-Evidence ($parentItem.PSIsContainer -and ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'OutputDirectory parent must be one physical directory'
foreach ($input in @($archive, $bundleEvidence)) { $null = Get-Identity $input $input }
$branch = (& git -C $root rev-parse --abbrev-ref HEAD).Trim()
$head = (& git -C $root rev-parse HEAD).Trim()
$upstream = (& git -C $root rev-parse '@{upstream}').Trim()
Assert-Evidence ($LASTEXITCODE -eq 0 -and $branch -ceq 'codex/self-hosted-corpus' -and $head -ceq $upstream) 'evidence generation requires the published branch HEAD'
& git -C $root diff --quiet --ignore-submodules --
Assert-Evidence ($LASTEXITCODE -eq 0) 'evidence generation requires a clean tracked tree'
& git -C $root diff --cached --quiet --ignore-submodules --
Assert-Evidence ($LASTEXITCODE -eq 0) 'evidence generation requires a clean index'

try {
    [IO.Directory]::CreateDirectory($stagingPath) | Out-Null
    $stagingCreated = $true
    $stagingRelative = $stagingPath.Substring($root.Length + 1).Replace('\', '/')
    $buildLine = if ($UsePrebuilt) { 'test -x "$binary"' } else { 'cargo build -p cantor_release_signature --release --locked --offline --bin cantor-release-verify --example generate_release_signature_fixture' }
    $bash = @'
set -euo pipefail
export CARGO_TARGET_DIR='__TARGET__'
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true
export LC_ALL=C
repo=$(pwd)
binary="$CARGO_TARGET_DIR/release/cantor-release-verify"
generator="$CARGO_TARGET_DIR/release/examples/generate_release_signature_fixture"
fixture='/tmp/cantor-release-signature-evidence'
stage="$repo/__STAGING__"
bundle="$repo/experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0.zip"
evidence="$repo/experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0-evidence.json"
cleanup() {
  if [ -d "$fixture" ] && [ "$(dirname "$fixture")" = '/tmp' ] && [ "$(basename "$fixture")" = 'cantor-release-signature-evidence' ]; then
    rm -r -- "$fixture"
  fi
}
trap cleanup EXIT
test ! -e "$fixture"
__BUILD__
test -x "$binary"
test -x "$generator"
"$generator" "$bundle" "$evidence" "$fixture" >/dev/null
"$binary" --bundle "$bundle" --bundle-evidence "$evidence" --policy "$fixture/policy.json" --envelope "$fixture/envelope.json" > "$fixture/receipt-1.json"
"$binary" --bundle "$bundle" --bundle-evidence "$evidence" --policy "$fixture/policy.json" --envelope "$fixture/envelope.json" > "$fixture/receipt-2.json"
cmp -s "$fixture/receipt-1.json" "$fixture/receipt-2.json"
cp "$fixture/policy.json" "$stage/release_signature_policy_synthetic_v1.json"
cp "$fixture/envelope.json" "$stage/release_signature_envelope_synthetic_v1.json"
cp "$fixture/receipt-1.json" "$stage/release_signature_receipt_synthetic_v1.json"
cp "$binary" "$stage/cantor-release-verify-linux-x86_64"
cleanup
trap - EXIT
test ! -e "$fixture"
printf 'release_signature_wsl_execution=passed\n'
'@
    $bash = $bash.Replace('__TARGET__', $TargetDir).Replace('__STAGING__', $stagingRelative).Replace('__BUILD__', $buildLine)
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($bash))
    & wsl.exe -d $Distro --cd $root -- bash -lc "set -o pipefail; printf '%s' '$payload' | base64 --decode | bash"
    Assert-Evidence ($LASTEXITCODE -eq 0) 'guarded WSL signature execution failed'

    $policyPath = Join-Path $stagingPath $names[0]
    $envelopePath = Join-Path $stagingPath $names[1]
    $receiptPath = Join-Path $stagingPath $names[2]
    $binaryPath = Join-Path $stagingPath $names[3]
    $policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
    $envelope = Get-Content -LiteralPath $envelopePath -Raw | ConvertFrom-Json
    $receiptText = Get-Content -LiteralPath $receiptPath -Raw
    $receipt = $receiptText | ConvertFrom-Json
    Assert-Evidence ($policy.use_status -ceq 'synthetic_fixture_only' -and $envelope.payload.use_status -ceq 'synthetic_fixture_only' -and $receipt.use_status -ceq 'synthetic_fixture_only') 'synthetic status differs'
    Assert-Evidence ([bool]$receipt.signature_verified -and -not [bool]$receipt.safety.policy_governance_proved -and -not [bool]$receipt.safety.production_publisher_authenticity_proved) 'receipt authority boundary differs'
    Assert-Evidence (-not $receiptText.Contains($root, [StringComparison]::OrdinalIgnoreCase) -and -not $receiptText.Contains('signature_hex', [StringComparison]::OrdinalIgnoreCase) -and -not $receiptText.Contains('verifying_key_hex', [StringComparison]::OrdinalIgnoreCase)) 'receipt disclosed path key or signature'
    $elf = [IO.File]::ReadAllBytes($binaryPath)
    Assert-Evidence ($elf.Length -gt 4 -and $elf[0] -eq 0x7F -and $elf[1] -eq 0x45 -and $elf[2] -eq 0x4C -and $elf[3] -eq 0x46) 'retained verifier is not one ELF binary'
    $report = [ordered]@{
        profile = 'cantor-provider-free-release-signature-evidence/0.1'
        status = 'synthetic_signature_mechanics_verified_with_declared_trust_gaps'
        source_commit = $head
        execution_platform = 'linux_x86_64_wsl2'
        signed_artifact_target = 'windows-x86_64'
        build_mode = $(if ($UsePrebuilt) { 'verified_prebuilt' } else { 'built_locked_offline' })
        bundle_input = Get-Identity $archive 'experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0.zip'
        bundle_evidence_input = Get-Identity $bundleEvidence 'experiments/provider_free_portable_release_bundle/artifacts/cantor-provider-free-windows-x86_64-p0-evidence.json'
        sources = [ordered]@{
            cargo_lock = Get-Identity (Join-Path $root 'Cargo.lock') 'Cargo.lock'
            workspace_manifest = Get-Identity (Join-Path $root 'Cargo.toml') 'Cargo.toml'
            crate_manifest = Get-Identity (Join-Path $root 'crates/cantor_release_signature/Cargo.toml') 'crates/cantor_release_signature/Cargo.toml'
            library = Get-Identity (Join-Path $root 'crates/cantor_release_signature/src/lib.rs') 'crates/cantor_release_signature/src/lib.rs'
            cli = Get-Identity (Join-Path $root 'crates/cantor_release_signature/src/main.rs') 'crates/cantor_release_signature/src/main.rs'
            fixture_helper = Get-Identity (Join-Path $root 'crates/cantor_release_signature/examples/generate_release_signature_fixture.rs') 'crates/cantor_release_signature/examples/generate_release_signature_fixture.rs'
            library_tests = Get-Identity (Join-Path $root 'crates/cantor_release_signature/tests/release_signature.rs') 'crates/cantor_release_signature/tests/release_signature.rs'
            cli_tests = Get-Identity (Join-Path $root 'crates/cantor_release_signature/tests/release_signature_cli.rs') 'crates/cantor_release_signature/tests/release_signature_cli.rs'
            producer = Get-Identity $PSCommandPath 'scripts/build_cantor_provider_free_release_signature_evidence.ps1'
            verifier = Get-Identity (Join-Path $PSScriptRoot 'verify_cantor_provider_free_release_signature_evidence.ps1') 'scripts/verify_cantor_provider_free_release_signature_evidence.ps1'
            adversarial_tests = Get-Identity (Join-Path $PSScriptRoot 'test_cantor_provider_free_release_signature_evidence.ps1') 'scripts/test_cantor_provider_free_release_signature_evidence.ps1'
        }
        artifacts = [ordered]@{
            policy = Get-Identity $policyPath $names[0]
            envelope = Get-Identity $envelopePath $names[1]
            receipt = Get-Identity $receiptPath $names[2]
            verifier_binary = Get-Identity $binaryPath $names[3]
        }
        observation = [ordered]@{
            verification_count = [uint32]2
            receipt_byte_equal = $true
            signature_verified = $true
            use_status = 'synthetic_fixture_only'
            policy_governance_proved = $false
            production_publisher_authenticity_proved = $false
            supported_delivery_proved = $false
        }
        cleanup = [ordered]@{ fixture_root_removed = $true; fixture_root_absent_at_publication = $true; signing_key_retained = $false; live_process_retained = $false }
        safety = [ordered]@{ archive_extracted = $false; archive_executed = $false; installation_performed = $false; service_started = $false; provider_contacted = $false; remote_accessed = $false; production_secret_created = $false; trust_state_mutated = $false }
        capability_denials = @('policy_governance', 'production_publisher_authenticity', 'trust_onboarding', 'supported_delivery', 'installation_or_extraction', 'production_secret_lifecycle', 'service_or_provider_operation', 'automatic_remote_access', 'external_effect_execution', 'fpga_execution', 'minecraft_scope')
        non_authority_statement = $nonAuthority
    }
    $reportPath = Join-Path $stagingPath $names[4]
    Write-Json $reportPath $report
    $actualNames = @(Get-ChildItem -LiteralPath $stagingPath -Force | ForEach-Object Name | Sort-Object)
    Assert-Evidence (($actualNames -join ',') -ceq (($names | Sort-Object) -join ',')) 'evidence staging inventory differs'
    [IO.Directory]::Move($stagingPath, $outputFullPath)
    $stagingCreated = $false
}
finally { if ($stagingCreated) { Remove-ExactStaging } }

Write-Output "release_signature_evidence_written=true source_commit=$head executions=2 receipt_equal=true fixture_removed=true output=$outputFullPath"
