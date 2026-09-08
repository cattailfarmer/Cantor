param(
    [string]$RepositoryRoot = "",
    [string]$ImplementationCommit = "7760c78329f165a0ff7d02ec2aabc85dafbb3726",
    [string]$BookendCommit = "1aef4152568f9ad6b0abe59738ef20f213b0a574"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
}
else {
    $RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
}

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-GitText([string[]]$Arguments) {
    $output = @(& git -C $RepositoryRoot @Arguments 2>&1)
    Assert-Exact ($LASTEXITCODE -eq 0) "git object query failed"
    return (($output | ForEach-Object { $_.ToString() }) -join "`n").TrimEnd()
}

function Read-GitBlob([string]$Commit, [string]$Path) {
    Assert-Exact (-not [IO.Path]::IsPathRooted($Path)) "bound path is rooted"
    Assert-Exact ($Path -notmatch '(^|/)\.\.(/|$)') "bound path traverses"
    $objectId = Invoke-GitText @("rev-parse", "${Commit}:$Path")
    Assert-Exact ($objectId -match '^[0-9a-f]{40}$') "bound blob identity differs"
    $git = (Get-Command git -ErrorAction Stop).Source
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $git
    $start.Arguments = "-C `"$RepositoryRoot`" cat-file blob $objectId"
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    Assert-Exact $process.Start() "git blob reader did not start"
    $memory = [IO.MemoryStream]::new()
    $process.StandardOutput.BaseStream.CopyTo($memory)
    $errorText = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    Assert-Exact ($process.ExitCode -eq 0 -and $errorText.Length -eq 0) "git blob read failed"
    return $memory.ToArray()
}

function Get-Sha256([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace("-", "")
    }
    finally {
        $hasher.Dispose()
    }
}

function Read-Utf8([byte[]]$Bytes) {
    return [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
}

function Assert-BlobBinding(
    [string]$Commit,
    [string]$Path,
    [long]$ExpectedBytes,
    [string]$ExpectedSha256
) {
    $bytes = @(Read-GitBlob $Commit $Path)
    Assert-Exact ($bytes.Count -eq $ExpectedBytes) "bound byte count differs: $Path"
    Assert-Exact ((Get-Sha256 $bytes) -ceq $ExpectedSha256) "bound SHA256 differs: $Path"
}

Assert-Exact ($ImplementationCommit -match '^[0-9a-f]{40}$') "implementation commit shape differs"
Assert-Exact ($BookendCommit -match '^[0-9a-f]{40}$') "bookend commit shape differs"
Assert-Exact ((Invoke-GitText @("rev-parse", "${ImplementationCommit}^")) -ceq "4ed054efed00dc1866f6a4b82eb711530d45f602") "implementation predecessor differs"
Assert-Exact ((Invoke-GitText @("rev-parse", "${BookendCommit}^")) -ceq $ImplementationCommit) "bookend predecessor differs"

$implementationPaths = @((Invoke-GitText @("diff-tree", "--no-commit-id", "--name-only", "-r", $ImplementationCommit)) -split "`n")
Assert-Exact ($implementationPaths.Count -eq 68) "implementation path count differs"
$bookendPaths = @((Invoke-GitText @("diff-tree", "--no-commit-id", "--name-only", "-r", $BookendCommit)) -split "`n" | Sort-Object)
$expectedBookendPaths = @(
    "narrative/change_sets/4fd3729d-0c99-451e-99a0-98711e6acab1.sop",
    "narrative/file_changes/1788836843659_b1_a8_implementation_publication.sop",
    "narrative/reentry/Cantor_B1_Production_Broker_Projection_Correspondence_P0_Reentry.sop",
    "narrative/turns/1788836843659_b1_a8_implementation_publication.sop",
    "proofs/Cantor_B1_Production_Broker_Projection_Correspondence_P0_Implementation_Publication_Proof.sop"
) | Sort-Object
Assert-Exact ($bookendPaths.Count -eq $expectedBookendPaths.Count) "bookend path count differs"
for ($index = 0; $index -lt $expectedBookendPaths.Count; $index++) {
    Assert-Exact ($bookendPaths[$index] -ceq $expectedBookendPaths[$index]) "bookend path differs"
}

$signaturePath = "narrative/registries/Cantor_B1_Production_Broker_Projection_Correspondence_P0_Completion_Satisfaction_Signature.sop"
$signature = Read-Utf8 @(Read-GitBlob $ImplementationCommit $signaturePath)
Assert-Exact ($signature.Contains("@ [completion_signature_uuid] 21206f1e-c24d-4924-aac8-17562ccd2d9e")) "completion signature UUID differs"
$bindingPattern = '(?m)^  \+ \[artifact_binding\] (?<path>.+) bytes(?<bytes>[0-9]+) SHA256 (?<sha>[0-9A-F]{64})\r?$'
$bindings = @([regex]::Matches($signature, $bindingPattern))
Assert-Exact ($bindings.Count -eq 10) "completion binding count differs"
foreach ($binding in $bindings) {
    Assert-BlobBinding $ImplementationCommit $binding.Groups["path"].Value ([long]$binding.Groups["bytes"].Value) $binding.Groups["sha"].Value
}

$sourceBindings = @(
    @("crates/cantor_ecosystem/src/b1_production_broker_projection_correspondence.rs", 91949, "3EC2830D2C001F839FE2368C5531AE808EDDFB9894263AEA93D870A600AE4489"),
    @("crates/cantor_ecosystem/src/b1_production_broker_projection_correspondence_evidence.rs", 17943, "160306063986114633F370F817BE7EAF2F46A09914A171CF227837A26618C0E0"),
    @("crates/cantor_ecosystem/src/bin/cantor-b1-production-broker-projection-verify.rs", 540, "A4554CE01D939B9295AE9EF650F78588DD8BD07D2BCBFA9956573006271EF3ED"),
    @("crates/cantor_ecosystem/src/bin/cantor-b1-production-broker-projection-evidence-verify.rs", 697, "9923B5F19C216590A458AE2E095C2C8AB95B5FE0DAC1F61060D4009C9EF2CD33"),
    @("crates/cantor_ecosystem/tests/b1_production_broker_projection_correspondence.rs", 41895, "719CA381E13663531FBB8B074F4871100E950B073C471DAA36D54BEECA891A45")
)
foreach ($binding in $sourceBindings) {
    Assert-BlobBinding $ImplementationCommit $binding[0] ([long]$binding[1]) $binding[2]
}

$gatePath = "experiments/b1_production_broker_projection_correspondence_p0/implementation_gate_results.json"
$gate = Read-Utf8 @(Read-GitBlob $ImplementationCommit $gatePath) | ConvertFrom-Json
Assert-Exact ($gate.workspace_gates.Count -eq 2) "workspace profile count differs"
foreach ($profile in $gate.workspace_gates) {
    Assert-Exact ($profile.result_groups -eq 305 -and $profile.passed -eq 1881 -and $profile.failed -eq 0 -and $profile.ignored -eq 21) "workspace gate differs"
}
Assert-Exact ($gate.focused_gates.Count -eq 2) "focused profile count differs"
foreach ($profile in $gate.focused_gates) {
    Assert-Exact ($profile.unit_passed -eq 14 -and $profile.integration_passed -eq 12 -and $profile.failed -eq 0 -and $profile.ignored -eq 1) "focused gate differs"
}
Assert-Exact ($gate.authority_boundary.pinned_provider_status -ceq "provider_unavailable") "provider status differs"
Assert-Exact ($gate.authority_boundary.live_provider_trials -eq 0 -and $gate.authority_boundary.synthetic_provider_trials -eq 0) "provider trial account differs"
Assert-Exact (-not $gate.authority_boundary.execution_authorized -and $gate.authority_boundary.effect_count -eq 0) "gate authority differs"

$evidenceRoot = "experiments/b1_production_broker_projection_correspondence_p0/implementation_provider_free_evidence"
$evidencePaths = @((Invoke-GitText @("ls-tree", "-r", "--name-only", $ImplementationCommit, "--", $evidenceRoot)) -split "`n")
Assert-Exact ($evidencePaths.Count -eq 34) "retained evidence file count differs"
Assert-BlobBinding $ImplementationCommit "$evidenceRoot/evidence_manifest.json" 6199 "64E98F47FD01E28D339B1B73FD5EFC85032A0AE559FBCDB2AE98594BA97CBD7E"
Assert-BlobBinding $ImplementationCommit "$evidenceRoot/receipt.json" 23018 "763FD0992498528BDB278554349F5A6AA5A4D3C5172F9D2C7DF9FDDBE841EAD6"
$manifest = Read-Utf8 @(Read-GitBlob $ImplementationCommit "$evidenceRoot/evidence_manifest.json") | ConvertFrom-Json
$receipt = Read-Utf8 @(Read-GitBlob $ImplementationCommit "$evidenceRoot/receipt.json") | ConvertFrom-Json
Assert-Exact ($manifest.artifact_count -eq 33 -and $manifest.total_artifact_bytes -eq 202015) "retained manifest account differs"
$falseAuthority = @(
    "production_authority_claimed", "private_execution_permit_present", "permit_material_authenticated",
    "permit_dependency_satisfied", "broker_endpoint_resolved", "broker_reachable", "broker_identity_proved",
    "broker_authority_proved", "broker_session_authenticated", "broker_activation_authorized",
    "production_broker_projection_present", "live_authorization_admitted", "physical_preparation_authorized",
    "ready_for_physical_execution", "execution_authorized"
)
foreach ($field in $falseAuthority) { Assert-Exact (-not $receipt.$field) "A8 authority promoted: $field" }
$effects = @($receipt.effect_account.PSObject.Properties)
Assert-Exact ($effects.Count -eq 22) "effect field count differs"
foreach ($effect in $effects) {
    if ($effect.Name -ceq "physical_contact") { Assert-Exact (-not $effect.Value) "physical contact differs" }
    else { Assert-Exact ($effect.Value -eq 0) "effect count differs: $($effect.Name)" }
}

$publicationPath = "proofs/Cantor_B1_Production_Broker_Projection_Correspondence_P0_Implementation_Publication_Proof.sop"
$publication = Read-Utf8 @(Read-GitBlob $BookendCommit $publicationPath)
Assert-Exact ($publication.Contains("@ [implementation_commit] $ImplementationCommit")) "publication implementation binding differs"
Assert-Exact ($publication.Contains("@ [completion_signature_uuid] 21206f1e-c24d-4924-aac8-17562ccd2d9e")) "publication signature binding differs"

$remoteRef = "refs/remotes/origin/codex/self-hosted-corpus"
& git -C $RepositoryRoot show-ref --verify --quiet $remoteRef
if ($LASTEXITCODE -eq 0) {
    & git -C $RepositoryRoot merge-base --is-ancestor $BookendCommit $remoteRef
    Assert-Exact ($LASTEXITCODE -eq 0) "remote tracking ref does not contain the A8 bookend"
}

Write-Output "cantor_b1_a8_completion_verified=true implementation=$ImplementationCommit bookend=$BookendCommit implementation_paths=68 bookend_paths=5 source_bindings=5 completion_bindings=10 evidence_files=34 payloads=33 workspace_profiles=2 focused_profiles=2 false_authority=15 effects=0 provider_trials=0"
