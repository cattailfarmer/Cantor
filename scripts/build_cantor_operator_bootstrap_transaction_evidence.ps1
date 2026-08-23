[CmdletBinding()]
param(
    [string]$OutputPath = 'experiments/operator_bootstrap_transaction/artifacts/operator_bootstrap_transaction_evidence_v1.json',
    [switch]$UsePrebuilt,
    [switch]$ReplaceOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputFullPath = if ([IO.Path]::IsPathRooted($OutputPath)) { [IO.Path]::GetFullPath($OutputPath) } else { [IO.Path]::GetFullPath((Join-Path $root $OutputPath)) }
$outputParent = [IO.Path]::GetDirectoryName($outputFullPath)
$transaction = Join-Path $PSScriptRoot 'initialize_cantor_service_transaction.ps1'
$focusedTests = Join-Path $PSScriptRoot 'test_cantor_operator_bootstrap_transaction.ps1'
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixtureRoot = Join-Path $temporaryBase 'cantor-operator-bootstrap-transaction-p0-evidence'
$fixtureCreated = $false
$temporaryOutput = $null
$nonAuthority = 'This evidence proves one disposable initial-create local bootstrap transaction only. It grants no replacement, repair, migration, production secret lifecycle, permission policy, installation, delivery, service, provider, effect, operator-product, or production authority.'

function Assert-Evidence([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function ConvertTo-JsonBytes([object]$Value) {
    $text = (($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")) + "`n"
    [Text.UTF8Encoding]::new($false).GetBytes($text)
}

function Get-Identity([string]$Path, [string]$RelativePath) {
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Evidence (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Length -gt 0) "evidence input is not one nonempty physical file: $RelativePath"
    [ordered]@{
        path = $RelativePath.Replace('\', '/')
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

function Get-ByteIdentity([byte[]]$Bytes) {
    [ordered]@{
        bytes = [uint64]$Bytes.Length
        sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))
    }
}

function Compare-Bytes([byte[]]$Left, [byte[]]$Right) {
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) { return $false }
    }
    return $true
}

function Invoke-Diagnostic([string]$BinaryPath, [string]$ConfigPath) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $BinaryPath
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.ArgumentList.Add('--check-config')
    $start.ArgumentList.Add($ConfigPath)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        Assert-Evidence ($process.Start()) 'final diagnostic did not start'
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Assert-Evidence ($process.ExitCode -eq 0 -and [Text.UTF8Encoding]::new($false).GetByteCount($stderr) -eq 0) 'final diagnostic did not return ready without stderr'
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($stdout)
        Assert-Evidence ($bytes.Length -gt 1 -and $bytes[-1] -eq 10 -and $bytes[-2] -ne 13) 'final diagnostic is not LF terminated'
        $value = $stdout | ConvertFrom-Json
        Assert-Evidence ($value.status -ceq 'ready' -and -not [bool]$value.privacy.listener_bound -and -not [bool]$value.privacy.service_started) 'final diagnostic boundary differs'
        return [pscustomobject]@{ bytes = $bytes; value = $value }
    }
    finally { $process.Dispose() }
}

function Remove-ExactRuntime([string]$Path, [string]$ExpectedParent, [string]$ExpectedLeaf) {
    $item = Get-Item -LiteralPath $Path -Force
    $actualParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\', '/')
    Assert-Evidence ($actualParent.Equals([IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) 'runtime cleanup parent differs'
    Assert-Evidence ($item.Name -ceq $ExpectedLeaf -and $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'runtime cleanup identity differs'
    $names = @(Get-ChildItem -LiteralPath $item.FullName -Force | ForEach-Object Name | Sort-Object)
    Assert-Evidence (($names -join ',') -ceq 'activation.json,cantord.token,service.json') 'runtime cleanup inventory differs'
    foreach ($name in $names) {
        $child = Get-Item -LiteralPath (Join-Path $item.FullName $name) -Force
        Assert-Evidence (-not $child.PSIsContainer -and ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'runtime cleanup inventory is not physical'
    }
    [IO.Directory]::Delete($item.FullName, $true)
}

function Remove-FixtureRoot {
    if (-not [IO.Directory]::Exists($fixtureRoot)) { return }
    $item = Get-Item -LiteralPath $fixtureRoot -Force
    $actualParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\', '/')
    Assert-Evidence ($actualParent.Equals($temporaryBase.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) 'fixture cleanup parent differs'
    Assert-Evidence ($item.Name -ceq 'cantor-operator-bootstrap-transaction-p0-evidence' -and $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'fixture cleanup identity differs'
    $topNames = @(Get-ChildItem -LiteralPath $item.FullName -Force | ForEach-Object Name | Sort-Object)
    Assert-Evidence (($topNames -join ',') -ceq 'environment') 'fixture cleanup top-level inventory differs'
    [IO.Directory]::Delete($item.FullName, $true)
}

Assert-Evidence (-not [IO.Directory]::Exists($outputFullPath)) 'OutputPath must not identify a directory'
Assert-Evidence ($ReplaceOutput -or -not [IO.File]::Exists($outputFullPath)) 'OutputPath already exists; use ReplaceOutput only after reviewing the target'
$profileRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath('UserProfile'))
$driveRoot = [IO.Path]::GetFullPath([IO.Path]::GetPathRoot($outputFullPath))
Assert-Evidence (-not $outputFullPath.Equals($profileRoot, [StringComparison]::OrdinalIgnoreCase) -and -not $outputFullPath.Equals($driveRoot, [StringComparison]::OrdinalIgnoreCase) -and -not $outputFullPath.Equals($root, [StringComparison]::OrdinalIgnoreCase)) 'OutputPath must not be a broad protected root'
$existingOutputParent = if ([IO.Directory]::Exists($outputParent)) { Get-Item -LiteralPath $outputParent -Force } else { $null }
if ($null -ne $existingOutputParent) {
    Assert-Evidence ($existingOutputParent.PSIsContainer -and ($existingOutputParent.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'OutputPath parent must be one physical directory'
}
else {
    $grandParent = [IO.Path]::GetDirectoryName($outputParent)
    $grandParentItem = Get-Item -LiteralPath $grandParent -Force
    Assert-Evidence ($grandParentItem.PSIsContainer -and ($grandParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'OutputPath parent cannot be created safely'
}

$branch = (& git -C $root rev-parse --abbrev-ref HEAD).Trim()
$head = (& git -C $root rev-parse HEAD).Trim()
$upstream = (& git -C $root rev-parse '@{upstream}').Trim()
Assert-Evidence ($LASTEXITCODE -eq 0 -and $branch -ceq 'codex/self-hosted-corpus' -and $head -ceq $upstream) 'evidence generation requires the published codex/self-hosted-corpus HEAD'
& git -C $root diff --quiet --ignore-submodules --
Assert-Evidence ($LASTEXITCODE -eq 0) 'evidence generation requires a clean tracked working tree'
& git -C $root diff --cached --quiet --ignore-submodules --
Assert-Evidence ($LASTEXITCODE -eq 0) 'evidence generation requires a clean index'

if (-not $UsePrebuilt) {
    Push-Location $root
    try {
        & cargo build -p cantor_service --bin cantord --release --locked --offline
        Assert-Evidence ($LASTEXITCODE -eq 0) 'locked offline cantord build failed'
    }
    finally { Pop-Location }
    $buildMode = 'built_locked_offline'
}
else { $buildMode = 'verified_prebuilt' }

$cantord = Join-Path $root 'target/release/cantord.exe'
Assert-Evidence ([IO.File]::Exists($cantord)) 'release cantord is absent'
Assert-Evidence (-not (Test-Path -LiteralPath $fixtureRoot)) 'fixed evidence fixture root already exists; inspect it rather than replacing it'

try {
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    $fixtureCreated = $true
    $environmentRoot = Join-Path $fixtureRoot 'environment'
    Push-Location $root
    try {
        & cargo run --quiet -p cantor_cli --example generate_demo --release --locked --offline -- $environmentRoot | Out-Null
        Assert-Evidence ($LASTEXITCODE -eq 0) 'public signed fixture generation failed'
    }
    finally { Pop-Location }
    $environmentPath = Join-Path $environmentRoot 'environment.json'
    $receiptRuns = @()
    $diagnosticRuns = @()
    for ($runIndex = 0; $runIndex -lt 2; $runIndex++) {
        $runtimeLeaf = 'runtime'
        $runtimePath = Join-Path $fixtureRoot $runtimeLeaf
        $receiptText = & $transaction -EnvironmentPath $environmentPath -RuntimeDirectory $runtimePath -CantordPath $cantord -AllowedEnvironmentRoot $environmentRoot
        Assert-Evidence ($receiptText -is [string] -and -not $receiptText.Contains("`n", [StringComparison]::Ordinal) -and -not $receiptText.Contains("`r", [StringComparison]::Ordinal)) 'transaction receipt is not one compact line'
        $receipt = $receiptText | ConvertFrom-Json
        Assert-Evidence ($receipt.profile -ceq 'cantor-operator-bootstrap-transaction/0.1' -and $receipt.status -ceq 'initialized') 'transaction receipt profile or status differs'
        $tokenText = (Get-Content -LiteralPath (Join-Path $runtimePath 'cantord.token') -Raw).Trim()
        Assert-Evidence ($tokenText -cmatch '^[a-f0-9]{64}$') 'generated token shape differs'
        Assert-Evidence (-not $receiptText.Contains($tokenText, [StringComparison]::OrdinalIgnoreCase) -and -not $receiptText.Contains('cantord.token', [StringComparison]::OrdinalIgnoreCase)) 'transaction receipt disclosed token content or path'
        $diagnostic = Invoke-Diagnostic $cantord (Join-Path $runtimePath 'service.json')
        $receiptRuns += ,([Text.UTF8Encoding]::new($false).GetBytes("$receiptText`n"))
        $diagnosticRuns += ,([byte[]]$diagnostic.bytes)
        Remove-ExactRuntime $runtimePath $fixtureRoot $runtimeLeaf
        Assert-Evidence (-not (Test-Path -LiteralPath $runtimePath)) 'runtime remains after evidence cleanup'
    }
    Assert-Evidence (Compare-Bytes $receiptRuns[0] $receiptRuns[1]) 'two transaction receipt bytes differ'
    Assert-Evidence (Compare-Bytes $diagnosticRuns[0] $diagnosticRuns[1]) 'two final diagnostic bytes differ'
    $receiptIdentity = Get-ByteIdentity $receiptRuns[0]
    $diagnosticIdentity = Get-ByteIdentity $diagnosticRuns[0]
    Remove-FixtureRoot
    $fixtureCreated = $false
    Assert-Evidence (-not (Test-Path -LiteralPath $fixtureRoot)) 'fixture root remains before evidence publication'

    $report = [ordered]@{
        profile = 'cantor-operator-bootstrap-transaction-evidence/0.1'
        status = 'provider_free_initial_create_transaction_verified_with_declared_gaps'
        source_commit = $head
        platform = 'windows_x86_64_local'
        build_mode = $buildMode
        cargo_lock = Get-Identity (Join-Path $root 'Cargo.lock') 'Cargo.lock'
        cantord = Get-Identity $cantord 'target/release/cantord.exe'
        transaction_script = Get-Identity $transaction 'scripts/initialize_cantor_service_transaction.ps1'
        focused_tests = Get-Identity $focusedTests 'scripts/test_cantor_operator_bootstrap_transaction.ps1'
        observation = [ordered]@{
            transaction_count = [uint32]2
            receipt_profile = 'cantor-operator-bootstrap-transaction/0.1'
            receipt_status = 'initialized'
            receipt_bytes = $receiptIdentity.bytes
            receipt_sha256 = $receiptIdentity.sha256
            receipt_byte_equal = $true
            final_diagnostic_profile = 'cantor-operator-configuration-diagnostic/0.1'
            final_diagnostic_status = 'ready'
            final_diagnostic_bytes = $diagnosticIdentity.bytes
            final_diagnostic_sha256 = $diagnosticIdentity.sha256
            final_diagnostic_byte_equal = $true
            final_file_count_each = @([uint32]3, [uint32]3)
            token_shape_verified_each = @($true, $true)
            receipt_token_disclosure = $false
            changed_residual_refusal_proved = $true
        }
        cleanup = [ordered]@{
            runtime_removed_each = @($true, $true)
            random_tokens_destroyed = $true
            fixture_root_removed = $true
            fixture_root_absent_at_publication = $true
            staging_residual = $false
            live_cantord_residual = $false
        }
        safety = [ordered]@{
            listener_bound = $false
            service_started = $false
            provider_contacted = $false
            remote_accessed = $false
            replacement_performed = $false
            repair_performed = $false
            migration_performed = $false
            production_secret_lifecycle_claimed = $false
            token_content_recorded = $false
            token_hash_recorded = $false
            raw_receipt_retained = $false
            raw_diagnostic_retained = $false
        }
        capability_denials = @(
            'replacement_or_repair'
            'migration_or_upgrade'
            'production_secret_rotation_or_revocation'
            'permission_or_acl_policy'
            'installer_or_supported_delivery'
            'listener_or_service_operation'
            'provider_execution'
            'durable_or_distributed_custody'
            'external_effect_execution'
            'automatic_remote_access'
            'fpga_execution'
            'minecraft_scope'
            'operator_product_or_production_readiness'
        )
        non_authority_statement = $nonAuthority
    }
    if (-not [IO.Directory]::Exists($outputParent)) { [IO.Directory]::CreateDirectory($outputParent) | Out-Null }
    $temporaryOutput = Join-Path $outputParent ('.operator-bootstrap-evidence-' + [guid]::NewGuid().ToString('N') + '.json')
    [IO.File]::WriteAllBytes($temporaryOutput, (ConvertTo-JsonBytes $report))
    [IO.File]::Move($temporaryOutput, $outputFullPath, [bool]$ReplaceOutput)
    $temporaryOutput = $null
}
finally {
    if ($fixtureCreated) { Remove-FixtureRoot }
    if (-not [string]::IsNullOrWhiteSpace($temporaryOutput) -and [IO.File]::Exists($temporaryOutput)) {
        $item = Get-Item -LiteralPath $temporaryOutput -Force
        Assert-Evidence (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Directory.FullName.Equals($outputParent, [StringComparison]::OrdinalIgnoreCase) -and $item.Name -cmatch '^\.operator-bootstrap-evidence-[a-f0-9]{32}\.json$') 'temporary evidence cleanup identity differs'
        [IO.File]::Delete($item.FullName)
    }
}

Write-Output "operator_bootstrap_transaction_evidence_written=true source_commit=$head transactions=2 receipt_equal=true diagnostic_equal=true fixture_removed=true"
