[CmdletBinding()]
param(
    [string]$OutputDirectory = 'experiments/provider_free_portable_release_bundle/artifacts',
    [switch]$UsePrebuilt,
    [switch]$ReplaceOutputs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputDirectoryPath = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
    [IO.Path]::GetFullPath($OutputDirectory)
}
else {
    [IO.Path]::GetFullPath((Join-Path $root $OutputDirectory))
}
$archiveName = 'cantor-provider-free-windows-x86_64-p0.zip'
$reportName = 'cantor-provider-free-windows-x86_64-p0-evidence.json'
$archivePath = Join-Path $outputDirectoryPath $archiveName
$reportPath = Join-Path $outputDirectoryPath $reportName
$fixedTimestamp = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
$maxEntryBytes = [uint64](16MB)
$maxArchiveBytes = [uint64](16MB)
$stagingPath = $null

function Assert-Bundle([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Get-Identity([string]$Path, [string]$RelativePath, [string]$Role) {
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Bundle (-not $item.PSIsContainer) "bundle input is not a regular file: $RelativePath"
    Assert-Bundle (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "bundle input is a reparse point: $RelativePath"
    Assert-Bundle ([uint64]$item.Length -gt 0 -and [uint64]$item.Length -le $maxEntryBytes) "bundle input size is outside the admitted range: $RelativePath"
    [ordered]@{
        path = $RelativePath.Replace('\', '/')
        role = $Role
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
}

function Get-ByteIdentity([byte[]]$Bytes, [string]$RelativePath, [string]$Role) {
    Assert-Bundle ([uint64]$Bytes.Length -gt 0 -and [uint64]$Bytes.Length -le $maxEntryBytes) "generated entry size is outside the admitted range: $RelativePath"
    [ordered]@{
        path = $RelativePath
        role = $Role
        bytes = [uint64]$Bytes.Length
        sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))
    }
}

function ConvertTo-CanonicalJsonBytes([object]$Value) {
    $text = (($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")) + "`n"
    [Text.UTF8Encoding]::new($false).GetBytes($text)
}

function New-OperatorReadmeBytes([string]$SourceCommit) {
    $text = @(
        'Cantor provider-free portable release bundle candidate'
        ''
        'Profile: cantor-provider-free-portable-release-bundle/0.1'
        "Source commit: $SourceCommit"
        'Target: windows-x86_64'
        ''
        'Contents: cantor.exe, cantor-corpus.exe, cantord.exe, cantorctl.exe, and bundle-manifest.json.'
        'Verification: use scripts/verify_cantor_provider_free_portable_release_bundle.ps1 with the companion evidence JSON in the governed source repository.'
        ''
        'This archive is not an installer. Verification does not extract or execute it.'
        'No production trust, secret, configuration, provider, persistence, effect, remote, FPGA, Minecraft, operator-product, or production authority is granted.'
        ''
    ) -join "`n"
    [Text.UTF8Encoding]::new($false).GetBytes($text)
}

function New-BundleManifestBytes(
    [string]$SourceCommit,
    [object]$CargoLock,
    [object[]]$PayloadEntries
) {
    $manifest = [ordered]@{
        profile = 'cantor-provider-free-portable-release-bundle-manifest/0.1'
        source_commit = $SourceCommit
        target = 'windows-x86_64'
        cargo_lock = $CargoLock
        archive_format = [ordered]@{
            format = 'zip'
            compression = 'store'
            timestamp_contract = 'zip_dos_epoch_1980_01_01_00_00_00'
            entry_order = 'ordinal_path'
            entry_count = [uint32]6
            max_entry_bytes = $maxEntryBytes
            max_archive_bytes = $maxArchiveBytes
        }
        payload_entries = $PayloadEntries
        capability_denials = @(
            'os_installer_or_installation'
            'archive_extraction_or_execution'
            'production_trust_or_secret_lifecycle'
            'operator_configuration_or_service_lifecycle'
            'supported_distribution_or_upgrade_compatibility'
            'live_provider_success'
            'durable_or_distributed_custody'
            'external_effect_execution'
            'automatic_remote_access'
            'fpga_execution'
            'minecraft_scope'
        )
        non_authority_statement = 'This deterministic archive proves portable provider-free package identity only. SHA256 reproducibility is not publisher authenticity and grants no installer, trust, configuration, provider, effect, persistence, operator-product, or production authority.'
    }
    ConvertTo-CanonicalJsonBytes $manifest
}

function Write-ZipArchive([string]$Path, [object[]]$Entries) {
    $fileStream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $fileStream,
            [IO.Compression.ZipArchiveMode]::Create,
            $false,
            [Text.UTF8Encoding]::new($false)
        )
        try {
            foreach ($candidate in $Entries) {
                $entry = $archive.CreateEntry([string]$candidate.path, [IO.Compression.CompressionLevel]::NoCompression)
                $entry.LastWriteTime = $fixedTimestamp
                $entry.ExternalAttributes = 0
                $destination = $entry.Open()
                try {
                    if ($null -ne $candidate.bytes_value) {
                        $bytes = [byte[]]$candidate.bytes_value
                        $destination.Write($bytes, 0, $bytes.Length)
                    }
                    else {
                        $source = [IO.File]::OpenRead([string]$candidate.source_path)
                        try { $source.CopyTo($destination) }
                        finally { $source.Dispose() }
                    }
                }
                finally { $destination.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $fileStream.Dispose() }
}

function Compare-FileBytes([string]$Left, [string]$Right) {
    $leftItem = Get-Item -LiteralPath $Left
    $rightItem = Get-Item -LiteralPath $Right
    if ($leftItem.Length -ne $rightItem.Length) { return $false }
    $leftStream = [IO.File]::OpenRead($leftItem.FullName)
    $rightStream = [IO.File]::OpenRead($rightItem.FullName)
    try {
        $leftBuffer = [byte[]]::new(65536)
        $rightBuffer = [byte[]]::new(65536)
        while ($true) {
            $leftRead = $leftStream.Read($leftBuffer, 0, $leftBuffer.Length)
            $rightRead = $rightStream.Read($rightBuffer, 0, $rightBuffer.Length)
            if ($leftRead -ne $rightRead) { return $false }
            if ($leftRead -eq 0) { return $true }
            for ($index = 0; $index -lt $leftRead; $index++) {
                if ($leftBuffer[$index] -ne $rightBuffer[$index]) { return $false }
            }
        }
    }
    finally {
        $leftStream.Dispose()
        $rightStream.Dispose()
    }
}

function Remove-StagingDirectory {
    if ([string]::IsNullOrWhiteSpace($stagingPath) -or -not [IO.Directory]::Exists($stagingPath)) { return }
    $item = Get-Item -LiteralPath $stagingPath -Force
    $expectedParent = [IO.Path]::GetFullPath($outputDirectoryPath).TrimEnd('\', '/')
    $actualParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\', '/')
    $leaf = [IO.Path]::GetFileName($item.FullName)
    Assert-Bundle ($actualParent -ceq $expectedParent -and $leaf -cmatch '^\.cantor-portable-bundle-[a-f0-9]{32}$') 'staging cleanup identity differs'
    Assert-Bundle ($item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'staging cleanup target is not one physical directory'
    [IO.Directory]::Delete($item.FullName, $true)
}

function Publish-File([string]$StagedPath, [string]$DestinationPath) {
    [IO.File]::Move($StagedPath, $DestinationPath, $true)
}

$profileRoot = [IO.Path]::GetFullPath([Environment]::GetFolderPath('UserProfile'))
$driveRoot = [IO.Path]::GetPathRoot($outputDirectoryPath)
Assert-Bundle (-not $outputDirectoryPath.Equals($profileRoot, [StringComparison]::OrdinalIgnoreCase)) 'OutputDirectory must not be the user profile root'
Assert-Bundle (-not $outputDirectoryPath.Equals($driveRoot, [StringComparison]::OrdinalIgnoreCase)) 'OutputDirectory must not be a drive root'

if (-not [IO.Directory]::Exists($outputDirectoryPath)) {
    $parent = [IO.Path]::GetDirectoryName($outputDirectoryPath)
    Assert-Bundle (-not [string]::IsNullOrWhiteSpace($parent) -and [IO.Directory]::Exists($parent)) 'OutputDirectory parent must already exist'
    $parentItem = Get-Item -LiteralPath $parent -Force
    Assert-Bundle ($parentItem.PSIsContainer -and ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'OutputDirectory parent must be one physical directory'
    [IO.Directory]::CreateDirectory($outputDirectoryPath) | Out-Null
}
$outputDirectoryItem = Get-Item -LiteralPath $outputDirectoryPath -Force
Assert-Bundle ($outputDirectoryItem.PSIsContainer -and ($outputDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'OutputDirectory must be one physical directory'
Assert-Bundle (-not $archivePath.Equals($reportPath, [StringComparison]::OrdinalIgnoreCase)) 'archive and report paths must be distinct'
foreach ($destination in @($archivePath, $reportPath)) {
    Assert-Bundle (-not [IO.Directory]::Exists($destination)) 'an output path identifies a directory'
    if ([IO.File]::Exists($destination)) {
        Assert-Bundle $ReplaceOutputs 'output already exists; use ReplaceOutputs only after reviewing both targets'
        $destinationItem = Get-Item -LiteralPath $destination -Force
        Assert-Bundle (($destinationItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'output file is a reparse point'
    }
}

$head = (& git -C $root rev-parse HEAD).Trim()
Assert-Bundle ($LASTEXITCODE -eq 0) 'cannot resolve repository HEAD'
$branch = (& git -C $root rev-parse --abbrev-ref HEAD).Trim()
$upstream = (& git -C $root rev-parse '@{upstream}').Trim()
Assert-Bundle ($branch -ceq 'codex/self-hosted-corpus' -and $head -ceq $upstream) 'bundle generation requires the published codex/self-hosted-corpus HEAD'

if (-not $UsePrebuilt) {
    Push-Location $root
    try {
        & cargo build -p cantor_cli -p cantor_service --bins --release --locked --offline
        Assert-Bundle ($LASTEXITCODE -eq 0) 'locked offline release build failed'
    }
    finally { Pop-Location }
    $buildMode = 'built_locked_offline'
}
else {
    $buildMode = 'verified_prebuilt'
}

$cargoLock = Get-Identity (Join-Path $root 'Cargo.lock') 'Cargo.lock' 'dependency_lock'
$binaryDefinitions = @(
    [ordered]@{ path = 'bin/cantor-corpus.exe'; source = 'target/release/cantor-corpus.exe'; role = 'corpus_compiler' }
    [ordered]@{ path = 'bin/cantor.exe'; source = 'target/release/cantor.exe'; role = 'direct_cli' }
    [ordered]@{ path = 'bin/cantorctl.exe'; source = 'target/release/cantorctl.exe'; role = 'service_client' }
    [ordered]@{ path = 'bin/cantord.exe'; source = 'target/release/cantord.exe'; role = 'resident_service' }
)
$binaryEntries = @()
foreach ($definition in $binaryDefinitions) {
    $sourcePath = Join-Path $root ([string]$definition.source)
    Assert-Bundle ([IO.File]::Exists($sourcePath)) "release binary is absent: $($definition.source)"
    $identity = Get-Identity $sourcePath ([string]$definition.path) ([string]$definition.role)
    $binaryEntries += [ordered]@{
        path = $identity.path
        role = $identity.role
        bytes = $identity.bytes
        sha256 = $identity.sha256
        source_path = ([string]$definition.source).Replace('\', '/')
    }
}
Assert-Bundle (@($binaryEntries.sha256 | Select-Object -Unique).Count -eq 4) 'release binary hashes must be distinct'

$readmeBytes = New-OperatorReadmeBytes $head
$readmeIdentity = Get-ByteIdentity $readmeBytes 'BUNDLE_README.txt' 'operator_readme'
$manifestPayloadEntries = @($readmeIdentity) + @($binaryEntries | ForEach-Object {
    [ordered]@{ path = $_.path; role = $_.role; bytes = $_.bytes; sha256 = $_.sha256 }
})
$manifestBytes = New-BundleManifestBytes $head $cargoLock $manifestPayloadEntries
$manifestIdentity = Get-ByteIdentity $manifestBytes 'bundle-manifest.json' 'bundle_manifest'

$archiveEntries = @(
    [pscustomobject]@{ path = 'BUNDLE_README.txt'; role = 'operator_readme'; bytes_value = $readmeBytes; source_path = $null }
    [pscustomobject]@{ path = 'bin/cantor-corpus.exe'; role = 'corpus_compiler'; bytes_value = $null; source_path = (Join-Path $root 'target/release/cantor-corpus.exe') }
    [pscustomobject]@{ path = 'bin/cantor.exe'; role = 'direct_cli'; bytes_value = $null; source_path = (Join-Path $root 'target/release/cantor.exe') }
    [pscustomobject]@{ path = 'bin/cantorctl.exe'; role = 'service_client'; bytes_value = $null; source_path = (Join-Path $root 'target/release/cantorctl.exe') }
    [pscustomobject]@{ path = 'bin/cantord.exe'; role = 'resident_service'; bytes_value = $null; source_path = (Join-Path $root 'target/release/cantord.exe') }
    [pscustomobject]@{ path = 'bundle-manifest.json'; role = 'bundle_manifest'; bytes_value = $manifestBytes; source_path = $null }
)
$expectedArchivePaths = @(
    'BUNDLE_README.txt'
    'bin/cantor-corpus.exe'
    'bin/cantor.exe'
    'bin/cantorctl.exe'
    'bin/cantord.exe'
    'bundle-manifest.json'
)
Assert-Bundle ((@($archiveEntries.path) -join ',') -ceq ($expectedArchivePaths -join ',')) 'archive entries are not in the exact ordinal path order'

try {
    $stagingPath = Join-Path $outputDirectoryPath ('.cantor-portable-bundle-' + [guid]::NewGuid().ToString('N'))
    Assert-Bundle (-not (Test-Path -LiteralPath $stagingPath)) 'generated staging path already exists'
    [IO.Directory]::CreateDirectory($stagingPath) | Out-Null
    $primaryArchive = Join-Path $stagingPath 'primary.zip'
    $replayArchive = Join-Path $stagingPath 'replay.zip'
    Write-ZipArchive $primaryArchive $archiveEntries
    Write-ZipArchive $replayArchive $archiveEntries

    $primaryItem = Get-Item -LiteralPath $primaryArchive
    $replayItem = Get-Item -LiteralPath $replayArchive
    $primaryHash = (Get-FileHash -LiteralPath $primaryArchive -Algorithm SHA256).Hash
    $replayHash = (Get-FileHash -LiteralPath $replayArchive -Algorithm SHA256).Hash
    $byteEqual = Compare-FileBytes $primaryArchive $replayArchive
    Assert-Bundle ([uint64]$primaryItem.Length -gt 0 -and [uint64]$primaryItem.Length -le $maxArchiveBytes) 'archive size is outside the admitted range'
    Assert-Bundle ($primaryItem.Length -eq $replayItem.Length -and $primaryHash -ceq $replayHash -and $byteEqual) 'two bundle generations are not byte-identical'

    $reportEntries = @(
        [ordered]@{ ordinal = [uint32]0; path = $readmeIdentity.path; role = $readmeIdentity.role; bytes = $readmeIdentity.bytes; sha256 = $readmeIdentity.sha256 }
    ) + @($binaryEntries | ForEach-Object -Begin { $ordinal = 1 } -Process {
        $entry = [ordered]@{ ordinal = [uint32]$ordinal; path = $_.path; role = $_.role; bytes = $_.bytes; sha256 = $_.sha256; source_path = $_.source_path }
        $ordinal++
        $entry
    }) + @(
        [ordered]@{ ordinal = [uint32]5; path = $manifestIdentity.path; role = $manifestIdentity.role; bytes = $manifestIdentity.bytes; sha256 = $manifestIdentity.sha256 }
    )

    $report = [ordered]@{
        profile = 'cantor-provider-free-portable-release-bundle-evidence/0.1'
        status = 'provider_free_portable_release_bundle_verified_with_declared_gaps'
        source_commit = $head
        target = 'windows-x86_64'
        build_mode = $buildMode
        cargo_lock = $cargoLock
        archive = [ordered]@{
            file_name = $archiveName
            bytes = [uint64]$primaryItem.Length
            sha256 = $primaryHash
            format = 'zip'
            compression = 'store'
            timestamp_contract = 'zip_dos_epoch_1980_01_01_00_00_00'
            entry_count = [uint32]6
        }
        embedded_manifest = $manifestIdentity
        entries = $reportEntries
        determinism = [ordered]@{
            generation_count = [uint32]2
            byte_equal = $byteEqual
            sha256_equal = ($primaryHash -ceq $replayHash)
            replay_archive_removed_before_publication = $true
        }
        safety = [ordered]@{
            archive_extracted = $false
            executables_invoked = $false
            service_started = $false
            keys_or_tokens_created = $false
            configuration_or_state_created = $false
            provider_contacted = $false
            remote_accessed = $false
            staging_removed_after_publication = $true
        }
        capability_denials = @(
            'os_installer_or_installation'
            'archive_extraction_or_execution'
            'production_trust_or_secret_lifecycle'
            'operator_configuration_or_service_lifecycle'
            'supported_distribution_or_upgrade_compatibility'
            'live_provider_success'
            'durable_or_distributed_custody'
            'external_effect_execution'
            'automatic_remote_access'
            'fpga_execution'
            'minecraft_scope'
        )
        non_authority_statement = 'This deterministic archive proves portable provider-free package identity only. SHA256 reproducibility is not publisher authenticity and grants no installer, trust, configuration, provider, effect, persistence, operator-product, or production authority.'
    }
    $stagedReport = Join-Path $stagingPath 'evidence.json'
    [IO.File]::WriteAllBytes($stagedReport, (ConvertTo-CanonicalJsonBytes $report))
    [IO.File]::Delete($replayArchive)
    Publish-File $primaryArchive $archivePath
    Publish-File $stagedReport $reportPath
    Remove-StagingDirectory
    $stagingPath = $null
}
catch {
    try { Remove-StagingDirectory }
    catch { throw "bundle generation failed and safe staging cleanup also failed: $($_.Exception.Message)" }
    throw
}

Write-Output "portable_bundle_written=$archivePath bytes=$((Get-Item -LiteralPath $archivePath).Length) sha256=$((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash) entries=6 deterministic=true"
