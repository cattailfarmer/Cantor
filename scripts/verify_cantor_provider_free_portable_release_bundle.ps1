[CmdletBinding()]
param(
    [string]$InputDirectory = 'experiments/provider_free_portable_release_bundle/artifacts'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$inputDirectoryPath = if ([IO.Path]::IsPathRooted($InputDirectory)) {
    [IO.Path]::GetFullPath($InputDirectory)
}
else {
    [IO.Path]::GetFullPath((Join-Path $root $InputDirectory))
}
$archiveName = 'cantor-provider-free-windows-x86_64-p0.zip'
$reportName = 'cantor-provider-free-windows-x86_64-p0-evidence.json'
$archivePath = Join-Path $inputDirectoryPath $archiveName
$reportPath = Join-Path $inputDirectoryPath $reportName
$maxEntryBytes = [uint64](16MB)
$maxArchiveBytes = [uint64](16MB)

function Assert-Exact([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Fields([psobject]$Value, [string[]]$Expected, [string]$Label) {
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    Assert-Exact (($actual -join ',') -ceq ($wanted -join ',')) "$Label fields differ"
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

function Get-EntryBytes([IO.Compression.ZipArchiveEntry]$Entry) {
    Assert-Exact ([uint64]$Entry.Length -gt 0 -and [uint64]$Entry.Length -le $maxEntryBytes) "archive entry size is outside the admitted range: $($Entry.FullName)"
    $source = $Entry.Open()
    $memory = [IO.MemoryStream]::new([int]$Entry.Length)
    try {
        $source.CopyTo($memory)
        $bytes = $memory.ToArray()
    }
    finally {
        $source.Dispose()
        $memory.Dispose()
    }
    Assert-Exact ([uint64]$bytes.Length -eq [uint64]$Entry.Length) "archive entry byte count changed while reading: $($Entry.FullName)"
    $bytes
}

function Compare-Bytes([byte[]]$Left, [byte[]]$Right) {
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) { return $false }
    }
    $true
}

function Compare-EntryToFile([IO.Compression.ZipArchiveEntry]$Entry, [string]$Path) {
    $fileItem = Get-Item -LiteralPath $Path -Force
    if ([uint64]$Entry.Length -ne [uint64]$fileItem.Length) { return $false }
    $entryStream = $Entry.Open()
    $fileStream = [IO.File]::OpenRead($fileItem.FullName)
    try {
        $entryBuffer = [byte[]]::new(65536)
        $fileBuffer = [byte[]]::new(65536)
        while ($true) {
            $entryRead = $entryStream.Read($entryBuffer, 0, $entryBuffer.Length)
            $fileRead = $fileStream.Read($fileBuffer, 0, $fileBuffer.Length)
            if ($entryRead -ne $fileRead) { return $false }
            if ($entryRead -eq 0) { return $true }
            for ($index = 0; $index -lt $entryRead; $index++) {
                if ($entryBuffer[$index] -ne $fileBuffer[$index]) { return $false }
            }
        }
    }
    finally {
        $entryStream.Dispose()
        $fileStream.Dispose()
    }
}

Assert-Exact ([IO.Directory]::Exists($inputDirectoryPath)) 'InputDirectory is absent'
$inputDirectoryItem = Get-Item -LiteralPath $inputDirectoryPath -Force
Assert-Exact ($inputDirectoryItem.PSIsContainer -and ($inputDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'InputDirectory must be one physical directory'
foreach ($path in @($archivePath, $reportPath)) {
    Assert-Exact ([IO.File]::Exists($path)) "bundle artifact is absent: $path"
    $item = Get-Item -LiteralPath $path -Force
    Assert-Exact (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "bundle artifact is not one regular physical file: $path"
}

$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
Assert-Fields $report @(
    'profile','status','source_commit','target','build_mode','cargo_lock','archive',
    'embedded_manifest','entries','determinism','safety','capability_denials','non_authority_statement'
) 'report'
Assert-Exact ($report.profile -ceq 'cantor-provider-free-portable-release-bundle-evidence/0.1') 'report profile differs'
Assert-Exact ($report.status -ceq 'provider_free_portable_release_bundle_verified_with_declared_gaps') 'report status differs'
Assert-Exact ($report.target -ceq 'windows-x86_64') 'target differs'
Assert-Exact ($report.build_mode -in @('built_locked_offline','verified_prebuilt')) 'build mode differs'
Assert-Exact ([string]$report.source_commit -cmatch '^[a-f0-9]{40}$') 'source commit shape differs'
& git -C $root cat-file -e "$($report.source_commit)^{commit}" 2>$null
Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not a Git commit'
& git -C $root merge-base --is-ancestor ([string]$report.source_commit) HEAD
Assert-Exact ($LASTEXITCODE -eq 0) 'source commit is not an ancestor of HEAD'

Assert-Fields $report.cargo_lock @('path','role','bytes','sha256') 'Cargo.lock identity'
$lockItem = Get-Item -LiteralPath (Join-Path $root 'Cargo.lock') -Force
Assert-Exact ($report.cargo_lock.path -ceq 'Cargo.lock' -and $report.cargo_lock.role -ceq 'dependency_lock') 'Cargo.lock path or role differs'
Assert-Exact ([uint64]$report.cargo_lock.bytes -eq [uint64]$lockItem.Length -and $report.cargo_lock.sha256 -ceq (Get-FileHash -LiteralPath $lockItem.FullName -Algorithm SHA256).Hash) 'Cargo.lock identity drift'

Assert-Fields $report.archive @('file_name','bytes','sha256','format','compression','timestamp_contract','entry_count') 'archive identity'
$archiveItem = Get-Item -LiteralPath $archivePath -Force
Assert-Exact ($report.archive.file_name -ceq $archiveName -and $report.archive.format -ceq 'zip' -and $report.archive.compression -ceq 'store' -and $report.archive.timestamp_contract -ceq 'zip_dos_epoch_1980_01_01_00_00_00' -and [uint32]$report.archive.entry_count -eq 6) 'archive contract differs'
Assert-Exact ([uint64]$archiveItem.Length -gt 0 -and [uint64]$archiveItem.Length -le $maxArchiveBytes -and [uint64]$report.archive.bytes -eq [uint64]$archiveItem.Length) 'archive size differs'
$archiveHash = (Get-FileHash -LiteralPath $archiveItem.FullName -Algorithm SHA256).Hash
Assert-Exact ($report.archive.sha256 -cmatch '^[A-F0-9]{64}$' -and $report.archive.sha256 -ceq $archiveHash) 'archive hash differs'

Assert-Fields $report.embedded_manifest @('path','role','bytes','sha256') 'embedded manifest identity'
Assert-Exact ($report.embedded_manifest.path -ceq 'bundle-manifest.json' -and $report.embedded_manifest.role -ceq 'bundle_manifest') 'embedded manifest path or role differs'

$expectedPaths = @(
    'BUNDLE_README.txt'
    'bin/cantor-corpus.exe'
    'bin/cantor.exe'
    'bin/cantorctl.exe'
    'bin/cantord.exe'
    'bundle-manifest.json'
)
$expectedRoles = @('operator_readme','corpus_compiler','direct_cli','service_client','resident_service','bundle_manifest')
$expectedSources = @($null,'target/release/cantor-corpus.exe','target/release/cantor.exe','target/release/cantorctl.exe','target/release/cantord.exe',$null)
$entries = @($report.entries)
Assert-Exact ($entries.Count -eq 6) 'report entry count differs'
for ($index = 0; $index -lt $entries.Count; $index++) {
    $entry = $entries[$index]
    $expectedFields = if ($null -eq $expectedSources[$index]) { @('ordinal','path','role','bytes','sha256') } else { @('ordinal','path','role','bytes','sha256','source_path') }
    Assert-Fields $entry $expectedFields "report entry $index"
    Assert-Exact ([uint32]$entry.ordinal -eq [uint32]$index -and $entry.path -ceq $expectedPaths[$index] -and $entry.role -ceq $expectedRoles[$index]) "report entry identity differs: $index"
    Assert-Exact ([uint64]$entry.bytes -gt 0 -and [uint64]$entry.bytes -le $maxEntryBytes -and $entry.sha256 -cmatch '^[A-F0-9]{64}$') "report entry size or hash differs: $index"
    if ($null -ne $expectedSources[$index]) {
        Assert-Exact ($entry.source_path -ceq $expectedSources[$index]) "report source path differs: $index"
        $sourceItem = Get-Item -LiteralPath (Join-Path $root $expectedSources[$index]) -Force
        Assert-Exact (-not $sourceItem.PSIsContainer -and ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) "current release source is not one physical file: $index"
        Assert-Exact ([uint64]$entry.bytes -eq [uint64]$sourceItem.Length -and $entry.sha256 -ceq (Get-FileHash -LiteralPath $sourceItem.FullName -Algorithm SHA256).Hash) "current release binary identity drift: $index"
    }
}
Assert-Exact (@($entries[1..4].sha256 | Select-Object -Unique).Count -eq 4) 'release binary hashes are not distinct'
Assert-Exact ([uint64]$report.embedded_manifest.bytes -eq [uint64]$entries[5].bytes -and $report.embedded_manifest.sha256 -ceq $entries[5].sha256) 'embedded manifest report identity differs'

Assert-Fields $report.determinism @('generation_count','byte_equal','sha256_equal','replay_archive_removed_before_publication') 'determinism'
Assert-Exact ([uint32]$report.determinism.generation_count -eq 2 -and [bool]$report.determinism.byte_equal -and [bool]$report.determinism.sha256_equal -and [bool]$report.determinism.replay_archive_removed_before_publication) 'determinism proof differs'
Assert-Fields $report.safety @('archive_extracted','executables_invoked','service_started','keys_or_tokens_created','configuration_or_state_created','provider_contacted','remote_accessed','staging_removed_after_publication') 'safety'
foreach ($field in @('archive_extracted','executables_invoked','service_started','keys_or_tokens_created','configuration_or_state_created','provider_contacted','remote_accessed')) {
    Assert-Exact (-not [bool]$report.safety.$field) "safety denial differs: $field"
}
Assert-Exact ([bool]$report.safety.staging_removed_after_publication) 'staging cleanup proof differs'

$expectedDenials = @(
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
Assert-Exact ((@($report.capability_denials) -join ',') -ceq ($expectedDenials -join ',')) 'capability denials differ'
$expectedNonAuthority = 'This deterministic archive proves portable provider-free package identity only. SHA256 reproducibility is not publisher authenticity and grants no installer, trust, configuration, provider, effect, persistence, operator-product, or production authority.'
Assert-Exact ($report.non_authority_statement -ceq $expectedNonAuthority) 'non-authority statement differs'

$readmeBytes = New-OperatorReadmeBytes ([string]$report.source_commit)
$readmeIdentity = [ordered]@{
    path = 'BUNDLE_README.txt'
    role = 'operator_readme'
    bytes = [uint64]$readmeBytes.Length
    sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($readmeBytes))
}
$payloadEntries = @($readmeIdentity) + @($entries[1..4] | ForEach-Object {
    [ordered]@{ path = $_.path; role = $_.role; bytes = [uint64]$_.bytes; sha256 = $_.sha256 }
})
$manifestBytes = New-BundleManifestBytes ([string]$report.source_commit) $report.cargo_lock $payloadEntries
$manifestHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($manifestBytes))
Assert-Exact ([uint64]$readmeBytes.Length -eq [uint64]$entries[0].bytes -and $readmeIdentity.sha256 -ceq $entries[0].sha256) 'operator README rederivation differs'
Assert-Exact ([uint64]$manifestBytes.Length -eq [uint64]$entries[5].bytes -and $manifestHash -ceq $entries[5].sha256) 'embedded manifest rederivation differs'

$archiveStream = [IO.File]::OpenRead($archiveItem.FullName)
$zip = [IO.Compression.ZipArchive]::new($archiveStream, [IO.Compression.ZipArchiveMode]::Read, $false, [Text.UTF8Encoding]::new($false))
try {
    $zipEntries = @($zip.Entries)
    Assert-Exact ($zipEntries.Count -eq 6) 'ZIP entry count differs'
    Assert-Exact ((@($zipEntries.FullName) -join ',') -ceq ($expectedPaths -join ',')) 'ZIP entry allowlist order differs'
    Assert-Exact (@($zipEntries.FullName | Select-Object -Unique).Count -eq 6) 'ZIP contains a duplicate path'
    for ($index = 0; $index -lt $zipEntries.Count; $index++) {
        $zipEntry = $zipEntries[$index]
        $reportEntry = $entries[$index]
        Assert-Exact (-not [string]::IsNullOrWhiteSpace($zipEntry.FullName) -and $zipEntry.FullName.Length -le 128 -and -not $zipEntry.FullName.Contains('\') -and -not $zipEntry.FullName.StartsWith('/') -and $zipEntry.FullName -notmatch '(^|/)\.\.(/|$)') "ZIP entry path is unsafe: $index"
        Assert-Exact (
            $zipEntry.LastWriteTime.Year -eq 1980 -and
            $zipEntry.LastWriteTime.Month -eq 1 -and
            $zipEntry.LastWriteTime.Day -eq 1 -and
            $zipEntry.LastWriteTime.Hour -eq 0 -and
            $zipEntry.LastWriteTime.Minute -eq 0 -and
            $zipEntry.LastWriteTime.Second -eq 0
        ) "ZIP DOS timestamp fields differ: $index"
        Assert-Exact ($zipEntry.ExternalAttributes -eq 0) "ZIP external attributes differ: $index"
        Assert-Exact ([uint64]$zipEntry.Length -eq [uint64]$reportEntry.bytes -and [uint64]$zipEntry.CompressedLength -eq [uint64]$zipEntry.Length) "ZIP size or store contract differs: $index"
        $zipBytes = Get-EntryBytes $zipEntry
        $zipHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($zipBytes))
        Assert-Exact ($zipHash -ceq $reportEntry.sha256) "ZIP entry hash differs: $index"
        if ($index -eq 0) {
            Assert-Exact (Compare-Bytes $zipBytes $readmeBytes) 'ZIP operator README bytes differ from exact rederivation'
        }
        elseif ($index -eq 5) {
            Assert-Exact (Compare-Bytes $zipBytes $manifestBytes) 'ZIP manifest bytes differ from exact rederivation'
        }
        else {
            Assert-Exact (Compare-EntryToFile $zipEntry (Join-Path $root $expectedSources[$index])) "ZIP executable bytes differ from current release binary: $index"
        }
    }
}
finally {
    $zip.Dispose()
    $archiveStream.Dispose()
}

Write-Output "portable_bundle_verified=true archive_bytes=$($archiveItem.Length) entries=6 source_commit=$($report.source_commit) deterministic_generations=2"
