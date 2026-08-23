[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$builder = Join-Path $PSScriptRoot 'build_cantor_provider_free_portable_release_bundle.ps1'
$verifier = Join-Path $PSScriptRoot 'verify_cantor_provider_free_portable_release_bundle.ps1'
$archiveName = 'cantor-provider-free-windows-x86_64-p0.zip'
$reportName = 'cantor-provider-free-windows-x86_64-p0-evidence.json'
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $tempBase ('cantor-portable-bundle-tests-' + [guid]::NewGuid().ToString('N'))
$fixedTimestamp = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
$script:producerRefusals = 0
$script:verifierRefusals = 0

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Write-Json([string]$Path, [object]$Value) {
    $text = (($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")) + "`n"
    [IO.File]::WriteAllText($Path, $text, [Text.UTF8Encoding]::new($false))
}

function Assert-ProducerRefused([string]$Label, [scriptblock]$Action) {
    $refused = $false
    try { & $Action | Out-Null }
    catch { $refused = $true }
    Assert-Test $refused "producer admitted adversarial case: $Label"
    $script:producerRefusals++
}

function Assert-VerifierRefused([string]$Label, [scriptblock]$Mutator) {
    $caseDirectory = Join-Path $testRoot ('case-' + $Label)
    [IO.Directory]::CreateDirectory($caseDirectory) | Out-Null
    Copy-Item -LiteralPath (Join-Path $testRoot 'baseline-a' $archiveName) -Destination (Join-Path $caseDirectory $archiveName)
    Copy-Item -LiteralPath (Join-Path $testRoot 'baseline-a' $reportName) -Destination (Join-Path $caseDirectory $reportName)
    & $Mutator $caseDirectory
    $refused = $false
    try { & $verifier -InputDirectory $caseDirectory | Out-Null }
    catch { $refused = $true }
    Assert-Test $refused "verifier admitted adversarial case: $Label"
    $script:verifierRefusals++
}

function Update-ArchiveIdentity([string]$CaseDirectory) {
    $archivePath = Join-Path $CaseDirectory $archiveName
    $reportPath = Join-Path $CaseDirectory $reportName
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $archive = Get-Item -LiteralPath $archivePath
    $report.archive.bytes = [uint64]$archive.Length
    $report.archive.sha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    Write-Json $reportPath $report
}

function Rewrite-Zip([string]$ArchivePath, [ValidateSet('extra','duplicate','traversal','missing','timestamp')] [string]$Mode) {
    $sourceStream = [IO.File]::OpenRead($ArchivePath)
    $sourceArchive = [IO.Compression.ZipArchive]::new($sourceStream, [IO.Compression.ZipArchiveMode]::Read, $false, [Text.UTF8Encoding]::new($false))
    try {
        $payloads = @($sourceArchive.Entries | ForEach-Object {
            $entryStream = $_.Open()
            $memory = [IO.MemoryStream]::new()
            try {
                $entryStream.CopyTo($memory)
                [pscustomobject]@{ path = $_.FullName; bytes = $memory.ToArray(); timestamp = $fixedTimestamp }
            }
            finally {
                $entryStream.Dispose()
                $memory.Dispose()
            }
        })
    }
    finally {
        $sourceArchive.Dispose()
        $sourceStream.Dispose()
    }

    switch ($Mode) {
        'extra' {
            $payloads += [pscustomobject]@{ path = 'extra.txt'; bytes = [byte[]](1); timestamp = $fixedTimestamp }
        }
        'duplicate' {
            $payloads[5].path = $payloads[4].path
        }
        'traversal' {
            $payloads[5].path = '../bundle-manifest.json'
        }
        'missing' {
            $payloads = @($payloads[0..4])
        }
        'timestamp' {
            $payloads[0].timestamp = [DateTimeOffset]::new(1982, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
        }
    }

    $replacement = "$ArchivePath.replacement"
    $outputStream = [IO.File]::Open($replacement, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $outputArchive = [IO.Compression.ZipArchive]::new($outputStream, [IO.Compression.ZipArchiveMode]::Create, $false, [Text.UTF8Encoding]::new($false))
        try {
            foreach ($payload in $payloads) {
                $entry = $outputArchive.CreateEntry([string]$payload.path, [IO.Compression.CompressionLevel]::NoCompression)
                $entry.LastWriteTime = [DateTimeOffset]$payload.timestamp
                $entry.ExternalAttributes = 0
                $entryStream = $entry.Open()
                try {
                    $bytes = [byte[]]$payload.bytes
                    $entryStream.Write($bytes, 0, $bytes.Length)
                }
                finally { $entryStream.Dispose() }
            }
        }
        finally { $outputArchive.Dispose() }
    }
    finally { $outputStream.Dispose() }
    [IO.File]::Move($replacement, $ArchivePath, $true)
}

function Remove-TestRoot {
    if (-not [IO.Directory]::Exists($testRoot)) { return }
    $item = Get-Item -LiteralPath $testRoot -Force
    $expectedPrefix = $tempBase.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    Assert-Test ($item.FullName.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) 'test cleanup escaped the temporary directory'
    Assert-Test ($item.Name -cmatch '^cantor-portable-bundle-tests-[a-f0-9]{32}$') 'test cleanup leaf differs'
    Assert-Test ($item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'test cleanup target is not one physical directory'
    [IO.Directory]::Delete($item.FullName, $true)
}

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    $baselineA = Join-Path $testRoot 'baseline-a'
    $baselineB = Join-Path $testRoot 'baseline-b'
    [IO.Directory]::CreateDirectory($baselineA) | Out-Null
    [IO.Directory]::CreateDirectory($baselineB) | Out-Null
    & $builder -OutputDirectory $baselineA -UsePrebuilt | Out-Null
    & $builder -OutputDirectory $baselineB -UsePrebuilt | Out-Null
    & $verifier -InputDirectory $baselineA | Out-Null
    & $verifier -InputDirectory $baselineB | Out-Null

    $archiveA = Join-Path $baselineA $archiveName
    $archiveB = Join-Path $baselineB $archiveName
    $reportA = Join-Path $baselineA $reportName
    $reportB = Join-Path $baselineB $reportName
    Assert-Test ((Get-FileHash -LiteralPath $archiveA -Algorithm SHA256).Hash -ceq (Get-FileHash -LiteralPath $archiveB -Algorithm SHA256).Hash) 'independent archive generation hash differs'
    Assert-Test ((Get-FileHash -LiteralPath $reportA -Algorithm SHA256).Hash -ceq (Get-FileHash -LiteralPath $reportB -Algorithm SHA256).Hash) 'independent evidence generation hash differs'
    $archiveHashBeforeReplacement = (Get-FileHash -LiteralPath $archiveB -Algorithm SHA256).Hash
    $reportHashBeforeReplacement = (Get-FileHash -LiteralPath $reportB -Algorithm SHA256).Hash
    & $builder -OutputDirectory $baselineB -UsePrebuilt -ReplaceOutputs | Out-Null
    & $verifier -InputDirectory $baselineB | Out-Null
    Assert-Test ((Get-FileHash -LiteralPath $archiveB -Algorithm SHA256).Hash -ceq $archiveHashBeforeReplacement) 'explicit archive replacement changed deterministic bytes'
    Assert-Test ((Get-FileHash -LiteralPath $reportB -Algorithm SHA256).Hash -ceq $reportHashBeforeReplacement) 'explicit report replacement changed deterministic bytes'

    Assert-ProducerRefused 'profile-root' {
        & $builder -OutputDirectory ([Environment]::GetFolderPath('UserProfile')) -UsePrebuilt
    }
    Assert-ProducerRefused 'preexisting-outputs' {
        & $builder -OutputDirectory $baselineA -UsePrebuilt
    }
    $fileAsDirectory = Join-Path $testRoot 'not-a-directory'
    [IO.File]::WriteAllText($fileAsDirectory, 'fixture', [Text.UTF8Encoding]::new($false))
    Assert-ProducerRefused 'file-as-output-directory' {
        & $builder -OutputDirectory $fileAsDirectory -UsePrebuilt
    }

    Assert-VerifierRefused 'report-status' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $reportName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.status = 'false_success'
        Write-Json $path $report
    }
    Assert-VerifierRefused 'report-unknown-field' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $reportName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
        Write-Json $path $report
    }
    Assert-VerifierRefused 'report-target' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $reportName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.target = 'linux-x86_64'
        Write-Json $path $report
    }
    Assert-VerifierRefused 'report-entry-missing' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $reportName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.entries = @($report.entries[0..4])
        Write-Json $path $report
    }
    Assert-VerifierRefused 'report-archive-hash' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $reportName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.archive.sha256 = '0' * 64
        Write-Json $path $report
    }
    Assert-VerifierRefused 'report-determinism' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $reportName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.determinism.byte_equal = $false
        Write-Json $path $report
    }
    Assert-VerifierRefused 'report-provider-contact' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $reportName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.safety.provider_contacted = $true
        Write-Json $path $report
    }
    Assert-VerifierRefused 'report-capability' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $reportName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.capability_denials = @($report.capability_denials[0..9])
        Write-Json $path $report
    }
    Assert-VerifierRefused 'report-binary-hash' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $reportName
        $report = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $report.entries[1].sha256 = 'A' * 64
        Write-Json $path $report
    }
    Assert-VerifierRefused 'zip-extra-entry' {
        param($caseDirectory)
        Rewrite-Zip (Join-Path $caseDirectory $archiveName) 'extra'
        Update-ArchiveIdentity $caseDirectory
    }
    Assert-VerifierRefused 'zip-duplicate-entry' {
        param($caseDirectory)
        Rewrite-Zip (Join-Path $caseDirectory $archiveName) 'duplicate'
        Update-ArchiveIdentity $caseDirectory
    }
    Assert-VerifierRefused 'zip-traversal-entry' {
        param($caseDirectory)
        Rewrite-Zip (Join-Path $caseDirectory $archiveName) 'traversal'
        Update-ArchiveIdentity $caseDirectory
    }
    Assert-VerifierRefused 'zip-missing-entry' {
        param($caseDirectory)
        Rewrite-Zip (Join-Path $caseDirectory $archiveName) 'missing'
        Update-ArchiveIdentity $caseDirectory
    }
    Assert-VerifierRefused 'zip-timestamp' {
        param($caseDirectory)
        Rewrite-Zip (Join-Path $caseDirectory $archiveName) 'timestamp'
        Update-ArchiveIdentity $caseDirectory
    }
    Assert-VerifierRefused 'zip-corruption' {
        param($caseDirectory)
        $path = Join-Path $caseDirectory $archiveName
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $stream.Position = [Math]::Floor($stream.Length / 2)
            $value = $stream.ReadByte()
            $stream.Position -= 1
            $stream.WriteByte([byte]($value -bxor 1))
        }
        finally { $stream.Dispose() }
    }

    Write-Output "portable_bundle_tests=passed producer_refusals=$script:producerRefusals verifier_refusals=$script:verifierRefusals cross_generation_equal=true explicit_replacement_equal=true"
}
finally {
    Remove-TestRoot
}
