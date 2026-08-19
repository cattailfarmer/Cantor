[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $SourceRevision = 'HEAD',

    [Parameter()]
    [switch] $KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$Profile = 'cantor-field-attention-reproducible-windows-build/0.1'
$CampaignPrefix = 'cantor-field-cycle-repro-'

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [Parameter()]
        [string[]] $ArgumentList = @(),

        [Parameter(Mandatory)]
        [string] $WorkingDirectory
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        [void] $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Failed to start native command: $FilePath"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            $summary = $stderr.Trim()
            if ([string]::IsNullOrWhiteSpace($summary)) {
                $summary = $stdout.Trim()
            }
            throw "Native command failed with exit code $($process.ExitCode): $FilePath $($ArgumentList -join ' ')`n$summary"
        }
        return [pscustomobject]@{
            StdOut = $stdout
            StdErr = $stderr
        }
    }
    finally {
        $process.Dispose()
    }
}

function Get-TextSha256 {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Text
    )

    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([Convert]::ToHexString($algorithm.ComputeHash($bytes))).ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Assert-ExactJsonPropertySet {
    param(
        [Parameter(Mandatory)]
        [psobject] $InputObject,

        [Parameter(Mandatory)]
        [string[]] $ExpectedProperties,

        [Parameter(Mandatory)]
        [string] $Context
    )

    $actual = @($InputObject.PSObject.Properties.Name)
    $missing = @($ExpectedProperties | Where-Object { $actual -cnotcontains $_ })
    $unexpected = @($actual | Where-Object { $ExpectedProperties -cnotcontains $_ })
    if ($missing.Count -ne 0 -or $unexpected.Count -ne 0) {
        throw "Behavior gate failed: $Context property set differs from the governed reference; missing=$($missing -join ',') unexpected=$($unexpected -join ',')."
    }
}

function Test-FileBytesEqual {
    param(
        [Parameter(Mandatory)]
        [string] $LeftPath,

        [Parameter(Mandatory)]
        [string] $RightPath
    )

    $leftInfo = Get-Item -LiteralPath $LeftPath
    $rightInfo = Get-Item -LiteralPath $RightPath
    if ($leftInfo.Length -ne $rightInfo.Length) {
        return $false
    }

    $left = [System.IO.File]::OpenRead($leftInfo.FullName)
    $right = [System.IO.File]::OpenRead($rightInfo.FullName)
    try {
        $leftBuffer = [byte[]]::new(1048576)
        $rightBuffer = [byte[]]::new(1048576)
        while ($true) {
            $leftCount = $left.Read($leftBuffer, 0, $leftBuffer.Length)
            $rightCount = $right.Read($rightBuffer, 0, $rightBuffer.Length)
            if ($leftCount -ne $rightCount) {
                return $false
            }
            if ($leftCount -eq 0) {
                return $true
            }
            for ($index = 0; $index -lt $leftCount; $index++) {
                if ($leftBuffer[$index] -ne $rightBuffer[$index]) {
                    return $false
                }
            }
        }
    }
    finally {
        $left.Dispose()
        $right.Dispose()
    }
}

function Assert-SafeCampaignRoot {
    param(
        [Parameter(Mandatory)]
        [string] $CandidatePath,

        [Parameter(Mandatory)]
        [string] $TargetRoot
    )

    $resolvedCandidate = [System.IO.Path]::GetFullPath($CandidatePath).TrimEnd('\', '/')
    $resolvedTarget = [System.IO.Path]::GetFullPath($TargetRoot).TrimEnd('\', '/')
    $targetItem = Get-Item -LiteralPath $resolvedTarget
    if (-not $targetItem.PSIsContainer -or
        ($targetItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing a target root that is not a physical directory: $resolvedTarget"
    }
    $parent = [System.IO.Directory]::GetParent($resolvedCandidate)
    $leaf = [System.IO.Path]::GetFileName($resolvedCandidate)
    if ($null -eq $parent -or
        -not $parent.FullName.Equals($resolvedTarget, [System.StringComparison]::OrdinalIgnoreCase) -or
        $leaf -notmatch '^cantor-field-cycle-repro-[0-9a-f]{32}$') {
        throw "Refusing campaign path outside the declared target child boundary: $resolvedCandidate"
    }
    if (Test-Path -LiteralPath $resolvedCandidate) {
        $candidateItem = Get-Item -LiteralPath $resolvedCandidate
        if (-not $candidateItem.PSIsContainer -or
            ($candidateItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing a campaign root that is not a physical directory: $resolvedCandidate"
        }
    }
    return $resolvedCandidate
}

$initialDirectory = (Get-Location).Path
$repoQuery = Invoke-NativeCommand -FilePath 'git.exe' -ArgumentList @('rev-parse', '--show-toplevel') -WorkingDirectory $initialDirectory
$repositoryRoot = [System.IO.Path]::GetFullPath($repoQuery.StdOut.Trim())
$targetRoot = Join-Path $repositoryRoot 'target'
[void] (New-Item -ItemType Directory -Path $targetRoot -Force)
$campaignName = $CampaignPrefix + ([guid]::NewGuid().ToString('N'))
$campaignRoot = Assert-SafeCampaignRoot -CandidatePath (Join-Path $targetRoot $campaignName) -TargetRoot $targetRoot
$campaignCreated = $false
$receipt = $null

$inheritedEnvironment = [ordered]@{
    SOURCE_DATE_EPOCH = [Environment]::GetEnvironmentVariable('SOURCE_DATE_EPOCH', 'Process')
    CARGO_INCREMENTAL = [Environment]::GetEnvironmentVariable('CARGO_INCREMENTAL', 'Process')
    RUSTFLAGS = [Environment]::GetEnvironmentVariable('RUSTFLAGS', 'Process')
    CARGO_TARGET_DIR = [Environment]::GetEnvironmentVariable('CARGO_TARGET_DIR', 'Process')
}

try {
    [void] (New-Item -ItemType Directory -Path $campaignRoot)
    $campaignCreated = $true
    $sourceA = Join-Path $campaignRoot 'source-a'
    $sourceB = Join-Path $campaignRoot 'source-b'
    $targetA = Join-Path $campaignRoot 'target-a'
    $targetB = Join-Path $campaignRoot 'target-b'
    $archivePath = Join-Path $campaignRoot 'source.tar'
    [void] (New-Item -ItemType Directory -Path $sourceA)
    [void] (New-Item -ItemType Directory -Path $sourceB)

    $commit = (Invoke-NativeCommand -FilePath 'git.exe' -ArgumentList @('rev-parse', '--verify', '--end-of-options', "$SourceRevision^{commit}") -WorkingDirectory $repositoryRoot).StdOut.Trim()
    if ($commit -notmatch '^[0-9a-f]{40}$') {
        throw "Resolved source commit is not a full lowercase Git object ID: $commit"
    }
    $tree = (Invoke-NativeCommand -FilePath 'git.exe' -ArgumentList @('rev-parse', "$commit^{tree}") -WorkingDirectory $repositoryRoot).StdOut.Trim()
    $sourceDateEpoch = (Invoke-NativeCommand -FilePath 'git.exe' -ArgumentList @('show', '-s', '--format=%ct', $commit) -WorkingDirectory $repositoryRoot).StdOut.Trim()
    if ($tree -notmatch '^[0-9a-f]{40}$' -or $sourceDateEpoch -notmatch '^[0-9]+$') {
        throw 'Git tree or commit timestamp identity is malformed.'
    }

    [void] (Invoke-NativeCommand -FilePath 'git.exe' -ArgumentList @('archive', '--format=tar', "--output=$archivePath", $commit) -WorkingDirectory $repositoryRoot)
    $archiveSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [void] (Invoke-NativeCommand -FilePath 'tar.exe' -ArgumentList @('-xf', $archivePath, '-C', $sourceA) -WorkingDirectory $campaignRoot)
    [void] (Invoke-NativeCommand -FilePath 'tar.exe' -ArgumentList @('-xf', $archivePath, '-C', $sourceB) -WorkingDirectory $campaignRoot)

    $cargoLockA = Join-Path $sourceA 'Cargo.lock'
    $cargoLockB = Join-Path $sourceB 'Cargo.lock'
    $cargoLockSha256 = (Get-FileHash -LiteralPath $cargoLockA -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($cargoLockSha256 -ne (Get-FileHash -LiteralPath $cargoLockB -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'Extracted Cargo.lock identities differ.'
    }

    $rustcVerboseA = (Invoke-NativeCommand -FilePath 'rustc.exe' -ArgumentList @('-vV') -WorkingDirectory $sourceA).StdOut.Trim()
    $rustcVerboseB = (Invoke-NativeCommand -FilePath 'rustc.exe' -ArgumentList @('-vV') -WorkingDirectory $sourceB).StdOut.Trim()
    $cargoVersionA = (Invoke-NativeCommand -FilePath 'cargo.exe' -ArgumentList @('--version') -WorkingDirectory $sourceA).StdOut.Trim()
    $cargoVersionB = (Invoke-NativeCommand -FilePath 'cargo.exe' -ArgumentList @('--version') -WorkingDirectory $sourceB).StdOut.Trim()
    if ($rustcVerboseA -cne $rustcVerboseB -or $cargoVersionA -cne $cargoVersionB) {
        throw 'Toolchain gate failed: isolated source roots select different rustc or Cargo identities.'
    }
    $rustcVerbose = $rustcVerboseA
    $cargoVersion = $cargoVersionA
    $rustcVersion = ($rustcVerbose -split "`r?`n")[0].Trim()
    $rustcCommitHash = ([regex]::Match($rustcVerbose, '(?m)^commit-hash:\s*(.+)$')).Groups[1].Value.Trim()
    $rustcCommitDate = ([regex]::Match($rustcVerbose, '(?m)^commit-date:\s*(.+)$')).Groups[1].Value.Trim()
    $rustcRelease = ([regex]::Match($rustcVerbose, '(?m)^release:\s*(.+)$')).Groups[1].Value.Trim()
    $rustcHost = ([regex]::Match($rustcVerbose, '(?m)^host:\s*(.+)$')).Groups[1].Value.Trim()
    $llvmVersion = ([regex]::Match($rustcVerbose, '(?m)^LLVM version:\s*(.+)$')).Groups[1].Value.Trim()
    if ([string]::IsNullOrWhiteSpace($rustcVersion) -or
        $rustcCommitHash -notmatch '^[0-9a-f]{40}$' -or
        $rustcCommitDate -notmatch '^\d{4}-\d{2}-\d{2}$' -or
        [string]::IsNullOrWhiteSpace($rustcRelease) -or
        [string]::IsNullOrWhiteSpace($rustcHost) -or
        [string]::IsNullOrWhiteSpace($llvmVersion)) {
        throw 'rustc verbose output did not expose complete version commit release host and LLVM identities.'
    }

    $env:SOURCE_DATE_EPOCH = $sourceDateEpoch
    $env:CARGO_INCREMENTAL = '0'
    $env:RUSTFLAGS = '-C link-arg=/Brepro'
    $buildArguments = @('build', '--release', '-p', 'cantor_field_cycle', '--locked', '--offline')

    $env:CARGO_TARGET_DIR = $targetA
    [void] (Invoke-NativeCommand -FilePath 'cargo.exe' -ArgumentList $buildArguments -WorkingDirectory $sourceA)
    $env:CARGO_TARGET_DIR = $targetB
    [void] (Invoke-NativeCommand -FilePath 'cargo.exe' -ArgumentList $buildArguments -WorkingDirectory $sourceB)

    $executableA = Join-Path $targetA 'release\cantor_field_cycle.exe'
    $executableB = Join-Path $targetB 'release\cantor_field_cycle.exe'
    $artifactA = Get-Item -LiteralPath $executableA
    $artifactB = Get-Item -LiteralPath $executableB
    $shaA = (Get-FileHash -LiteralPath $executableA -Algorithm SHA256).Hash.ToLowerInvariant()
    $shaB = (Get-FileHash -LiteralPath $executableB -Algorithm SHA256).Hash.ToLowerInvariant()
    $byteEqual = Test-FileBytesEqual -LeftPath $executableA -RightPath $executableB
    if ($artifactA.Length -ne $artifactB.Length -or $shaA -ne $shaB -or -not $byteEqual) {
        throw 'Reproducibility gate failed: executable identities differ.'
    }

    $contractA = (Invoke-NativeCommand -FilePath $executableA -ArgumentList @('contract') -WorkingDirectory $sourceA).StdOut
    $contractB = (Invoke-NativeCommand -FilePath $executableB -ArgumentList @('contract') -WorkingDirectory $sourceB).StdOut
    if ($contractA -cne $contractB) {
        throw 'Behavior gate failed: contract outputs differ.'
    }
    $contractSha256 = Get-TextSha256 -Text $contractA
    if ($contractSha256 -cne 'b6f5fd56767a0857c8f30560c63a2e4ae5c138f6ff374d6033f3e2a551e46e37') {
        throw 'Behavior gate failed: contract output bytes differ from the governed P0 reference.'
    }
    $contract = $contractA | ConvertFrom-Json
    if ($contract.profile -cne 'cantor-field-attention-cycle/0.1' -or
        $contract.field_profile -cne 'cantor-semantic-field/0.1' -or
        $contract.request_profile -cne 'cantor-field-attention-requests/0.5' -or
        $contract.authority -cne 'attention-local proposal and admission only') {
        throw 'Behavior gate failed: contract identity differs from the governed P0 reference.'
    }

    $fieldPathA = Join-Path $sourceA 'experiments\cantor_field_cycle_p0\attention_cycle_field.json'
    $fieldPathB = Join-Path $sourceB 'experiments\cantor_field_cycle_p0\attention_cycle_field.json'
    $fieldDigestA = (Invoke-NativeCommand -FilePath $executableA -ArgumentList @('field-digest', $fieldPathA) -WorkingDirectory $sourceA).StdOut.Trim()
    $fieldDigestB = (Invoke-NativeCommand -FilePath $executableB -ArgumentList @('field-digest', $fieldPathB) -WorkingDirectory $sourceB).StdOut.Trim()
    if ($fieldDigestA -cne $fieldDigestB -or
        $fieldDigestA -cne '136955ea1f1931de88c22cef392377f3a1fa4e6d4bd1de53450cb7e1f598c8e0') {
        throw 'Behavior gate failed: field digests differ from each other or the governed fixture.'
    }

    $reportContracts = @(
        [pscustomobject]@{
            Name = 'evox2_live_v5.json'
            Sha256 = '7a2b934811beb4bff4917791f68ee5e2988574480443c212616cf950b133418e'
            TerminalState = 'completed'
            LatchStatus = 'admitted_for_attention'
            Assurance = 'stored_provider_replay'
            ExchangeCount = 5
            VerifiedReportSha256 = 'ac2a07ac0b25267e16eefa68b56eb76ea08afd502ac9a555cc311de8eb0d204c'
        },
        [pscustomobject]@{
            Name = 'evox2_control_v5.json'
            Sha256 = '2fa77676b688a7ee6893e56c9afec596a8fa5f197011c065bb645bb8a6bbb337'
            TerminalState = 'control_completed'
            LatchStatus = $null
            Assurance = 'stored_provider_replay'
            ExchangeCount = 1
            VerifiedReportSha256 = '83a8450d88147acd0b93db1a7952955084d6736e9aa04e3e7a1d51d1bcbff599'
        },
        [pscustomobject]@{
            Name = 'evox2_hostile_boundary_v5.json'
            Sha256 = 'e7109037bc3ad84d0c8e19501d6c234e858cd9d5d4599c13afd825306ac09b98'
            TerminalState = 'rejected'
            LatchStatus = $null
            Assurance = 'stored_provider_replay'
            ExchangeCount = 4
            VerifiedReportSha256 = '6d57cd6fd9a0366b9f69105e30bc97be3e504bbd4af15968af3a9b47b931907e'
        }
    )
    $reportEvidence = @()
    foreach ($reportContract in $reportContracts) {
        $reportName = $reportContract.Name
        $reportA = Join-Path $sourceA "experiments\cantor_field_cycle_p0\$reportName"
        $reportB = Join-Path $sourceB "experiments\cantor_field_cycle_p0\$reportName"
        $reportShaA = (Get-FileHash -LiteralPath $reportA -Algorithm SHA256).Hash.ToLowerInvariant()
        $reportShaB = (Get-FileHash -LiteralPath $reportB -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($reportShaA -cne $reportContract.Sha256 -or $reportShaB -cne $reportContract.Sha256) {
            throw "Behavior gate failed: retained report bytes differ from the governed reference for $reportName."
        }
        $verifyA = (Invoke-NativeCommand -FilePath $executableA -ArgumentList @('verify', $reportA) -WorkingDirectory $sourceA).StdOut
        $verifyB = (Invoke-NativeCommand -FilePath $executableB -ArgumentList @('verify', $reportB) -WorkingDirectory $sourceB).StdOut
        if ($verifyA -cne $verifyB) {
            throw "Behavior gate failed: verifier outputs differ for $reportName."
        }
        $verification = $verifyA | ConvertFrom-Json
        Assert-ExactJsonPropertySet -InputObject $verification -ExpectedProperties @(
            'valid', 'terminal_state', 'latch_status', 'exchange_count', 'assurance', 'report_sha256'
        ) -Context "verifier output for $reportName"
        $latchMatches = if ($null -eq $reportContract.LatchStatus) {
            $null -eq $verification.latch_status
        }
        else {
            $verification.latch_status -ceq $reportContract.LatchStatus
        }
        if ($verification.valid -ne $true -or
            $verification.terminal_state -cne $reportContract.TerminalState -or
            -not $latchMatches -or
            $verification.assurance -cne $reportContract.Assurance -or
            $verification.exchange_count -ne $reportContract.ExchangeCount -or
            $verification.report_sha256 -cne $reportContract.VerifiedReportSha256) {
            throw "Behavior gate failed: retained report disposition differs from the governed reference for $reportName."
        }
        $reportEvidence += [ordered]@{
            report = $reportName
            report_sha256 = $reportShaA
            terminal_state = $verification.terminal_state
            latch_status = $verification.latch_status
            assurance = $verification.assurance
            exchange_count = $verification.exchange_count
            verified_report_sha256 = $verification.report_sha256
        }
    }

    $receipt = [ordered]@{
        profile = $Profile
        result = 'passed'
        source = [ordered]@{
            commit = $commit
            tree = $tree
            commit_timestamp = [long] $sourceDateEpoch
            archive_sha256 = $archiveSha256
            cargo_lock_sha256 = $cargoLockSha256
            source_root_count = 2
        }
        toolchain = [ordered]@{
            rustc_version = $rustcVersion
            rustc_commit_hash = $rustcCommitHash
            rustc_commit_date = $rustcCommitDate
            rustc_release = $rustcRelease
            rustc_verbose_sha256 = Get-TextSha256 -Text $rustcVerbose
            cargo_version = $cargoVersion
            host = $rustcHost
            llvm_version = $llvmVersion
        }
        build = [ordered]@{
            command = 'cargo build --release -p cantor_field_cycle --locked --offline'
            source_date_epoch = [long] $sourceDateEpoch
            cargo_incremental = 0
            rustflags = '-C link-arg=/Brepro'
            target_root_count = 2
        }
        artifact = [ordered]@{
            file_name = 'cantor_field_cycle.exe'
            bytes = [long] $artifactA.Length
            sha256 = $shaA
            byte_equal = $byteEqual
        }
        behavior = [ordered]@{
            contract_output_sha256 = $contractSha256
            field_digest = $fieldDigestA
            verifier_invocations = 6
            reports = $reportEvidence
            provider_request_count = 0
        }
        cleanup = [ordered]@{
            artifacts_retained = [bool] $KeepArtifacts
            temporary_paths_disclosed = $false
        }
        claim = 'byte-identical local reproduction on one Windows host and one recorded toolchain; not cross-host reproducibility, deployment trust, signing, semantic truth, or historical h8 provenance'
    }
}
finally {
    foreach ($entry in $inheritedEnvironment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
    if ($campaignCreated -and -not $KeepArtifacts) {
        $validatedCampaignRoot = Assert-SafeCampaignRoot -CandidatePath $campaignRoot -TargetRoot $targetRoot
        Remove-Item -LiteralPath $validatedCampaignRoot -Recurse -Force
    }
}

if ($null -eq $receipt) {
    throw 'Campaign ended without a receipt.'
}
$receipt | ConvertTo-Json -Depth 8
