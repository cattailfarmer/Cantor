[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$transaction = Join-Path $PSScriptRoot 'initialize_cantor_service_transaction.ps1'
$cantord = Join-Path $root 'target/release/cantord.exe'
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $temporaryBase ('cantor-bootstrap-transaction-tests-' + [guid]::NewGuid().ToString('N'))
$environmentRoot = Join-Path $testRoot 'environment'
$environmentPath = Join-Path $environmentRoot 'environment.json'
$script:refusals = 0
$script:reparseRefusals = 0

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Refused([string]$Label, [scriptblock]$Action) {
    $refused = $false
    try { & $Action *> $null }
    catch { $refused = $true }
    Assert-Test $refused "transaction admitted adversarial case: $Label"
    $script:refusals++
}

function Assert-NoStagingResidual([string]$RuntimeLeaf) {
    $residuals = @(Get-ChildItem -LiteralPath $testRoot -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -cmatch "^\.$([regex]::Escape($RuntimeLeaf))\.cantor-bootstrap-[a-f0-9]{32}$" })
    Assert-Test ($residuals.Count -eq 0) "staging residual remains for $RuntimeLeaf"
}

function Remove-TestRuntime([string]$Path, [string]$ExpectedLeaf) {
    if (-not [IO.Directory]::Exists($Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    $actualParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\', '/')
    Assert-Test ($actualParent.Equals($testRoot.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) 'test runtime cleanup parent differs'
    Assert-Test ($item.Name -ceq $ExpectedLeaf -and $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'test runtime cleanup identity differs'
    [IO.Directory]::Delete($item.FullName, $true)
}

function Invoke-FinalDiagnostic([string]$ConfigPath) {
    $output = @(& $cantord --check-config $ConfigPath 2>$null)
    Assert-Test ($LASTEXITCODE -eq 0 -and $output.Count -eq 1) 'final diagnostic did not return one ready line'
    $diagnostic = ($output -join "`n") | ConvertFrom-Json
    Assert-Test ($diagnostic.status -ceq 'ready' -and -not [bool]$diagnostic.privacy.listener_bound -and -not [bool]$diagnostic.privacy.service_started) 'final diagnostic boundary differs'
}

function Invoke-TamperRace {
    $pwshPath = (Get-Process -Id $PID).Path
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        $leaf = "tamper-runtime-$attempt"
        $runtime = Join-Path $testRoot $leaf
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $pwshPath
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        foreach ($argument in @(
            '-NoProfile', '-File', $transaction,
            '-EnvironmentPath', $environmentPath,
            '-RuntimeDirectory', $runtime,
            '-CantordPath', $cantord,
            '-AllowedEnvironmentRoot', $environmentRoot
        )) { $start.ArgumentList.Add($argument) }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        try {
            Assert-Test ($process.Start()) 'tamper-race process did not start'
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
            $injected = $false
            while (-not $process.HasExited) {
                if ([IO.Directory]::Exists($runtime)) {
                    try {
                        [IO.File]::WriteAllText((Join-Path $runtime 'operator-change.txt'), 'preserve', [Text.UTF8Encoding]::new($false))
                        $injected = $true
                        break
                    }
                    catch { }
                }
                [Threading.Thread]::Yield() | Out-Null
            }
            $process.WaitForExit()
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            if ($injected) {
                Assert-Test ($process.ExitCode -ne 0) 'postpublication tamper did not refuse success'
                Assert-Test ([IO.Directory]::Exists($runtime) -and [IO.File]::Exists((Join-Path $runtime 'operator-change.txt'))) 'changed residual was not preserved'
                Assert-Test ($stderr.Contains('changed residual preserved for operator review', [StringComparison]::Ordinal)) 'changed-residual fault class differs'
                Assert-Test (-not $stdout.Contains('"status": "initialized"', [StringComparison]::Ordinal)) 'tampered transaction emitted success'
                Remove-TestRuntime $runtime $leaf
                return $true
            }
            Remove-TestRuntime $runtime $leaf
            Assert-NoStagingResidual $leaf
        }
        finally { $process.Dispose() }
    }
    return $false
}

function Remove-TestRoot {
    if (-not [IO.Directory]::Exists($testRoot)) { return }
    $item = Get-Item -LiteralPath $testRoot -Force
    $actualParent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($item.FullName)).TrimEnd('\', '/')
    Assert-Test ($actualParent.Equals($temporaryBase.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) 'test cleanup parent differs'
    Assert-Test ($item.Name -cmatch '^cantor-bootstrap-transaction-tests-[a-f0-9]{32}$' -and $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'test cleanup target differs'
    [IO.Directory]::Delete($item.FullName, $true)
}

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    Push-Location $root
    try {
        & cargo run --quiet -p cantor_cli --example generate_demo --release --locked --offline -- $environmentRoot | Out-Null
        Assert-Test ($LASTEXITCODE -eq 0) 'public fixture generation failed'
    }
    finally { Pop-Location }
    Assert-Test ([IO.File]::Exists($cantord) -and [IO.File]::Exists($environmentPath)) 'required checked inputs are absent'
    $priorCantord = @(Get-Process cantord -ErrorAction SilentlyContinue | ForEach-Object Id)

    $successLeaf = 'success-runtime'
    $successRuntime = Join-Path $testRoot $successLeaf
    $receiptText = & $transaction `
        -EnvironmentPath $environmentPath `
        -RuntimeDirectory $successRuntime `
        -CantordPath $cantord `
        -AllowedEnvironmentRoot $environmentRoot
    Assert-Test ($receiptText -is [string] -and -not $receiptText.Contains("`n", [StringComparison]::Ordinal) -and -not $receiptText.Contains("`r", [StringComparison]::Ordinal)) 'success receipt is not one compact JSON line'
    $receipt = $receiptText | ConvertFrom-Json
    Assert-Test ($receipt.profile -ceq 'cantor-operator-bootstrap-transaction/0.1' -and $receipt.status -ceq 'initialized') 'success receipt profile or status differs'
    Assert-Test (@($receipt.checks).Count -eq 4 -and @($receipt.checks | Where-Object status -ne 'passed').Count -eq 0) 'success receipt checks differ'
    Assert-Test ([uint32]$receipt.publication.final_file_count -eq 3 -and [bool]$receipt.publication.staging_absent) 'success publication receipt differs'
    foreach ($field in $receipt.secrecy.PSObject.Properties) { Assert-Test (-not [bool]$field.Value) "secrecy field is true: $($field.Name)" }
    foreach ($field in $receipt.effects.PSObject.Properties) { Assert-Test (-not [bool]$field.Value) "effect field is true: $($field.Name)" }
    $tokenText = (Get-Content -LiteralPath (Join-Path $successRuntime 'cantord.token') -Raw).Trim()
    Assert-Test ($tokenText -cmatch '^[a-f0-9]{64}$') 'created token shape differs'
    Assert-Test (-not $receiptText.Contains($tokenText, [StringComparison]::OrdinalIgnoreCase) -and -not $receiptText.Contains('cantord.token', [StringComparison]::OrdinalIgnoreCase)) 'receipt disclosed token content or path'
    Assert-Test ((@(Get-ChildItem -LiteralPath $successRuntime -Force | ForEach-Object Name | Sort-Object) -join ',') -ceq 'activation.json,cantord.token,service.json') 'success inventory differs'
    Invoke-FinalDiagnostic (Join-Path $successRuntime 'service.json')
    Assert-NoStagingResidual $successLeaf
    Remove-TestRuntime $successRuntime $successLeaf

    $nonLoopbackLeaf = 'nonloopback-runtime'
    Assert-Refused 'nonloopback' {
        & $transaction -EnvironmentPath $environmentPath -RuntimeDirectory (Join-Path $testRoot $nonLoopbackLeaf) -CantordPath $cantord -AllowedEnvironmentRoot $environmentRoot -ListenAddress '0.0.0.0:39841'
    }
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $testRoot $nonLoopbackLeaf))) 'nonloopback refusal created final root'
    Assert-NoStagingResidual $nonLoopbackLeaf

    $otherRoot = Join-Path $testRoot 'other-root'
    [IO.Directory]::CreateDirectory($otherRoot) | Out-Null
    Assert-Refused 'uncontained-environment' {
        & $transaction -EnvironmentPath $environmentPath -RuntimeDirectory (Join-Path $testRoot 'uncontained-runtime') -CantordPath $cantord -AllowedEnvironmentRoot $otherRoot
    }

    $preexistingRuntime = Join-Path $testRoot 'preexisting-runtime'
    [IO.Directory]::CreateDirectory($preexistingRuntime) | Out-Null
    [IO.File]::WriteAllText((Join-Path $preexistingRuntime 'marker.txt'), 'preserve', [Text.UTF8Encoding]::new($false))
    Assert-Refused 'preexisting-runtime' {
        & $transaction -EnvironmentPath $environmentPath -RuntimeDirectory $preexistingRuntime -CantordPath $cantord -AllowedEnvironmentRoot $environmentRoot
    }
    Assert-Test ((Get-Content -LiteralPath (Join-Path $preexistingRuntime 'marker.txt') -Raw) -ceq 'preserve') 'preexisting runtime was mutated'

    $fileRuntime = Join-Path $testRoot 'file-runtime'
    [IO.File]::WriteAllText($fileRuntime, 'preserve', [Text.UTF8Encoding]::new($false))
    Assert-Refused 'file-as-runtime' {
        & $transaction -EnvironmentPath $environmentPath -RuntimeDirectory $fileRuntime -CantordPath $cantord -AllowedEnvironmentRoot $environmentRoot
    }
    Assert-Test ((Get-Content -LiteralPath $fileRuntime -Raw) -ceq 'preserve') 'file-as-runtime input was mutated'

    Assert-Refused 'missing-cantord' {
        & $transaction -EnvironmentPath $environmentPath -RuntimeDirectory (Join-Path $testRoot 'missing-cantord-runtime') -CantordPath (Join-Path $testRoot 'missing-cantord.exe') -AllowedEnvironmentRoot $environmentRoot
    }
    Assert-Refused 'repository-root' {
        & $transaction -EnvironmentPath $environmentPath -RuntimeDirectory $root -CantordPath $cantord -AllowedEnvironmentRoot $environmentRoot
    }
    Assert-Refused 'parent-traversal' {
        & $transaction -EnvironmentPath $environmentPath -RuntimeDirectory (Join-Path $testRoot 'child\..\traversal-runtime') -CantordPath $cantord -AllowedEnvironmentRoot $environmentRoot
    }

    $linkPath = Join-Path $testRoot 'environment-link.json'
    try {
        New-Item -ItemType SymbolicLink -Path $linkPath -Target $environmentPath -ErrorAction Stop | Out-Null
        Assert-Refused 'environment-reparse' {
            & $transaction -EnvironmentPath $linkPath -RuntimeDirectory (Join-Path $testRoot 'reparse-runtime') -CantordPath $cantord -AllowedEnvironmentRoot $testRoot
        }
        $script:reparseRefusals++
    }
    catch {
        if (Test-Path -LiteralPath $linkPath) { throw }
    }

    Assert-Test (Invoke-TamperRace) 'could not exercise postpublication changed-residual refusal'
    $script:refusals++
    $newCantord = @(Get-Process cantord -ErrorAction SilentlyContinue | Where-Object { $priorCantord -notcontains $_.Id } | ForEach-Object Id)
    Assert-Test ($newCantord.Count -eq 0) "transaction left cantord process residuals: $($newCantord -join ',')"

    Write-Output "operator_bootstrap_transaction_tests=passed refusals=$script:refusals reparse_refusals=$script:reparseRefusals inventory=3 postpublish_changed_residual_preserved=true"
}
finally {
    Remove-TestRoot
}
