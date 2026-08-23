[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify_cantor_development_state_supersession_audit.ps1'
$inventoryRelative = 'experiments/development_state_supersession_audit/artifacts/development_state_supersession_inventory_v1.json'
$inventorySource = Join-Path $repositoryRoot $inventoryRelative
$temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixtureLeaf = 'cantor-dsa-audit-test-' + [guid]::NewGuid().ToString('N')
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path $temporaryParent $fixtureLeaf))
$refusals = 0

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Write-Json([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path, "$(($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
}

function Read-Baseline {
    Get-Content -LiteralPath $inventorySource -Raw | ConvertFrom-Json
}

function Invoke-Refusal([string]$Label) {
    $refused = $false
    try {
        & $verifier -RepositoryRoot $fixtureRoot -InventoryPath $inventoryRelative 2>$null | Out-Null
    }
    catch { $refused = $true }
    Assert-Test $refused "verifier admitted mutation: $Label"
    $script:refusals++
}

try {
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    $baseline = Read-Baseline
    $copyPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $copyPaths.Add($inventoryRelative) | Out-Null
    foreach ($entry in @($baseline.entries)) {
        $copyPaths.Add([string]$entry.target_path) | Out-Null
        $copyPaths.Add([string]$entry.proof_path) | Out-Null
    }
    foreach ($relative in $copyPaths) {
        $source = Join-Path $repositoryRoot $relative
        $destination = Join-Path $fixtureRoot $relative
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
        [IO.File]::Copy($source, $destination, $false)
    }
    & git -C $fixtureRoot init --quiet
    Assert-Test ($LASTEXITCODE -eq 0) 'fixture git init failed'
    & git -c core.autocrlf=false -C $fixtureRoot add -- .
    Assert-Test ($LASTEXITCODE -eq 0) 'fixture git add failed'
    & $verifier -RepositoryRoot $fixtureRoot -InventoryPath $inventoryRelative | Out-Null

    $fixtureInventory = Join-Path $fixtureRoot $inventoryRelative
    $variant = Read-Baseline
    $variant | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'unknown top-level field'

    $variant = Read-Baseline
    $variant.profile = 'wrong-profile'
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'wrong profile'

    $variant = Read-Baseline
    $variant.entry_count = 21
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'wrong entry count'

    $variant = Read-Baseline
    $variant.entries = @($variant.entries | Select-Object -First 21)
    $variant.entry_count = 21
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'missing entry'

    $variant = Read-Baseline
    $variant.entries[1].target_path = $variant.entries[0].target_path
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'duplicate target'

    $variant = Read-Baseline
    $swap = $variant.entries[0]
    $variant.entries[0] = $variant.entries[1]
    $variant.entries[1] = $swap
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'entry reordering'

    $variant = Read-Baseline
    $variant.entries[0].proof_path = $variant.entries[1].proof_path
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'wrong proof mapping'

    $variant = Read-Baseline
    $variant.entries[0].historical_marker = 'implementation_ready'
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'wrong historical marker'

    $variant = Read-Baseline
    $variant.entries[0].current_status = 'production_ready'
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'authority widening status'

    $variant = Read-Baseline
    $variant.entries[0] | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'unknown entry field'

    $variant = Read-Baseline
    $variant.entries[0].target_path = 'C:/outside.sop'
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'absolute target'

    $variant = Read-Baseline
    $variant.entries[0].target_path = '../outside.sop'
    Write-Json $fixtureInventory $variant
    Invoke-Refusal 'traversing target'

    Write-Json $fixtureInventory (Read-Baseline)
    $targetRelative = [string]$baseline.entries[0].target_path
    $targetPath = Join-Path $fixtureRoot $targetRelative
    $targetText = [IO.File]::ReadAllText($targetPath)
    [IO.File]::WriteAllText($targetPath, $targetText.Replace('& [CurrentSupersession] is proof bound', '& [CurrentSupersession] is missing', [StringComparison]::Ordinal), [Text.UTF8Encoding]::new($false))
    Invoke-Refusal 'missing target supersession'
    [IO.File]::WriteAllText($targetPath, $targetText, [Text.UTF8Encoding]::new($false))

    $proofRelative = [string]$baseline.entries[0].proof_path
    $proofPath = Join-Path $fixtureRoot $proofRelative
    $proofText = [IO.File]::ReadAllText($proofPath)
    [IO.File]::WriteAllText($proofPath, $proofText.Replace('  + [status] is passed', '  + [status] is absent', [StringComparison]::Ordinal), [Text.UTF8Encoding]::new($false))
    Invoke-Refusal 'missing proof marker'
    [IO.File]::WriteAllText($proofPath, $proofText, [Text.UTF8Encoding]::new($false))

    & git -C $fixtureRoot rm --cached --quiet -- $targetRelative
    Assert-Test ($LASTEXITCODE -eq 0) 'fixture untrack failed'
    Invoke-Refusal 'untracked target'
    & git -c core.autocrlf=false -C $fixtureRoot add -- $targetRelative
    Assert-Test ($LASTEXITCODE -eq 0) 'fixture retrack failed'

    & $verifier -RepositoryRoot $fixtureRoot -InventoryPath $inventoryRelative | Out-Null
}
finally {
    if ([IO.Directory]::Exists($fixtureRoot)) {
        $resolved = [IO.Path]::GetFullPath($fixtureRoot)
        Assert-Test ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\', '/') -ceq $temporaryParent.TrimEnd('\', '/') -and [IO.Path]::GetFileName($resolved) -cmatch '^cantor-dsa-audit-test-[a-f0-9]{32}$') 'fixture cleanup identity differs'
        Get-ChildItem -LiteralPath $resolved -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = [IO.FileAttributes]::Normal } catch {} }
        (Get-Item -LiteralPath $resolved -Force).Attributes = [IO.FileAttributes]::Directory
        [IO.Directory]::Delete($resolved, $true)
    }
}

Write-Output "development_state_supersession_tests=passed verifier_refusals=$refusals fixture_removed=true"
