[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'verify_cantor_nested_host_gap_audit.ps1'
$matrixRelative = 'experiments/nested_cantor_host_gap_audit/artifacts/nested_cantor_host_gap_matrix_v1.json'
$matrixSource = Join-Path $repositoryRoot $matrixRelative
$temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixtureLeaf = 'cantor-nested-host-gap-test-' + [guid]::NewGuid().ToString('N')
$fixtureRoot = [IO.Path]::GetFullPath((Join-Path $temporaryParent $fixtureLeaf))
$refusals = 0

function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Write-Json([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path, "$(($Value | ConvertTo-Json -Depth 100).Replace("`r`n", "`n"))`n", [Text.UTF8Encoding]::new($false))
}

function Read-Baseline {
    Get-Content -LiteralPath $matrixSource -Raw | ConvertFrom-Json
}

function Invoke-Refusal([string]$Label) {
    $refused = $false
    try {
        & $verifier -RepositoryRoot $fixtureRoot -MatrixPath $matrixRelative 2>$null | Out-Null
    }
    catch { $refused = $true }
    Assert-Test $refused "verifier admitted mutation: $Label"
    $script:refusals++
}

try {
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    $baseline = Read-Baseline
    $copyPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    [void]$copyPaths.Add($matrixRelative)
    foreach ($entry in @($baseline.entries)) {
        foreach ($relative in @($entry.evidence_paths)) { [void]$copyPaths.Add([string]$relative) }
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
    & $verifier -RepositoryRoot $fixtureRoot -MatrixPath $matrixRelative | Out-Null

    $fixtureMatrix = Join-Path $fixtureRoot $matrixRelative
    $variant = Read-Baseline
    $variant | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'unknown top-level field'

    $variant = Read-Baseline
    $variant.profile = 'wrong-profile'
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'wrong profile'

    $variant = Read-Baseline
    $variant.source_uuid = [guid]::Empty.Guid
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'wrong source identity'

    $variant = Read-Baseline
    $variant.entry_count = 15
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'wrong entry count'

    $variant = Read-Baseline
    $variant.entries = @($variant.entries | Select-Object -First 15)
    $variant.entry_count = 15
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'missing coordinate'

    $variant = Read-Baseline
    $swap = $variant.entries[0]
    $variant.entries[0] = $variant.entries[1]
    $variant.entries[1] = $swap
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'coordinate reordering'

    $variant = Read-Baseline
    $variant.entries[1].coordinate = $variant.entries[0].coordinate
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'duplicate coordinate'

    $variant = Read-Baseline
    $variant.entries[0].substrate_state = 'production_ready'
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'substrate authority widening'

    $variant = Read-Baseline
    $variant.entries[0].nested_system_state = 'complete'
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'nested completion fabrication'

    $variant = Read-Baseline
    $variant.entries[0].gap = ''
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'gap deletion'

    $variant = Read-Baseline
    $variant.entries[0].next_contract = 'launch_now'
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'contract sequence substitution'

    $variant = Read-Baseline
    $variant.entries[0].effect_authority = 'process_launch'
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'effect authority fabrication'

    $variant = Read-Baseline
    $variant.entries[0].evidence_paths[0] = $variant.entries[1].evidence_paths[0]
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'evidence substitution'

    $variant = Read-Baseline
    $variant.entries[0].evidence_paths[0] = 'C:/outside.sop'
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'absolute evidence path'

    $variant = Read-Baseline
    $variant.entries[0] | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    Write-Json $fixtureMatrix $variant
    Invoke-Refusal 'unknown entry field'

    Write-Json $fixtureMatrix (Read-Baseline)
    $evidenceRelative = 'proofs/Cantor_Seeded_Compiler_Slice4_External_Inference_Host_Proof.sop'
    & git -C $fixtureRoot rm --cached --quiet -- $evidenceRelative
    Assert-Test ($LASTEXITCODE -eq 0) 'fixture untrack failed'
    Invoke-Refusal 'untracked evidence'
    & git -c core.autocrlf=false -C $fixtureRoot add -- $evidenceRelative
    Assert-Test ($LASTEXITCODE -eq 0) 'fixture retrack failed'

    $proofPath = Join-Path $fixtureRoot $evidenceRelative
    $proofText = [IO.File]::ReadAllText($proofPath)
    [IO.File]::WriteAllText($proofPath, $proofText.Replace('SeededCompilerSlice4ExternalInferenceHost_implemented_verified_and_closed', 'SeededCompilerSlice4ExternalInferenceHost_unverified', [StringComparison]::Ordinal), [Text.UTF8Encoding]::new($false))
    Invoke-Refusal 'proof marker tamper'
    [IO.File]::WriteAllText($proofPath, $proofText, [Text.UTF8Encoding]::new($false))

    $providerRelative = 'experiments/llama_tool_reflection/artifacts/lifecycle_tool_loop/provider_unavailable_probe_verification.json'
    $providerPath = Join-Path $fixtureRoot $providerRelative
    $providerText = [IO.File]::ReadAllText($providerPath)
    [IO.File]::WriteAllText($providerPath, $providerText.Replace('"provider_contacted": false', '"provider_contacted": true', [StringComparison]::Ordinal), [Text.UTF8Encoding]::new($false))
    Invoke-Refusal 'provider-contact fabrication'
    [IO.File]::WriteAllText($providerPath, $providerText, [Text.UTF8Encoding]::new($false))

    & $verifier -RepositoryRoot $fixtureRoot -MatrixPath $matrixRelative | Out-Null
}
finally {
    if ([IO.Directory]::Exists($fixtureRoot)) {
        $resolved = [IO.Path]::GetFullPath($fixtureRoot)
        Assert-Test ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\', '/') -ceq $temporaryParent.TrimEnd('\', '/') -and [IO.Path]::GetFileName($resolved) -cmatch '^cantor-nested-host-gap-test-[a-f0-9]{32}$') 'fixture cleanup identity differs'
        Get-ChildItem -LiteralPath $resolved -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = [IO.FileAttributes]::Normal } catch {} }
        (Get-Item -LiteralPath $resolved -Force).Attributes = [IO.FileAttributes]::Directory
        [IO.Directory]::Delete($resolved, $true)
    }
}

Write-Output "nested_host_gap_tests=passed verifier_refusals=$refusals fixture_removed=true"
