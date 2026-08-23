[CmdletBinding()]
param(
    [string]$InventoryPath = 'experiments/development_state_supersession_audit/artifacts/development_state_supersession_inventory_v1.json',
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$defaultRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$root = if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { $defaultRoot } else { [IO.Path]::GetFullPath($RepositoryRoot) }
$inventoryFullPath = if ([IO.Path]::IsPathRooted($InventoryPath)) { [IO.Path]::GetFullPath($InventoryPath) } else { [IO.Path]::GetFullPath((Join-Path $root $InventoryPath)) }
$profile = 'cantor-development-state-supersession-audit/0.1'

function Assert-Audit([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Properties([object]$Value, [string[]]$Expected, [string]$Label) {
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    Assert-Audit (($actual -join ',') -ceq ($wanted -join ',')) "$Label properties differ"
}

function Get-ContainedPhysicalFile([string]$RelativePath, [string]$Label) {
    Assert-Audit (-not [string]::IsNullOrWhiteSpace($RelativePath) -and $RelativePath -cmatch '^[A-Za-z0-9_.\-/]+$') "$Label path shape differs"
    Assert-Audit (-not [IO.Path]::IsPathRooted($RelativePath) -and ($RelativePath -split '/') -notcontains '..' -and -not $RelativePath.Contains('\')) "$Label path is not conservative relative form"
    $full = [IO.Path]::GetFullPath((Join-Path $root $RelativePath))
    $prefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    Assert-Audit ($full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) "$Label escapes repository root"
    $item = Get-Item -LiteralPath $full -Force
    Assert-Audit (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $item.Length -gt 0 -and $item.Length -le 1MB) "$Label is not one bounded physical file"
    $tracked = @(& git -C $root ls-files --error-unmatch -- $RelativePath 2>$null)
    Assert-Audit ($LASTEXITCODE -eq 0 -and $tracked.Count -eq 1 -and $tracked[0].Replace('\', '/') -ceq $RelativePath) "$Label is not one exact tracked file"
    $item
}

$expectedRows = @(
    'feature_support/M2BSuppliedContentDigest_Requirement_Matrix.sop|  + [status] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Content_Digest_Proof.sop|  + [status] is passed',
    'feature_support/M2BSuppliedDirectoryTopologyProjection_Requirement_Matrix.sop|& [CoverageState] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Directory_Topology_Projection_Proof.sop|  + [status] is passed',
    'feature_support/M2BSuppliedRegularFileTopologyProjection_Requirement_Matrix.sop|  + [status] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Regular_File_Topology_Projection_Proof.sop|  + [status] is passed',
    'feature_support/M2BSuppliedRootTopologyProjection_Requirement_Matrix.sop|& [CoverageState] is implementation_ready with no physical test requirement|implemented_and_proven|proofs/Cantor_M2B_Supplied_Root_Topology_Projection_Proof.sop|  + [status] is passed',
    'feature_support/M2BSuppliedTopologyInventoryAssembly_Requirement_Matrix.sop|& [CoverageState] is implementation_ready with no physical test requirement|implemented_and_proven|proofs/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Proof.sop|  + [status] is passed',
    'feature_support/M2BWindowsSysCompileProbe_Requirement_Matrix.sop|  + [status] is authorized_pending_implementation|implemented_and_proven_by_lock_revision|proofs/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Proof.sop|  + [status] is complete',
    'feature_support/slices/M2BSuppliedContentDigest.sop|  + [authority_state] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Content_Digest_Proof.sop|  + [status] is passed',
    'feature_support/slices/M2BSuppliedDirectoryTopologyProjection.sop|  + [state] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Directory_Topology_Projection_Proof.sop|  + [status] is passed',
    'feature_support/slices/M2BSuppliedOrderedTopologyInventoryDigest.sop|  + [state] is implementation_ready_after_signature|implemented_and_proven|proofs/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Proof.sop|  + [status] is passed',
    'feature_support/slices/M2BSuppliedRegularFileTopologyProjection.sop|  + [authority_state] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Regular_File_Topology_Projection_Proof.sop|  + [status] is passed',
    'feature_support/slices/M2BSuppliedRootTopologyProjection.sop|  + [state] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Root_Topology_Projection_Proof.sop|  + [status] is passed',
    'feature_support/slices/M2BSuppliedTopologyInventoryAssembly.sop|  + [state] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Proof.sop|  + [status] is passed',
    'feature_support/slices/M2BWindowsSysCompileProbe.sop|  + [enqueue_readiness] is ready|implemented_and_proven_by_lock_revision|proofs/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Proof.sop|  + [status] is complete',
    'narrative/registries/Cantor_M2B_Supplied_Content_Digest_Registry.sop|  + [state] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Content_Digest_Proof.sop|  + [status] is passed',
    'narrative/registries/Cantor_M2B_Supplied_Directory_Topology_Projection_Registry.sop|  + [state] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Directory_Topology_Projection_Proof.sop|  + [status] is passed',
    'narrative/registries/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Registry.sop|  + [state] is implementation_ready_after_signature|implemented_and_proven|proofs/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Reconciliation_Proof.sop|  + [status] is passed',
    'narrative/registries/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Registry.sop|  + [state] is implementation_ready_after_signature|implemented_and_proven|proofs/Cantor_M2B_Supplied_Ordered_Topology_Inventory_Digest_Proof.sop|  + [status] is passed',
    'narrative/registries/Cantor_M2B_Supplied_Regular_File_Topology_Projection_Registry.sop|  + [state] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Regular_File_Topology_Projection_Proof.sop|  + [status] is passed',
    'narrative/registries/Cantor_M2B_Supplied_Root_Topology_Projection_Registry.sop|  + [state] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Root_Topology_Projection_Proof.sop|  + [status] is passed',
    'narrative/registries/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Registry.sop|  + [state] is implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Topology_Inventory_Assembly_Proof.sop|  + [status] is passed',
    'plans/Cantor_M2B_Windows_Sys_Compile_Probe_Plan.sop|  + [status] is ready|implemented_and_proven_by_lock_revision|proofs/Cantor_M2B_Windows_Sys_Compile_Probe_Lock_Revision_Proof.sop|  + [status] is complete',
    'plans/Cantor_Phase3_M2B_Activation_Readiness.sop|  + [status] is supplied_root_topology_projection_signed_implementation_ready|implemented_and_proven|proofs/Cantor_M2B_Supplied_Root_Topology_Projection_Proof.sop|  + [status] is passed'
)

Assert-Audit ([IO.Directory]::Exists($root) -and $expectedRows.Count -eq 22) 'repository root or expected inventory differs'
$inventoryItem = Get-Item -LiteralPath $inventoryFullPath -Force
Assert-Audit (-not $inventoryItem.PSIsContainer -and ($inventoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $inventoryItem.Length -gt 0 -and $inventoryItem.Length -le 128KB) 'inventory is not one bounded physical file'
$inventory = Get-Content -LiteralPath $inventoryItem.FullName -Raw | ConvertFrom-Json
Assert-Properties $inventory @('profile', 'version', 'entry_count', 'entries') 'inventory'
Assert-Audit ($inventory.profile -ceq $profile -and [int]$inventory.version -eq 1 -and [int]$inventory.entry_count -eq 22 -and @($inventory.entries).Count -eq 22) 'inventory identity or count differs'

$targets = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$canonicalRows = [Collections.Generic.List[string]]::new()
for ($index = 0; $index -lt $expectedRows.Count; $index++) {
    $parts = @($expectedRows[$index] -split '\|', 5)
    Assert-Audit ($parts.Count -eq 5) 'internal expected row differs'
    $entry = $inventory.entries[$index]
    Assert-Properties $entry @('target_path', 'historical_marker', 'current_status', 'proof_path', 'proof_marker') "entry $index"
    $actual = @([string]$entry.target_path, [string]$entry.historical_marker, [string]$entry.current_status, [string]$entry.proof_path, [string]$entry.proof_marker)
    for ($field = 0; $field -lt 5; $field++) {
        Assert-Audit ($actual[$field] -ceq $parts[$field]) "entry $index field $field differs"
    }
    Assert-Audit ($targets.Add($actual[0])) "duplicate target: $($actual[0])"
    $targetItem = Get-ContainedPhysicalFile $actual[0] "target $index"
    $proofItem = Get-ContainedPhysicalFile $actual[3] "proof $index"
    $targetLines = @(Get-Content -LiteralPath $targetItem.FullName)
    $proofLines = @(Get-Content -LiteralPath $proofItem.FullName)
    Assert-Audit ($targetLines -ccontains $actual[1]) "historical marker differs: $($actual[0])"
    Assert-Audit (@($targetLines | Where-Object { $_ -ceq '& [CurrentSupersession] is proof bound' }).Count -eq 1) "supersession count differs: $($actual[0])"
    Assert-Audit ($targetLines -ccontains '  + [audit_profile] is cantor-development-state-supersession-audit/0.1') "audit profile differs: $($actual[0])"
    Assert-Audit ($targetLines -ccontains "  + [historical_marker] is $($actual[1])") "supersession marker differs: $($actual[0])"
    Assert-Audit ($targetLines -ccontains "  + [current_status] is $($actual[2])") "current status differs: $($actual[0])"
    Assert-Audit ($targetLines -ccontains "  + [current_proof] is $($actual[3])") "current proof differs: $($actual[0])"
    Assert-Audit ($targetLines -ccontains '  + [superseded_for_current_navigation] is true') "supersession truth differs: $($actual[0])"
    Assert-Audit ($proofLines -ccontains $actual[4]) "proof marker differs: $($actual[3])"
    $canonicalRows.Add(($actual -join "`0"))
}

$canonicalBytes = [Text.Encoding]::UTF8.GetBytes(($canonicalRows -join "`n"))
$mappingDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($canonicalBytes))
$receipt = [ordered]@{
    profile = $profile
    status = 'passed'
    entry_count = [uint32]22
    target_count = [uint32]$targets.Count
    mapping_sha256 = $mappingDigest
    historical_markers_preserved = $true
    current_supersessions_verified = $true
    runtime_or_authority_changed = $false
}
Write-Output ($receipt | ConvertTo-Json -Compress)
