param(
    [switch]$VerifyOnly,
    [string]$Cargo = 'cargo'
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$fixtureRoot = Join-Path $root 'fixtures/sjs_repository_graph_p0'
$inventoryPath = Join-Path $fixtureRoot 'diff_inventory.json'
$changeSetPath = Join-Path $fixtureRoot 'change_set.json'
$receiptPath = Join-Path $fixtureRoot 'verification_receipt.json'
$evidencePath = Join-Path $root 'crates/cantor_ecosystem/evidence/sjs_repository_graph_p0_evidence_manifest.json'
$utf8 = [Text.UTF8Encoding]::new($false)

function Get-CanonicalJson([object]$Value) {
    return $Value | ConvertTo-Json -Depth 64 -Compress
}

function Get-DomainDigest([string]$Domain, [object]$Value) {
    $body = [Text.Encoding]::UTF8.GetBytes((Get-CanonicalJson $Value))
    $length = [BitConverter]::GetBytes([uint64]$body.Length)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($length) }
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash(
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        $hash.AppendData([Text.Encoding]::UTF8.GetBytes($Domain))
        $hash.AppendData([byte[]]@(0))
        $hash.AppendData($length)
        $hash.AppendData($body)
        return [Convert]::ToHexString($hash.GetHashAndReset())
    } finally {
        $hash.Dispose()
    }
}

function New-Node(
    [string]$NodeId,
    [string]$Kind,
    [AllowNull()][object]$Path,
    [AllowNull()][object]$Sha256
) {
    return [ordered]@{
        node_id = $NodeId
        kind = $Kind
        repository_path = $Path
        content_sha256 = $Sha256
    }
}

function New-Coordinate(
    [string]$Status,
    [AllowNull()][object]$OldPath,
    [AllowNull()][object]$NewPath
) {
    return [ordered]@{
        status = $Status
        old_path = $OldPath
        new_path = $NewPath
    }
}

function New-Event(
    [string]$EventUuid,
    [string]$Suffix,
    [string]$Operation,
    [object]$Coordinate,
    [AllowNull()][object]$BeforeSha256,
    [AllowNull()][object]$AfterSha256,
    [bool]$Tombstone,
    [bool]$Generated,
    [string]$Reason
) {
    $event = [ordered]@{
        profile = 'cantor-sjs-element-history-event/0.1'
        event_uuid = $EventUuid
        event_node_id = "event:$Suffix"
        element_id = "cantor.fixture.$Suffix"
        element_node_id = "element:$Suffix"
        operation = $Operation
        turn_uuid = '22222222-2222-4222-8222-222222222222'
        conversation_uuid = '33333333-3333-4333-8333-333333333333'
        change_set_uuid = '44444444-4444-4444-8444-444444444444'
        covered_changes = @($Coordinate)
        source_node_ids = @('source:graph')
        requirement_node_ids = @('requirement:csg-001')
        constraint_node_ids = @('constraint:c01')
        justification_node_ids = @('justification:graph')
        plan_node_ids = @('plan:graph')
        implementation_node_ids = @("implementation:$Suffix")
        evidence_node_ids = @('evidence:graph')
        proof_node_ids = @('proof:graph')
        narrative_node_ids = @('narrative:graph')
        frontier_node_ids = @('frontier:physical-git')
        reason_summary = $Reason
        before_sha256 = $BeforeSha256
        after_sha256 = $AfterSha256
        tombstone = $Tombstone
        generated = $Generated
        nonclaims = @('No physical Git observation mutation commit push or publication authority.')
        unresolved_frontier = @('Physical staged-diff acquisition remains separately governed.')
        event_sha256 = ''
    }
    $event.event_sha256 = Get-DomainDigest 'cantor:sjs-repository-graph:element-event:0.1' $event
    return $event
}

function Write-Json([string]$Path, [object]$Value) {
    $json = ($Value | ConvertTo-Json -Depth 64) + "`n"
    [IO.File]::WriteAllText($Path, $json, $utf8)
}

function Assert-JsonEqual([string]$Path, [object]$Expected, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "$Label is absent" }
    $actual = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 64 -Compress
    $expectedJson = Get-CanonicalJson $Expected
    if ($actual -cne $expectedJson) { throw "$Label differs" }
}

$shaA = [string]::new('A', 64)
$shaB = [string]::new('B', 64)
$shaC = [string]::new('C', 64)
$shaD = [string]::new('D', 64)
$shaE = [string]::new('E', 64)
$shaF = [string]::new('F', 64)

$inventory = [ordered]@{
    profile = 'cantor-sjs-diff-inventory/0.1'
    repository_id = 'cattailfarmer/cantor'
    branch_ref = 'refs/heads/codex/self-hosted-corpus'
    predecessor_commit = '2e802dc9f10b9902543d670ab6a183c70e04a24e'
    entries = @(
        [ordered]@{ status = 'added'; old_path = $null; new_path = 'src/new.rs'; before_sha256 = $null; after_sha256 = $shaA },
        [ordered]@{ status = 'modified'; old_path = $null; new_path = 'src/existing.rs'; before_sha256 = $shaA; after_sha256 = $shaB },
        [ordered]@{ status = 'deleted'; old_path = 'src/retired.rs'; new_path = $null; before_sha256 = $shaC; after_sha256 = $null },
        [ordered]@{ status = 'renamed'; old_path = 'src/old_name.rs'; new_path = 'src/new_name.rs'; before_sha256 = $shaD; after_sha256 = $shaE },
        [ordered]@{ status = 'generated_refresh'; old_path = $null; new_path = 'evidence/manifest.json'; before_sha256 = $shaF; after_sha256 = $shaA }
    )
    inventory_sha256 = ''
}
$inventory.inventory_sha256 = Get-DomainDigest 'cantor:sjs-repository-graph:diff-inventory:0.1' $inventory

$commonNodes = @(
    (New-Node 'source:graph' 'source' 'source_documents/graph.sop' $shaA),
    (New-Node 'requirement:csg-001' 'requirement' $null $null),
    (New-Node 'constraint:c01' 'constraint' $null $null),
    (New-Node 'justification:graph' 'justification' 'justifications/graph.sop' $shaA),
    (New-Node 'plan:graph' 'plan' 'plans/graph.sop' $shaA),
    (New-Node 'evidence:graph' 'evidence' 'evidence/graph.json' $shaA),
    (New-Node 'proof:graph' 'proof' 'proofs/graph.sop' $shaA),
    (New-Node 'narrative:graph' 'narrative_turn' 'narrative/turns/graph.sop' $shaA),
    (New-Node 'frontier:physical-git' 'frontier' $null $null)
)
$suffixes = @('add', 'modify', 'delete', 'rename', 'generated')
$nodes = [Collections.Generic.List[object]]::new()
foreach ($node in $commonNodes) { $nodes.Add($node) }
foreach ($suffix in $suffixes) {
    $nodes.Add((New-Node "element:$suffix" 'element' $null $null))
    $nodes.Add((New-Node "event:$suffix" 'element_history_event' $null $null))
    $nodes.Add((New-Node "implementation:$suffix" 'implementation_artifact' "implementation/$suffix.sop" $shaA))
}

$events = @(
    (New-Event '11111111-1111-4111-8111-111111111111' 'add' 'add' (New-Coordinate 'added' $null 'src/new.rs') $null $shaA $false $false 'Add one governed element from signed source.'),
    (New-Event '11111111-1111-4111-8111-111111111112' 'modify' 'correct' (New-Coordinate 'modified' $null 'src/existing.rs') $shaA $shaB $false $false 'Correct one existing governed element for its requirement.'),
    (New-Event '11111111-1111-4111-8111-111111111113' 'delete' 'delete' (New-Coordinate 'deleted' 'src/retired.rs' $null) $shaC $null $true $false 'Delete one obsolete element while preserving its tombstone.'),
    (New-Event '11111111-1111-4111-8111-111111111114' 'rename' 'rename' (New-Coordinate 'renamed' 'src/old_name.rs' 'src/new_name.rs') $shaD $shaE $false $false 'Rename one element without changing stable semantic identity.'),
    (New-Event '11111111-1111-4111-8111-111111111115' 'generated' 'generated_refresh' (New-Coordinate 'generated_refresh' $null 'evidence/manifest.json') $shaF $shaA $false $true 'Refresh one enumerated mechanical derivative from its governed source.')
)

$edges = @($suffixes | ForEach-Object {
    [ordered]@{
        edge_id = "edge:$($_)-modifies-element"
        kind = 'modifies'
        source_node_id = "event:$_"
        target_node_id = "element:$_"
    }
})

$changeSet = [ordered]@{
    profile = 'cantor-sjs-repository-change-set/0.1'
    change_set_uuid = '44444444-4444-4444-8444-444444444444'
    repository_id = 'cattailfarmer/cantor'
    branch_ref = 'refs/heads/codex/self-hosted-corpus'
    predecessor_commit = '2e802dc9f10b9902543d670ab6a183c70e04a24e'
    resulting_commit = $null
    publication_state = 'candidate'
    turn_uuid = '22222222-2222-4222-8222-222222222222'
    conversation_uuid = '33333333-3333-4333-8333-333333333333'
    inventory_sha256 = $inventory.inventory_sha256
    nodes = @($nodes)
    edges = $edges
    events = $events
    foreign_exclusions = @(
        [ordered]@{ path = 'AGENTS.md'; reason = 'Pre-existing tracked boot-authority edit remains foreign to the fixture.' },
        [ordered]@{ path = 'narrative/turns/foreign.sop'; reason = 'Representative foreign narrative remains excluded.' }
    )
    authority = 'verification_only'
    physical_contact = $false
    change_set_sha256 = ''
}
$changeSet.change_set_sha256 = Get-DomainDigest 'cantor:sjs-repository-graph:change-set:0.1' $changeSet

if (-not $VerifyOnly) {
    [IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
    Write-Json $inventoryPath $inventory
    Write-Json $changeSetPath $changeSet
} else {
    Assert-JsonEqual $inventoryPath $inventory 'diff inventory fixture'
    Assert-JsonEqual $changeSetPath $changeSet 'change set fixture'
}

$receiptText = (& $Cargo run --quiet --offline --locked -p cantor_ecosystem --bin cantor-sjs-graph-verify -- --change-set $changeSetPath --diff-inventory $inventoryPath 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw "Rust graph verifier failed: $receiptText" }
$receipt = $receiptText | ConvertFrom-Json
if ($receipt.diff_entry_count -ne 5 -or $receipt.element_event_count -ne 5 -or -not $receipt.complete_coverage -or $receipt.physical_contact) {
    throw 'verification receipt semantic account differs'
}
if ($VerifyOnly) {
    Assert-JsonEqual $receiptPath $receipt 'verification receipt fixture'
} else {
    Write-Json $receiptPath $receipt
}

$artifactPaths = @(
    'source_documents/2026-08-24_cantor_sjs_repository_graph_p0/Cantor_SJS_Repository_Graph_P0_Dictated_Source.sop',
    'specifications/Cantor_SJS_Repository_Graph_P0_Revision_0_2.sop',
    'narrative/registries/Cantor_SJS_Repository_Graph_P0_Revision_0_2_Satisfaction_Signature.sop',
    'crates/cantor_ecosystem/src/sjs_repository_graph.rs',
    'crates/cantor_ecosystem/src/lib.rs',
    'crates/cantor_ecosystem/src/bin/cantor-sjs-graph-verify.rs',
    'crates/cantor_ecosystem/tests/sjs_repository_graph_static.rs',
    'fixtures/sjs_repository_graph_p0/diff_inventory.json',
    'fixtures/sjs_repository_graph_p0/change_set.json',
    'fixtures/sjs_repository_graph_p0/verification_receipt.json',
    'scripts/build_sjs_repository_graph_p0_evidence_manifest.ps1',
    'scripts/test_sjs_repository_graph_p0.ps1'
)
$artifacts = @($artifactPaths | ForEach-Object {
    $item = Get-Item -LiteralPath (Join-Path $root $_)
    [ordered]@{
        path = $_
        bytes = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    }
})
$manifest = [ordered]@{
    profile = 'cantor-sjs-repository-graph-evidence/0.1'
    evidence_uuid = '3996fb25-bb92-4246-9bab-41a6761562bf'
    canonical_uuid = 'ca7e0a5f-086f-4987-b968-c512defbfef9'
    signature_uuid = '9966dc83-6281-4ced-8d5b-9c4612fde58d'
    change_set_profile = 'cantor-sjs-repository-change-set/0.1'
    diff_inventory_profile = 'cantor-sjs-diff-inventory/0.1'
    physical_contact = $false
    authority = 'verification_only'
    diff_entry_count = 5
    graph_node_count = 24
    graph_edge_count = 5
    element_event_count = 5
    covered_change_count = 5
    complete_coverage = $true
    cargo_delta = $false
    effect_delta = $false
    artifacts = $artifacts
}

if ($VerifyOnly) {
    Assert-JsonEqual $evidencePath $manifest 'evidence manifest'
    Write-Output "sjs_repository_graph_p0_evidence_verified=true artifacts=$($artifacts.Count)"
    exit 0
}
Write-Json $evidencePath $manifest
Write-Output "sjs_repository_graph_p0_evidence_written=$evidencePath artifacts=$($artifacts.Count)"
