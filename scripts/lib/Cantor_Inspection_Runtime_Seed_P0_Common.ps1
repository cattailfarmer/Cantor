# Shared source descriptions and bounded primitives; never launches a packaged runtime.
#requires -Version 7.6
Set-StrictMode -Version Latest
$script:SeedRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$script:SeedUtf8 = [Text.UTF8Encoding]::new($false, $true)
$script:SeedSourceCommit = '2974d2782898aa0c0c39ba36ebcce079d428af74'
$script:SeedFormationCommit = '176af3579c18b3983e59c3770b9656c4cafbf06c'
$script:SeedRustFlags = '-C overflow-checks=on -C link-arg=/Brepro'
$script:SeedLinkSpec = '9b6b789d-f0b4-478b-a1d5-af979e6ee42b'
$script:SeedLinkSignature = '5ef0374a-67b5-4972-87de-7508c9f1bb08'
$script:SeedLinkBookend = '5130e4eb12765d73b2c982c71afc72e839280773'
$script:SeedNames = @('GUIDE.md','bin/cantor-sop-inspect-mcp.exe','bin/cantor-sop-inspect-stdio.exe','examples/inspect-seed-request.json','examples/mcp-tool-arguments.json','seed-manifest.json','sop/seed.sop')
$script:SeedDenials = 'Inspection only. No installation, model, provider, service, persistent custody, remote host, autonomous agent, update, publication authority or publisher authenticity.'
function ConvertTo-SeedCanonical($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [ValueType]) { return ConvertTo-Json -InputObject $Value -Compress -Depth 100 }
    if ($Value -is [System.Collections.IDictionary]) {
        [string[]]$keys = @($Value.Keys); [Array]::Sort($keys,[StringComparer]::Ordinal)
        return '{' + (($keys | ForEach-Object { (ConvertTo-Json -InputObject $_ -Compress)+':'+(ConvertTo-SeedCanonical $Value[$_]) }) -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) { return '[' + ((@($Value) | ForEach-Object { ConvertTo-SeedCanonical $_ }) -join ',') + ']' }
    $object = [ordered]@{}; foreach ($property in $Value.PSObject.Properties) { $object[$property.Name]=$property.Value }
    return ConvertTo-SeedCanonical $object
}
function Get-SeedSha([byte[]]$Bytes) { return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)) }
function Test-SeedBytes([byte[]]$Left,[byte[]]$Right) {
    if ($Left.Length -ne $Right.Length) { return $false }
    return [Linq.Enumerable]::SequenceEqual[byte]($Left,$Right)
}
function Read-SeedBounded([string]$Path,[int]$Maximum) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $length=$stream.Length
        if ($length -le 0 -or $length -gt $Maximum) { throw 'seed_file_bound' }
        $bytes=[byte[]]::new([int]$length); $stream.ReadExactly($bytes)
        if ($stream.ReadByte() -ne -1) { throw 'seed_file_changed' }
        return ,$bytes
    } finally { $stream.Dispose() }
}
function Write-SeedNew([string]$Path,[byte[]]$Bytes) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes); $stream.Flush($true) } finally { $stream.Dispose() }
}
function Assert-SeedLeaf([string]$Leaf,[switch]$Create) {
    $base='D:\CantorBuilds\cantor-inspection-seed'
    $full=[IO.Path]::GetFullPath($Leaf)
    if (-not $full.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetDirectoryName($full) -cne $base -or [IO.Path]::GetFileName($full) -cnotmatch '^seed-[0-9a-f]{32}$') { throw 'seed_output_scope' }
    foreach ($parent in @('D:\','D:\CantorBuilds',$base)) {
        if (Test-Path -LiteralPath $parent) {
            $item=Get-Item -LiteralPath $parent
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'seed_reparse_parent' }
        } elseif ($parent -ceq $base -and $Create) { [IO.Directory]::CreateDirectory($base) | Out-Null } else { throw 'seed_parent_missing' }
    }
    if ($Create) {
        if (Test-Path -LiteralPath $full) { throw 'seed_output_exists' }
        New-Item -ItemType Directory -Path $full -ErrorAction Stop | Out-Null
    } else {
        $item=Get-Item -LiteralPath $full
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'seed_leaf_invalid' }
    }
    return $full
}
function Assert-SeedSource {
    & (Join-Path $script:SeedRoot 'scripts/verify_cantor_inspection_seed_link_refinement_formation.ps1') | Out-Null
    & (Join-Path $script:SeedRoot 'scripts/verify_cantor_inspection_runtime_seed_p0_formation.ps1') | Out-Null
    & (Join-Path $script:SeedRoot 'scripts/verify_cantor_semantic_inspection_mcp_adapter_p0_evidence.ps1') | Out-Null
    foreach ($commit in @($script:SeedSourceCommit,$script:SeedFormationCommit)) {
        & git -C $script:SeedRoot merge-base --is-ancestor $commit HEAD
        if ($LASTEXITCODE -ne 0) { throw 'seed_source_ancestry' }
    }
}
function Get-SeedTemplates {
    $seed=@'
kind [kind:capability] "Capability" { meaning "A described capability is not effect authority" }
context [context:seed] { scopes ("inspection") purposes ("handoff") perspectives ("operator") }
term [seed:runtime] "Seed runtime" { kind [kind:capability] context [context:seed] meaning "Two ephemeral Windows inspection endpoints, not an installed agent" }
term [seed:stdio] "Seed stdio" { kind [kind:capability] context [context:seed] meaning "One sealed supplied-value request followed by observed EOF" }
term [seed:mcp] "Seed MCP" { kind [kind:capability] context [context:seed] meaning "Initialized sequential semantic_inspect calls on inherited stdio" }
term [seed:trust] "Seed trust" { kind [kind:capability] context [context:seed] meaning "Byte identity is not publisher authenticity or effect authorization" }
term [seed:frontier] "Seed frontier" { kind [kind:capability] context [context:seed] meaning "Installation models remote hosts autonomous work and updates remain unproved" }
'@
    $seed=$seed.Replace("`r`n","`n").TrimEnd()+"`n"
    $request=[ordered]@{
        profile='cantor-sop-semantic-inspection-request/0.1'
        project=[ordered]@{profile='cantor-sop-supplied-project/0.1';packages=@([ordered]@{
            id='pkg:seed';version='0.1.0';namespaces=@('seed');dependencies=@()
            files=@([ordered]@{id='source:seed';path='seed/seed.sop';namespace='seed';text=$seed})
        })}
        find=[ordered]@{
            profile='cantor-sop-semantic-find-request/0.1';text='Seed';mode='prefix';namespace=$null;visible_from=$null;kinds=@()
            context=[ordered]@{scope=$null;purpose=$null;perspective=$null;at_epoch_seconds=$null}
            include_superseded=$false;limit=16;cursor=$null
        }
        projection='page_hits_with_exact_source';request_digest=''
    }
    $request.request_digest=(Get-SeedSha $script:SeedUtf8.GetBytes('cantor-sop-semantic-inspection-request/0.1'+[char]0+(ConvertTo-SeedCanonical $request))).ToLowerInvariant()
    $wire=ConvertTo-SeedCanonical ([ordered]@{profile='cantor-sop-inspection-wire-request/0.1';operation='semantic_inspect';request=$request})
    $arguments=ConvertTo-SeedCanonical ([ordered]@{wire_request_json=$wire})
    $guide=@'
# Cantor Windows inspection seed P0

This is an inspection-only seed, not the full Cantor agent or an installer.
It contains two Windows x86-64 MSVC executables and one descriptive SOP fixture.
A compatible Windows runtime and the applicable MSVC/UCRT libraries are prerequisites;
this local machine's successful replay does not prove distribution on other machines.

The SOP uses real kind/context/term grammar. Its five Seed terms describe the
inspection boundary; they do not grant permission to execute installation or agent jobs.

The stdio executable accepts exactly the raw bytes in examples/inspect-seed-request.json
followed by EOF and returns one wire JSON value without a newline.
A caller must own the process, bounded captures, deadline and exit status.
The MCP executable uses inherited stdin/stdout, must be initialized before tools/call,
and exposes inspect_sop_semantics with the one-string example in examples/mcp-tool-arguments.json.
Clients await each response before sending the next call and close stdin on completion.
Never append logging to protocol stdout. No listener, service or model is started.

Rebuild and verify from the governed repository using the mandatory locked offline
serialized overflow-checked release recipe in the companion report. Archive verification
does not extract files or launch executables. Only the explicit developer replay harness
creates two fresh native fixture copies and starts them, with bounded capture and cleanup.
Byte hashes bind this local build, not publisher authenticity or cross-toolchain reproducibility.
Installation, autonomous SOP work, models, EVO-X2 and updates remain separate governed frontiers.
'@
    $guide=$guide.Replace("`r`n","`n").TrimEnd()+"`n"
    return @{seed=$script:SeedUtf8.GetBytes($seed);wire=$script:SeedUtf8.GetBytes($wire+"`n");arguments=$script:SeedUtf8.GetBytes($arguments+"`n");guide=$script:SeedUtf8.GetBytes($guide);wire_string=$wire;request_digest=$request.request_digest}
}
function Get-SeedCrc([byte[]]$Bytes) {
    if ($null -eq (Get-Variable -Scope Script -Name SeedCrcTable -ErrorAction SilentlyContinue)) {
        $script:SeedCrcTable=[uint32[]]::new(256)
        for ($index=0;$index -lt 256;$index++) {
            [uint32]$word=$index
            for ($bit=0;$bit -lt 8;$bit++) { if ($word -band 1) {$word=($word -shr 1) -bxor [uint32]3988292384} else {$word=$word -shr 1} }
            $script:SeedCrcTable[$index]=$word
        }
    }
    [uint32]$crc=4294967295
    foreach ($octet in $Bytes) { $crc=($crc -shr 8) -bxor $script:SeedCrcTable[($crc -bxor $octet) -band 255] }
    return [uint32]($crc -bxor [uint32]4294967295)
}
function Assert-SeedPe([byte[]]$Bytes) {
    if ($Bytes.Length -lt 256 -or $Bytes[0] -ne 77 -or $Bytes[1] -ne 90) { throw 'seed_pe_header' }
    $offset=[BitConverter]::ToUInt32($Bytes,60)
    if ($offset -gt $Bytes.Length-24 -or [BitConverter]::ToUInt32($Bytes,[int]$offset) -ne 17744 -or [BitConverter]::ToUInt16($Bytes,[int]$offset+4) -ne 34404) { throw 'seed_pe_amd64' }
}
function Get-SeedPayloads {
    $templates=Get-SeedTemplates
    foreach ($pair in @(@('seed.sop','seed',8192),@('inspect-seed-request.json','wire',65536),@('mcp-tool-arguments.json','arguments',131072))) {
        $actual=Read-SeedBounded (Join-Path $script:SeedRoot ('fixtures/inspection_runtime_seed_p0/'+$pair[0])) $pair[2]
        if (-not (Test-SeedBytes $actual $templates[$pair[1]])) { throw 'seed_fixture_drift' }
    }
    $payloads=[ordered]@{
        'GUIDE.md'=$templates.guide
        'bin/cantor-sop-inspect-mcp.exe'=(Read-SeedBounded 'D:\CantorBuilds\target\release\cantor-sop-inspect-mcp.exe' 8388608)
        'bin/cantor-sop-inspect-stdio.exe'=(Read-SeedBounded 'D:\CantorBuilds\target\release\cantor-sop-inspect-stdio.exe' 8388608)
        'examples/inspect-seed-request.json'=$templates.wire
        'examples/mcp-tool-arguments.json'=$templates.arguments
        'sop/seed.sop'=$templates.seed
    }
    Assert-SeedPe $payloads['bin/cantor-sop-inspect-mcp.exe']
    Assert-SeedPe $payloads['bin/cantor-sop-inspect-stdio.exe']
    $inputIdentities=@(); foreach ($name in $payloads.Keys) {$inputIdentities+= [ordered]@{path=$name;bytes=$payloads[$name].Length;sha256=(Get-SeedSha $payloads[$name])}}
    $manifest=[ordered]@{
        profile='cantor-inspection-runtime-seed-manifest/0.1';specification_uuid='e3e7a424-c013-492a-a913-044ea17dc66d'
        source_commit=$script:SeedSourceCommit;formation_commit=$script:SeedFormationCommit;target='x86_64-pc-windows-msvc'
        link_refinement_specification_uuid=$script:SeedLinkSpec;link_refinement_signature_uuid=$script:SeedLinkSignature;link_refinement_formation_bookend=$script:SeedLinkBookend
        cargo_lock_sha256=(Get-SeedSha (Read-SeedBounded (Join-Path $script:SeedRoot 'Cargo.lock') 131072))
        entry_count=7;non_authority=$script:SeedDenials;inputs=$inputIdentities
    }
    $payloads['seed-manifest.json']=$script:SeedUtf8.GetBytes((ConvertTo-SeedCanonical $manifest)+"`n")
    return $payloads
}
function Get-SeedReport($Payloads,[byte[]]$Archive) {
    $entries=@();foreach($name in $script:SeedNames) {$bytes=$Payloads[$name];$entries += [ordered]@{path=$name;bytes=$bytes.Length;sha256=(Get-SeedSha $bytes);crc32=(Get-SeedCrc $bytes)}}
    return [ordered]@{
        profile='cantor-inspection-runtime-seed-report/0.1';specification_uuid='e3e7a424-c013-492a-a913-044ea17dc66d'
        source_commit=$script:SeedSourceCommit;formation_commit=$script:SeedFormationCommit;target='x86_64-pc-windows-msvc'
        link_refinement_specification_uuid=$script:SeedLinkSpec;link_refinement_signature_uuid=$script:SeedLinkSignature;link_refinement_formation_bookend=$script:SeedLinkBookend
        cargo_lock_sha256=(Get-SeedSha (Read-SeedBounded (Join-Path $script:SeedRoot 'Cargo.lock') 131072))
        recipe='cargo build --release --locked --offline --jobs 1 -p cantor_sop_inspect_wire --bin cantor-sop-inspect-stdio -p cantor_sop_inspect_mcp --bin cantor-sop-inspect-mcp'
        rustflags=$script:SeedRustFlags;target_directory='D:/CantorBuilds/target';incremental=0
        archive_profile='ZIP_STORE_UTF8_DOS1980_EXACT7/0.1';archive_bytes=$Archive.Length;archive_sha256=(Get-SeedSha $Archive)
        entry_count=7;entries=$entries;non_authority=$script:SeedDenials
        runtime_launches=0;installer_effects=0;provider_trials=0;remote_calls=0
    }
}
