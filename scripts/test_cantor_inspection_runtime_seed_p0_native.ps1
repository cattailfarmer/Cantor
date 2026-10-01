#requires -Version 7.6
param([Parameter(Mandatory)][string]$PackageLeaf,[Parameter(Mandatory)][string]$ReplayLeaf)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'lib/Cantor_Inspection_Runtime_Seed_P0_Common.ps1')
& (Join-Path $PSScriptRoot 'verify_cantor_inspection_runtime_seed_p0.ps1') -PackageLeaf $PackageLeaf
$leaf=Assert-SeedLeaf $ReplayLeaf -Create
$payloads=Get-SeedPayloads;$templates=Get-SeedTemplates
$script:ReplayProcessCount=0;$script:ReplayFailureKills=0
function Get-Remaining($State) {
    $remaining=30000-[int]$State.clock.ElapsedMilliseconds
    if($remaining -le 0){throw 'seed_native_deadline'}
    return $remaining
}
function Read-ReplayChunk($State) {
    $buffer=[byte[]]::new(4096)
    $task=$State.process.StandardOutput.BaseStream.ReadAsync($buffer,0,$buffer.Length)
    if(-not $task.Wait((Get-Remaining $State))){throw 'seed_native_read_deadline'}
    $count=$task.Result
    $State.total+=$count
    if($State.total -gt 1048576){throw 'seed_native_stdout_bound'}
    if($count -gt 0){$State.pending.AddRange([byte[]]$buffer[0..($count-1)])}
    return $count
}
function Receive-ReplayLine($State) {
    while($true) {
        $index=$State.pending.IndexOf([byte]10)
        if($index -ge 0) {
            $bytes=$State.pending.GetRange(0,$index).ToArray();$State.pending.RemoveRange(0,$index+1)
            $line=$script:SeedUtf8.GetString($bytes)
            $State.lines.Add($line)
            return ($line|ConvertFrom-Json -AsHashtable -Depth 100)
        }
        if((Read-ReplayChunk $State) -eq 0){throw 'seed_native_premature_eof'}
    }
}
function Send-ReplayBytes($State,[byte[]]$Bytes) {
    $task=$State.process.StandardInput.BaseStream.WriteAsync($Bytes,0,$Bytes.Length)
    if(-not $task.Wait((Get-Remaining $State))){throw 'seed_native_write_deadline'}
    $flush=$State.process.StandardInput.BaseStream.FlushAsync()
    if(-not $flush.Wait((Get-Remaining $State))){throw 'seed_native_flush_deadline'}
}
function Send-ReplayJson($State,$Message) {Send-ReplayBytes $State $script:SeedUtf8.GetBytes((ConvertTo-SeedCanonical $Message)+"`n")}
function Start-Replay([string]$Name) {
    $copy=Join-Path $leaf $Name
    Write-SeedNew $copy $payloads['bin/'+$Name]
    $start=[Diagnostics.ProcessStartInfo]::new()
    $start.FileName=$copy;$start.WorkingDirectory=$leaf;$start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    if(-not $process.Start()){throw 'seed_native_start'}
    $script:ReplayProcessCount++
    $stderrBuffer=[byte[]]::new(4096)
    return @{process=$process;clock=[Diagnostics.Stopwatch]::StartNew();pending=[Collections.Generic.List[byte]]::new();lines=[Collections.Generic.List[string]]::new();total=0;stderrBuffer=$stderrBuffer;stderrTask=$process.StandardError.BaseStream.ReadAsync($stderrBuffer,0,$stderrBuffer.Length)}
}
function Stop-Replay($State,[bool]$Succeeded) {
    $process=$State.process
    try {
        if(-not $Succeeded) {
            if(-not $process.HasExited){$process.Kill($true);$script:ReplayFailureKills++}
            if(-not $process.WaitForExit(1000)){throw 'seed_native_reap_failed'}
        }
    } finally {
        $process.StandardInput.Dispose();$process.StandardOutput.Dispose();$process.StandardError.Dispose();$process.Dispose()
    }
}
function Finish-Replay($State) {
    $State.process.StandardInput.Close()
    while((Read-ReplayChunk $State) -gt 0) {}
    if(-not $State.process.WaitForExit((Get-Remaining $State))){throw 'seed_native_exit_deadline'}
    if($State.process.ExitCode -ne 0){throw 'seed_native_exit'}
    if(-not $State.stderrTask.Wait((Get-Remaining $State)) -or $State.stderrTask.Result -ne 0){throw 'seed_native_stderr'}
}
$stdio=Start-Replay 'cantor-sop-inspect-stdio.exe';$ok=$false
try {
    Send-ReplayBytes $stdio $templates.wire
    Finish-Replay $stdio
    $wireBytes=$stdio.pending.ToArray();$wireString=$script:SeedUtf8.GetString($wireBytes)
    $wire=$wireString|ConvertFrom-Json -AsHashtable -Depth 100
    if($wire.status -cne 'succeeded' -or $wire.request_digest -cne $templates.request_digest -or $wire.result.find.items.Count -ne 5 -or $wire.result.excerpts.Count -ne 5 -or -not $wire.result.find.complete -or $null -ne $wire.result.find.next){throw 'seed_native_semantics'}
    $expectedIds=@('seed:frontier','seed:mcp','seed:runtime','seed:stdio','seed:trust')
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($excerpt in $wire.result.excerpts) {
        if($excerpt.record_id -cnotin $expectedIds -or -not $seen.Add($excerpt.record_id) -or $excerpt.path -cne 'seed/seed.sop' -or $excerpt.span.source -cne 'source:seed' -or $excerpt.span.start -lt 0 -or $excerpt.span.end -le $excerpt.span.start -or $excerpt.span.end -gt $templates.seed.Length){throw 'seed_native_excerpt_span'}
        $span=[byte[]]::new($excerpt.span.end-$excerpt.span.start)
        [Array]::Copy($templates.seed,$excerpt.span.start,$span,0,$span.Length)
        if($script:SeedUtf8.GetString($span) -cne $excerpt.text -or $excerpt.text -cnotmatch '^term \[seed:'){throw 'seed_native_excerpt'}
    }
    $ok=$true
} finally {Stop-Replay $stdio $ok}
$mcp=Start-Replay 'cantor-sop-inspect-mcp.exe';$ok=$false
try {
    Send-ReplayJson $mcp @{jsonrpc='2.0';id=1;method='initialize';params=@{protocolVersion='2025-11-25';capabilities=@{};clientInfo=@{name='cantor-seed-native-replay';version='0.1'}}}
    $initialized=Receive-ReplayLine $mcp
    if($initialized.id -ne 1 -or $initialized.result.protocolVersion -cne '2025-11-25'){throw 'seed_native_initialize'}
    Send-ReplayJson $mcp @{jsonrpc='2.0';method='notifications/initialized'}
    Send-ReplayJson $mcp @{jsonrpc='2.0';id=2;method='tools/list';params=@{}}
    $listed=Receive-ReplayLine $mcp
    if($listed.id -ne 2 -or $listed.result.tools.Count -ne 1 -or $listed.result.tools[0].name -cne 'inspect_sop_semantics'){throw 'seed_native_tools'}
    $tool=$listed.result.tools[0]
    if($tool.inputSchema.additionalProperties -or $tool.inputSchema.required.Count -ne 1 -or $tool.inputSchema.required[0] -cne 'wire_request_json' -or $tool.inputSchema.properties.wire_request_json.type -cne 'string' -or -not $tool.annotations.readOnlyHint -or $tool.annotations.destructiveHint -or -not $tool.annotations.idempotentHint -or $tool.annotations.openWorldHint){throw 'seed_native_tool_contract'}
    $arguments=$script:SeedUtf8.GetString($templates.arguments)|ConvertFrom-Json -AsHashtable
    foreach($id in @(3,6)) {
        Send-ReplayJson $mcp @{jsonrpc='2.0';id=$id;method='tools/call';params=@{name='inspect_sop_semantics';arguments=$arguments}}
        $reply=Receive-ReplayLine $mcp
        $structured=$reply.result.structuredContent
        if($reply.id -ne $id -or $reply.result.isError -or $structured.profile -cne 'cantor-sop-inspection-mcp-reply/0.1' -or $structured.outcome -cne 'inspection_succeeded' -or $structured.wire_response_json -cne $wireString -or $structured.response_sha256 -cne (Get-SeedSha $wireBytes).ToLowerInvariant() -or $structured.non_authority -cnotmatch 'No pathname acquisition'){throw 'seed_native_exact_wire'}
        if($structured.request_bytes -ne $script:SeedUtf8.GetByteCount($templates.wire_string) -or $structured.request_sha256 -cne (Get-SeedSha $script:SeedUtf8.GetBytes($templates.wire_string)).ToLowerInvariant() -or $structured.response_bytes -ne $wireBytes.Length){throw 'seed_native_wire_identities'}
        if($id -eq 3) {
            Send-ReplayJson $mcp @{jsonrpc='2.0';id=4;method='tools/call';params=@{name='unknown_seed_tool';arguments=@{}}}
            $unknown=Receive-ReplayLine $mcp
            if($unknown.id -ne 4 -or $unknown.error.code -ne -32601){throw 'seed_native_unknown_tool'}
            Send-ReplayJson $mcp @{jsonrpc='2.0';id=5;method='tools/call';params=@{name='inspect_sop_semantics';arguments=@{wire_request_json=17;future='seed-private-token'}}}
            $malformed=Receive-ReplayLine $mcp
            if($malformed.id -ne 5 -or -not $malformed.result.isError -or $malformed.result.structuredContent.fault_code -cne 'arguments' -or $malformed.result.structuredContent.wire_response_json -ne $null -or (ConvertTo-SeedCanonical $malformed).Contains('seed-private-token')){throw 'seed_native_argument_refusal'}
        }
    }
    Finish-Replay $mcp
    if($mcp.pending.Count -ne 0){throw 'seed_native_extra_stdout'}
    $ok=$true
    $report=[ordered]@{
        profile='cantor-inspection-runtime-seed-native-replay/0.1';package_archive_sha256=(Get-SeedSha (Read-SeedBounded (Join-Path $PackageLeaf 'cantor-inspection-runtime-seed-windows-x86_64-p0.zip') 16777216))
        native_process_trials=$script:ReplayProcessCount;successful_children_killed=0;failure_kills=$script:ReplayFailureKills;whole_exchange_deadline_ms=30000
        stdio_exit=0;mcp_exit=0;stderr_bytes=0;seed_terms=5;complete_source_excerpts=5;mcp_initialized_sessions=1
        mcp_calls=4;mcp_exact_wire_responses=2;unknown_tool_refusals=1;malformed_argument_refusals=1;after_refusal_recoveries=1
        wire_response_bytes=$wireBytes.Length;wire_response_sha256=(Get-SeedSha $wireBytes);wire_response_json=$wireString;mcp_frames=$mcp.lines.ToArray();unique_seed_excerpt_ids=$seen.Count;exact_utf8_source_span_checks=5
        provider_trials=0;remote_calls=0;installed_application_acceptances=0;non_authority=$script:SeedDenials
    }
    Write-SeedNew (Join-Path $leaf 'native-replay-report.json') $script:SeedUtf8.GetBytes((ConvertTo-SeedCanonical $report)+"`n")
    Write-Output ('cantor_seed_native_replay_passed=true processes=2 terms=5 excerpts=5 exact_mcp_replies=2 protocol_refusals=1 adapter_refusals=1 recovery=1 report='+$leaf)
} finally {Stop-Replay $mcp $ok}
