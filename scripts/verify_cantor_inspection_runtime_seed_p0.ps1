#requires -Version 7.6
param([Parameter(Mandatory)][string]$PackageLeaf)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'lib/Cantor_Inspection_Runtime_Seed_P0_Common.ps1')
Assert-SeedSource
$leaf=Assert-SeedLeaf $PackageLeaf
$archive=Read-SeedBounded (Join-Path $leaf 'cantor-inspection-runtime-seed-windows-x86_64-p0.zip') 16777216
$reportBytes=Read-SeedBounded (Join-Path $leaf 'seed-report.json') 131072
# Independent raw framing validation: no ZipArchive reader, extraction or builder invocation.
function Read-U16([int]$Offset) {if($Offset -lt 0 -or $Offset -gt $archive.Length-2){throw 'seed_zip_offset'};return [BitConverter]::ToUInt16($archive,$Offset)}
function Read-U32([int]$Offset) {if($Offset -lt 0 -or $Offset -gt $archive.Length-4){throw 'seed_zip_offset'};return [BitConverter]::ToUInt32($archive,$Offset)}
function Assert-U16([int]$Offset,[int]$Expected) {if ((Read-U16 $Offset) -ne $Expected) {throw 'seed_zip_header'}}
function Assert-U32([int]$Offset,[long]$Expected) {if ((Read-U32 $Offset) -ne $Expected) {throw 'seed_zip_header'}}
if ($archive.Length -lt 22) {throw 'seed_zip_end'}
$end=$archive.Length-22
Assert-U32 $end 101010256
foreach($offset in @(4,6,20)) {Assert-U16 ($end+$offset) 0}
Assert-U16 ($end+8) 7;Assert-U16 ($end+10) 7
[long]$centralSize=Read-U32 ($end+12);[long]$centralOffset=Read-U32 ($end+16)
if($centralOffset -le 0 -or $centralOffset -gt $end -or $centralSize -ne $end-$centralOffset) {throw 'seed_zip_directory'}
$expectedPayloads=Get-SeedPayloads
$local=0;[int]$central=$centralOffset
foreach($name in $script:SeedNames) {
    $nameBytes=$script:SeedUtf8.GetBytes($name);$size=$expectedPayloads[$name].Length
    if($size -gt 8388608 -or $local+30+$nameBytes.Length+$size -gt $centralOffset -or $central+46+$nameBytes.Length -gt $end) {throw 'seed_zip_entry_bound'}
    Assert-U32 $local 67324752
    Assert-U16 ($local+4) 20;Assert-U16 ($local+6) 2048;Assert-U16 ($local+8) 0
    Assert-U16 ($local+10) 0;Assert-U16 ($local+12) 33
    Assert-U32 ($local+18) $size;Assert-U32 ($local+22) $size
    Assert-U16 ($local+26) $nameBytes.Length;Assert-U16 ($local+28) 0
    $actualName=[byte[]]$archive[($local+30)..($local+29+$nameBytes.Length)]
    if (-not (Test-SeedBytes $actualName $nameBytes)) {throw 'seed_zip_name'}
    $start=$local+30+$nameBytes.Length
    $payload=[byte[]]::new($size);[Array]::Copy($archive,$start,$payload,0,$size)
    # Actual octets, not the CRC property from a ZIP header, determine integrity.
    $crc=Get-SeedCrc $payload
    Assert-U32 ($local+14) $crc
    if ((Get-SeedSha $payload) -cne (Get-SeedSha $expectedPayloads[$name]) -or -not (Test-SeedBytes $payload $expectedPayloads[$name])) {throw 'seed_zip_payload_identity'}
    Assert-U32 $central 33639248
    Assert-U16 ($central+4) 20;Assert-U16 ($central+6) 20;Assert-U16 ($central+8) 2048
    Assert-U16 ($central+10) 0;Assert-U16 ($central+12) 0;Assert-U16 ($central+14) 33
    Assert-U32 ($central+16) $crc;Assert-U32 ($central+20) $size;Assert-U32 ($central+24) $size
    Assert-U16 ($central+28) $nameBytes.Length
    foreach($offset in @(30,32,34,36)){Assert-U16 ($central+$offset) 0}
    Assert-U32 ($central+38) 0;Assert-U32 ($central+42) $local
    $centralName=[byte[]]$archive[($central+46)..($central+45+$nameBytes.Length)]
    if (-not (Test-SeedBytes $centralName $nameBytes)) {throw 'seed_zip_central_name'}
    $local=$start+$size;$central+=46+$nameBytes.Length
}
if($local -ne $centralOffset -or $central -ne $end) {throw 'seed_zip_contiguity'}
# Full source-derived canonical raw bytes enforce order, closed fields, types,
# duplicate refusal and absence of trailing JSON without parser normalization.
$expectedReport=Get-SeedReport $expectedPayloads $archive
$canonical=$script:SeedUtf8.GetBytes((ConvertTo-SeedCanonical $expectedReport)+"`n")
if(-not (Test-SeedBytes $reportBytes $canonical)){throw 'seed_report_identity'}
Write-Output ('cantor_inspection_seed_verified=true entries=7 archive_bytes='+$archive.Length+' archive_sha256='+(Get-SeedSha $archive)+' runtime_launches=0 extraction_effects=0')
