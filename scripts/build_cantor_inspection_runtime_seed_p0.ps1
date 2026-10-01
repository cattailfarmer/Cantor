#requires -Version 7.6
param([Parameter(Mandatory)][string]$OutputLeaf)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'lib/Cantor_Inspection_Runtime_Seed_P0_Common.ps1')
Assert-SeedSource
$leaf=Assert-SeedLeaf $OutputLeaf -Create
$prior=@{};foreach($key in @('CARGO_TARGET_DIR','CARGO_BUILD_TARGET','CARGO_BUILD_JOBS','CARGO_INCREMENTAL','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER')) {$prior[$key]=[Environment]::GetEnvironmentVariable($key,'Process')}
Push-Location $script:SeedRoot
try {
    $env:CARGO_TARGET_DIR='D:\CantorBuilds\target';$env:CARGO_BUILD_JOBS='1';$env:CARGO_INCREMENTAL='0';$env:RUSTFLAGS=$script:SeedRustFlags
    $env:CARGO_BUILD_TARGET=$null;$env:CARGO_ENCODED_RUSTFLAGS=$null;$env:RUSTC_WRAPPER=$null;$env:RUSTC_WORKSPACE_WRAPPER=$null
    $compiler=@(& rustc -Vv)
    if($LASTEXITCODE -ne 0 -or 'host: x86_64-pc-windows-msvc' -cnotin $compiler -or 'release: 1.96.0' -cnotin $compiler){throw 'seed_toolchain_identity'}
    & cargo build --release --locked --offline --jobs 1 -p cantor_sop_inspect_wire --bin cantor-sop-inspect-stdio -p cantor_sop_inspect_mcp --bin cantor-sop-inspect-mcp
    if ($LASTEXITCODE -ne 0) { throw 'seed_recipe_failed' }
} finally {
    foreach($key in $prior.Keys){
        if($null -eq $prior[$key]){Remove-Item -LiteralPath ('Env:'+ $key) -ErrorAction SilentlyContinue}
        else {Set-Item -LiteralPath ('Env:'+ $key) -Value $prior[$key]}
    }
    Pop-Location
}
$payloads=Get-SeedPayloads
$total=22
foreach($name in $script:SeedNames) {
    $count=$payloads[$name].Length
    if ($count -gt 8388608) { throw 'seed_entry_bound' }
    $total += $count + 76 + 2*$script:SeedUtf8.GetByteCount($name)
}
if ($total -gt 16777216) { throw 'seed_archive_bound' }
$archivePath=Join-Path $leaf 'cantor-inspection-runtime-seed-windows-x86_64-p0.zip'
$stream=[IO.File]::Open($archivePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$true,$script:SeedUtf8)
    try {
        foreach($name in $script:SeedNames) {
            $entry=$zip.CreateEntry($name,[IO.Compression.CompressionLevel]::NoCompression)
            $entry.LastWriteTime=[DateTimeOffset]::new(1980,1,1,0,0,0,[TimeSpan]::Zero)
            $entry.ExternalAttributes=0
            $entryStream=$entry.Open();try {$entryStream.Write([byte[]]$payloads[$name])} finally {$entryStream.Dispose()}
        }
    } finally {$zip.Dispose()}
    $stream.Flush($true)
} finally {$stream.Dispose()}
$archive=Read-SeedBounded $archivePath 16777216
$report=Get-SeedReport $payloads $archive
$reportBytes=$script:SeedUtf8.GetBytes((ConvertTo-SeedCanonical $report)+"`n")
if ($reportBytes.Length -gt 131072) {throw 'seed_report_bound'}
Write-SeedNew (Join-Path $leaf 'seed-report.json') $reportBytes
& (Join-Path $PSScriptRoot 'verify_cantor_inspection_runtime_seed_p0.ps1') -PackageLeaf $leaf
Write-Output ('cantor_inspection_seed_built='+$leaf)
