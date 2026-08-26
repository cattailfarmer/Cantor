[CmdletBinding()]
param(
    [string]$OutputPath = 'crates/cantor_ecosystem/tests/fixtures/succeeding_sop_activation_transaction_receipt.json',
    [string]$Distro = 'Ubuntu-24.04'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fullOutput = if ([IO.Path]::IsPathRooted($OutputPath)) {
    [IO.Path]::GetFullPath($OutputPath)
} else {
    [IO.Path]::GetFullPath((Join-Path $root $OutputPath))
}

$generator = @'
set -euo pipefail
export CARGO_TARGET_DIR=/tmp/cantor-sfp-p0-fixture-target
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 LC_ALL=C
"$HOME/.cargo/bin/cargo" run -q -p cantor_core --example succeeding_sop_activation_fixture --locked --offline
'@
$transport = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($generator))
$lines = @(& wsl.exe -d $Distro --cd $root -- bash -lc "set -o pipefail; printf '%s' '$transport' | base64 --decode | bash")
if ($LASTEXITCODE -ne 0) { throw 'synthetic activation fixture generation failed' }
$machineForm = $lines -join "`n"
$fixture = $machineForm | ConvertFrom-Json
if ($fixture.profile -cne 'cantor-succeeding-sop-activation-transaction-receipt/0.1' -or
    $fixture.policy_use_status -cne 'synthetic_fixture_only' -or
    $fixture.status -cne 'transaction_correspondence_verified_awaiting_physical_execution' -or
    [bool]$fixture.physical_contact -or
    [bool]$fixture.physical_execution_eligible) {
    throw 'synthetic activation fixture boundary differs'
}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($fullOutput)) | Out-Null
[IO.File]::WriteAllText($fullOutput, "$machineForm`n", [Text.UTF8Encoding]::new($false))
$item = Get-Item -LiteralPath $fullOutput
$sha = (Get-FileHash -LiteralPath $fullOutput -Algorithm SHA256).Hash
Write-Output "succeeding_sop_activation_fixture_built bytes=$($item.Length) sha256=$sha"
