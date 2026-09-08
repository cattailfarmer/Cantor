param([string]$RepositoryRoot = "")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
}
$verifier = Join-Path $PSScriptRoot "verify_cantor_b1_production_broker_projection_correspondence_p0_completion.ps1"

& $verifier -RepositoryRoot $RepositoryRoot
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$refusals = 0
foreach ($case in @(
    @{ ImplementationCommit = "539f00e23384624a317c8ab06fc2225c2a52246d"; BookendCommit = "1aef4152568f9ad6b0abe59738ef20f213b0a574" },
    @{ ImplementationCommit = "7760c78329f165a0ff7d02ec2aabc85dafbb3726"; BookendCommit = "7760c78329f165a0ff7d02ec2aabc85dafbb3726" }
)) {
    try {
        & $verifier -RepositoryRoot $RepositoryRoot -ImplementationCommit $case.ImplementationCommit -BookendCommit $case.BookendCommit | Out-Null
    }
    catch {
        $refusals++
    }
}
if ($refusals -ne 2) { throw "A8 completion refusal count differs" }
Write-Output "cantor_b1_a8_completion_tests=passed successes=1 refusals=$refusals"
