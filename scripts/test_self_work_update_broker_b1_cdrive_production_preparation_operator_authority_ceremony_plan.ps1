$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$planBinaryName = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-plan.exe"
$evidenceBinaryName = "cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-evidence-verify.exe"

function Add-BoundedProcessArguments(
  [Diagnostics.ProcessStartInfo]$StartInfo,
  [string[]]$Arguments
) {
  foreach ($argument in $Arguments) {
    if ($argument.Contains('"')) {
      throw "focused CLI argument contains a quote"
    }
    if ($null -ne $StartInfo.PSObject.Properties["ArgumentList"]) {
      $StartInfo.ArgumentList.Add($argument)
    } else {
      if ($StartInfo.Arguments.Length -gt 0) { $StartInfo.Arguments += " " }
      $StartInfo.Arguments += '"' + $argument + '"'
    }
  }
}

function Invoke-ExactCase(
  [string]$Executable,
  [string[]]$Arguments,
  [string]$Expected
) {
  $start = [Diagnostics.ProcessStartInfo]::new($Executable)
  Add-BoundedProcessArguments $start $Arguments
  $start.UseShellExecute = $false
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $start
  $null = $process.Start()
  $stdout = $process.StandardOutput.ReadToEnd()
  $stderr = $process.StandardError.ReadToEnd()
  $process.WaitForExit()
  if ($process.ExitCode -ne 0 -or $stderr.Length -ne 0 -or $stdout.TrimEnd("`r", "`n") -cne $Expected) {
    throw "focused CLI canonical replay failed: $Executable"
  }
}

function Invoke-ArgumentRefusal([string]$Executable) {
  $start = [Diagnostics.ProcessStartInfo]::new($Executable)
  $start.UseShellExecute = $false
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $start
  $null = $process.Start()
  $stdout = $process.StandardOutput.ReadToEnd()
  $stderr = $process.StandardError.ReadToEnd()
  $process.WaitForExit()
  if ($process.ExitCode -ne 2 -or $stdout.Length -ne 0 -or $stderr.Length -eq 0) {
    throw "focused CLI bounded-argument refusal failed: $Executable"
  }
}

Push-Location $repositoryRoot
try {
  cargo test -p cantor_ecosystem --test self_work_update_broker_b1_cdrive_production_preparation_operator_authority_ceremony_plan --locked --offline
  if ($LASTEXITCODE -ne 0) { throw "focused debug tests failed" }

  $env:CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS = "true"
  cargo test -p cantor_ecosystem --test self_work_update_broker_b1_cdrive_production_preparation_operator_authority_ceremony_plan --release --locked --offline
  if ($LASTEXITCODE -ne 0) { throw "focused release tests failed" }

  cargo build -p cantor_ecosystem --bin cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-plan --bin cantor-self-work-update-broker-b1-cdrive-production-preparation-operator-authority-ceremony-evidence-verify --locked --offline
  if ($LASTEXITCODE -ne 0) { throw "focused CLI build failed" }

  $evidence = Join-Path $repositoryRoot "experiments/self_work_update_broker_b1_cdrive_production_preparation_operator_authority_ceremony_plan_p0/implementation_provider_free_evidence"
  $planBinary = Join-Path $repositoryRoot "target/debug/$planBinaryName"
  $evidenceBinary = Join-Path $repositoryRoot "target/debug/$evidenceBinaryName"
  Invoke-ExactCase $planBinary @((Join-Path $evidence "request.json")) (Get-Content -LiteralPath (Join-Path $evidence "plan.json") -Raw)

  $expectedEvidence = @(& $evidenceBinary $evidence)
  if ($LASTEXITCODE -ne 0 -or $expectedEvidence.Count -ne 1) { throw "focused evidence verifier failed" }
  Invoke-ExactCase $evidenceBinary @($evidence) ([string]$expectedEvidence)
  Invoke-ArgumentRefusal $planBinary
  Invoke-ArgumentRefusal $evidenceBinary
  Write-Output "production_preparation_operator_authority_ceremony_plan_provider_free=passed"
} finally {
  Pop-Location
}
