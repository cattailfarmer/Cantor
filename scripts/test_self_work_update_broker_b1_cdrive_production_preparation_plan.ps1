$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path

function Add-BoundedProcessArgument(
  [Diagnostics.ProcessStartInfo]$StartInfo,
  [string]$Argument
) {
  if ($Argument.Contains('"')) {
    throw "focused CLI argument contains a quote"
  }
  if ($null -ne $StartInfo.PSObject.Properties["ArgumentList"]) {
    $StartInfo.ArgumentList.Add($Argument)
  } else {
    # Windows PowerShell 5.1 exposes ProcessStartInfo.Arguments but not ArgumentList.
    $StartInfo.Arguments = '"' + $Argument + '"'
  }
}

Push-Location $repositoryRoot
try {
  cargo test -p cantor_ecosystem --test self_work_update_broker_b1_cdrive_production_preparation_plan --locked --offline
  if ($LASTEXITCODE -ne 0) { throw "focused debug tests failed" }

  $env:CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS = "true"
  cargo test -p cantor_ecosystem --test self_work_update_broker_b1_cdrive_production_preparation_plan --release --locked --offline
  if ($LASTEXITCODE -ne 0) { throw "focused release tests failed" }

  cargo build -p cantor_ecosystem --bin cantor-self-work-update-broker-b1-cdrive-production-preparation-plan --bin cantor-self-work-update-broker-b1-cdrive-production-preparation-plan-evidence-verify --locked --offline
  if ($LASTEXITCODE -ne 0) { throw "focused CLI build failed" }

  $evidence = Join-Path $repositoryRoot "experiments/self_work_update_broker_b1_cdrive_production_preparation_plan_p0/implementation_provider_free_evidence"
  $cases = @(
    @{
      Executable = Join-Path $repositoryRoot "target/debug/cantor-self-work-update-broker-b1-cdrive-production-preparation-plan.exe"
      Argument = Join-Path $evidence "request.json"
      Expected = Get-Content -LiteralPath (Join-Path $evidence "plan.json") -Raw
    },
    @{
      Executable = Join-Path $repositoryRoot "target/debug/cantor-self-work-update-broker-b1-cdrive-production-preparation-plan-evidence-verify.exe"
      Argument = $evidence
      Expected = Get-Content -LiteralPath (Join-Path $evidence "verification.json") -Raw
    }
  )
  foreach ($case in $cases) {
    $start = [Diagnostics.ProcessStartInfo]::new($case.Executable)
    Add-BoundedProcessArgument $start $case.Argument
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $null = $process.Start()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0 -or $stderr.Length -ne 0 -or $stdout.TrimEnd("`r", "`n") -cne $case.Expected) {
      throw "focused CLI canonical replay failed: $($case.Executable)"
    }

    $refusalStart = [Diagnostics.ProcessStartInfo]::new($case.Executable)
    $refusalStart.UseShellExecute = $false
    $refusalStart.RedirectStandardOutput = $true
    $refusalStart.RedirectStandardError = $true
    $refusal = [Diagnostics.Process]::new()
    $refusal.StartInfo = $refusalStart
    $null = $refusal.Start()
    $refusalStdout = $refusal.StandardOutput.ReadToEnd()
    $refusalStderr = $refusal.StandardError.ReadToEnd()
    $refusal.WaitForExit()
    if ($refusal.ExitCode -ne 2 -or $refusalStdout.Length -ne 0 -or $refusalStderr.Length -eq 0) {
      throw "focused CLI bounded-argument refusal failed: $($case.Executable)"
    }
  }
  Write-Output "production_preparation_plan_provider_free=passed"
} finally {
  Pop-Location
}
