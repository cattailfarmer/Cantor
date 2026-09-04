param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$verify=Join-Path $PSScriptRoot 'verify_cantor_b1_private_execution_permit_reference_correspondence_p0_formation.ps1'
& $verify -Root $root
$testRoot=Join-Path 'D:\CantorBuilds' ('a7-formation-'+[guid]::NewGuid().Guid)
$parent=[IO.Path]::GetFullPath('D:\CantorBuilds');$resolved=[IO.Path]::GetFullPath($testRoot)
if(-not $resolved.StartsWith($parent+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'unsafe test root'}
try{
 New-Item -ItemType Directory -Path $testRoot -Force|Out-Null
 $manifest=Get-Content -LiteralPath (Join-Path $root 'experiments/b1_private_execution_permit_reference_correspondence_p0/formation_evidence_manifest.json') -Raw|ConvertFrom-Json
 $manifestDst=Join-Path $testRoot 'experiments/b1_private_execution_permit_reference_correspondence_p0/formation_evidence_manifest.json';New-Item -ItemType Directory -Path (Split-Path -Parent $manifestDst) -Force|Out-Null;Copy-Item -LiteralPath (Join-Path $root 'experiments/b1_private_execution_permit_reference_correspondence_p0/formation_evidence_manifest.json') -Destination $manifestDst
 foreach($artifact in $manifest.artifacts){$dst=Join-Path $testRoot ([string]$artifact.path);New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force|Out-Null;Copy-Item -LiteralPath (Join-Path $root ([string]$artifact.path)) -Destination $dst}
 $scriptDst=Join-Path $testRoot 'scripts/verify_cantor_b1_private_execution_permit_reference_correspondence_p0_formation.ps1';New-Item -ItemType Directory -Path (Split-Path -Parent $scriptDst) -Force|Out-Null;Copy-Item -LiteralPath $verify -Destination $scriptDst
 & $scriptDst -Root $testRoot
 $spec=Join-Path $testRoot 'specifications/Cantor_B1_Private_Execution_Permit_Reference_Correspondence_P0.sop';[IO.File]::AppendAllText($spec,[Environment]::NewLine)
 $refused=$false;try{& $scriptDst -Root $testRoot|Out-Null}catch{$refused=$true};if(-not $refused){throw 'tamper admitted'}
 Copy-Item -LiteralPath (Join-Path $root 'specifications/Cantor_B1_Private_Execution_Permit_Reference_Correspondence_P0.sop') -Destination $spec -Force
 $manifestPath=Join-Path $testRoot 'experiments/b1_private_execution_permit_reference_correspondence_p0/formation_evidence_manifest.json';$mutated=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json;$mutated.verification.private_execution_permit_present=$true;$mutated|ConvertTo-Json -Depth 20 -Compress|Set-Content -LiteralPath $manifestPath -NoNewline
 $refused=$false;try{& $scriptDst -Root $testRoot|Out-Null}catch{$refused=$true};if(-not $refused){throw 'authority promotion admitted'}
 'b1_private_execution_permit_reference_correspondence_formation_tests=passed isolated_successes=1 isolated_refusals=2'
}finally{if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}}
