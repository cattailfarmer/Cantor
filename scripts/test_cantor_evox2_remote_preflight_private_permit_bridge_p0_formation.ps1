param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root=Split-Path -Parent $PSScriptRoot
$verify=Join-Path $PSScriptRoot 'verify_cantor_evox2_remote_preflight_private_permit_bridge_p0_formation.ps1'
& $verify -Root $root
$parent=[IO.Path]::GetFullPath('D:\CantorBuilds')
$testRoot=Join-Path $parent ('evox2-private-permit-bridge-formation-' + [guid]::NewGuid().Guid)
$resolved=[IO.Path]::GetFullPath($testRoot)
if(-not $resolved.StartsWith($parent + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'unsafe private permit bridge formation test root'}
try {
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    $manifestRelative='experiments/evox2_remote_preflight_one_shot_activation_ceremony_p0/private_permit_bridge_formation_evidence_manifest.json'
    $manifestSource=Join-Path $root $manifestRelative
    $manifestDestination=Join-Path $testRoot $manifestRelative
    New-Item -ItemType Directory -Path (Split-Path -Parent $manifestDestination) -Force | Out-Null
    Copy-Item -LiteralPath $manifestSource -Destination $manifestDestination
    $manifest=Get-Content -LiteralPath $manifestSource -Raw|ConvertFrom-Json
    foreach($artifact in $manifest.artifacts){$destination=Join-Path $testRoot ([string]$artifact.path);New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force|Out-Null;Copy-Item -LiteralPath (Join-Path $root ([string]$artifact.path)) -Destination $destination}
    $scriptDestination=Join-Path $testRoot 'scripts/verify_cantor_evox2_remote_preflight_private_permit_bridge_p0_formation.ps1'
    New-Item -ItemType Directory -Path (Split-Path -Parent $scriptDestination) -Force|Out-Null
    Copy-Item -LiteralPath $verify -Destination $scriptDestination
    & $scriptDestination -Root $testRoot
    $refusals=0
    $specRelative='specifications/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0.sop'
    $specDestination=Join-Path $testRoot $specRelative
    [IO.File]::AppendAllText($specDestination,[Environment]::NewLine)
    try{& $scriptDestination -Root $testRoot|Out-Null;throw 'raw-byte tamper admitted'}catch{if($_.Exception.Message -eq 'raw-byte tamper admitted'){throw};$refusals++}
    Copy-Item -LiteralPath (Join-Path $root $specRelative) -Destination $specDestination -Force
    $mutations=@(
        @('maximum_permit_issuances',2),@('retry_count',1),@('formation_permit_constructors',1),@('formation_runner_invocations',1),
        @('production_admission_constructor_present',$true),@('public_bridge_export_present',$true),@('admission_cloneable',$true),
        @('permit_consumed_before_runner',$false),@('terminal_has_outgoing_edge',$true),@('correspondence_is_live_admission',$true),
        @('live_initiation_authorized_by_formation',$true),@('activation_bookend_commit',('0'*40))
    )
    foreach($mutation in $mutations){Copy-Item -LiteralPath $manifestSource -Destination $manifestDestination -Force;$changed=Get-Content -LiteralPath $manifestDestination -Raw|ConvertFrom-Json;$changed.verification.($mutation[0])=$mutation[1];[IO.File]::WriteAllText($manifestDestination,(($changed|ConvertTo-Json -Depth 20 -Compress)),[Text.UTF8Encoding]::new($false));try{& $scriptDestination -Root $testRoot|Out-Null;throw "semantic mutation admitted $($mutation[0])"}catch{if($_.Exception.Message -like 'semantic mutation admitted*'){throw};$refusals++}}
    foreach($replacement in @(
        @('no pub mod no pub use','one pub mod and one pub use'),
        @('no production admission constructor exists','one production admission constructor exists')
    )){
        Copy-Item -LiteralPath $manifestSource -Destination $manifestDestination -Force
        Copy-Item -LiteralPath (Join-Path $root $specRelative) -Destination $specDestination -Force
        $signatureRelative='narrative/registries/Cantor_EVO_X2_Remote_Preflight_Private_Permit_Bridge_P0_Satisfaction_Signature.sop'
        $signatureDestination=Join-Path $testRoot $signatureRelative
        Copy-Item -LiteralPath (Join-Path $root $signatureRelative) -Destination $signatureDestination -Force
        $raw=[IO.File]::ReadAllText($specDestination)
        if(-not $raw.Contains([string]$replacement[0])){throw 'redigested mutation source token absent'}
        [IO.File]::WriteAllText($specDestination,$raw.Replace([string]$replacement[0],[string]$replacement[1]),[Text.UTF8Encoding]::new($false))
        $specItem=Get-Item -LiteralPath $specDestination;$specHash=(Get-FileHash -LiteralPath $specDestination -Algorithm SHA256).Hash
        $signatureRaw=[IO.File]::ReadAllText($signatureDestination)
        $pattern='(?m)^  \+ \[artifact_binding\] ' + [regex]::Escape($specRelative) + ' bytes\d+ SHA256 [A-F0-9]{64}$'
        $binding="  + [artifact_binding] $specRelative bytes$($specItem.Length) SHA256 $specHash"
        $signatureRaw=[regex]::Replace($signatureRaw,$pattern,$binding)
        [IO.File]::WriteAllText($signatureDestination,$signatureRaw,[Text.UTF8Encoding]::new($false))
        $changed=Get-Content -LiteralPath $manifestDestination -Raw|ConvertFrom-Json
        $specArtifact=@($changed.artifacts|Where-Object{$_.path -ceq $specRelative})[0];$specArtifact.bytes=[int64]$specItem.Length;$specArtifact.sha256=$specHash
        $signatureItem=Get-Item -LiteralPath $signatureDestination;$signatureHash=(Get-FileHash -LiteralPath $signatureDestination -Algorithm SHA256).Hash
        $signatureArtifact=@($changed.artifacts|Where-Object{$_.path -ceq $signatureRelative})[0];$signatureArtifact.bytes=[int64]$signatureItem.Length;$signatureArtifact.sha256=$signatureHash
        [IO.File]::WriteAllText($manifestDestination,(($changed|ConvertTo-Json -Depth 20 -Compress)),[Text.UTF8Encoding]::new($false))
        try{& $scriptDestination -Root $testRoot|Out-Null;throw "redigested semantic mutation admitted $($replacement[0])"}catch{if($_.Exception.Message -like 'redigested semantic mutation admitted*'){throw};$refusals++}
    }
    "cantor_evox2_remote_preflight_private_permit_bridge_formation_tests=passed isolated_successes=1 isolated_refusals=$refusals redigested_refusals=2"
} finally {
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
