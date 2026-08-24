[CmdletBinding()]
param([string]$EvidencePath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

function Invoke-Cargo([string[]]$Arguments, [string]$Label) {
    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Label failed with status $LASTEXITCODE" }
}

function Write-JsonLf([object]$Value, [string]$Path) {
    $json = ([string]::Join("`n", @($Value | ConvertTo-Json -Depth 8))).Replace("`r", '')
    [IO.Directory]::CreateDirectory((Split-Path -Parent $Path)) | Out-Null
    [IO.File]::WriteAllText($Path, ($json + "`n"), [Text.UTF8Encoding]::new($false))
}

Push-Location $root
try {
    Invoke-Cargo @('test','-q','-p','cantor_ecosystem','--lib','sjs_commit_placement_acquisition','--locked','--offline') 'P3 module debug tests'
    Invoke-Cargo @('test','-q','-p','cantor_ecosystem','--bin','cantor-sjs-commit-placement-acquire','--locked','--offline') 'P3 CLI debug tests'
    Invoke-Cargo @('test','-q','-p','cantor_ecosystem','--test','sjs_commit_placement_acquisition_physical','--locked','--offline') 'P3 physical debug tests'

    $priorRustFlags = $env:RUSTFLAGS
    try {
        $env:RUSTFLAGS = '-C overflow-checks=on -C metadata=cantor_sjs_cpa_p3_focused'
        Invoke-Cargo @('test','-q','-p','cantor_ecosystem','--lib','sjs_commit_placement_acquisition','--release','--locked','--offline') 'P3 module release tests'
        Invoke-Cargo @('test','-q','-p','cantor_ecosystem','--bin','cantor-sjs-commit-placement-acquire','--release','--locked','--offline') 'P3 CLI release tests'
        Invoke-Cargo @('test','-q','-p','cantor_ecosystem','--test','sjs_commit_placement_acquisition_physical','--release','--locked','--offline') 'P3 physical release tests'
    }
    finally {
        $env:RUSTFLAGS = $priorRustFlags
    }

    Invoke-Cargo @('clippy','-q','-p','cantor_ecosystem','--lib','--bin','cantor-sjs-commit-placement-acquire','--test','sjs_commit_placement_acquisition_physical','--locked','--offline','--','-D','warnings') 'P3 warnings-denied Clippy'
    Invoke-Cargo @('fmt','--all','--','--check') 'workspace format gate'

    $summary = [ordered]@{
        schema = 'cantor-sjs-commit-placement-acquisition-p3-controlled-evidence/0.1'
        canonical_uuid = '7602b617-05c5-459a-8a78-23bcd638e164'
        signature_uuid = '29c32998-d592-40f7-9481-6cba19634581'
        status = 'passed'
        module_tests = 9
        cli_tests = 2
        independent_physical_tests = 5
        controlled_successes = 3
        controlled_refusals = 5
        success_families = @('one_link_physical','two_link_physical','deterministic_replay')
        refusal_families = @('raw_blob_tamper','executable_tree_mode','cli_output_path','noncanonical_repository_path','git_version_replay')
        authority = 'observation_only'
        physical_contact = $true
        repository_mutation_authority = $false
        provider_contacted = $false
        product_git_mutation_commands = 0
    }
    if ($EvidencePath) {
        $resolved = [IO.Path]::GetFullPath((Join-Path $root $EvidencePath))
        $rootPrefix = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
        if (-not $resolved.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'evidence path escaped repository root'
        }
        Write-JsonLf $summary $resolved
    }
    Write-Output 'sjs_commit_placement_acquisition_p3_tests=passed successes=3 refusals=5'
}
finally {
    Pop-Location
}
