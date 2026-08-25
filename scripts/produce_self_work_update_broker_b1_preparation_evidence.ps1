[CmdletBinding()]
param(
    [string]$EnvelopeRoot = 'D:\CantorB1',
    [string]$OutputRoot = 'C:\Project\Cantor\crates\cantor_ecosystem\evidence\self_work_update_broker_b1_preparation',
    [string]$ProcessStartedUtc = '2026-08-25T17:15:47.9979737+00:00',
    [string]$ProcessEndedUtc = '2026-08-25T17:15:49.4211572+00:00',
    [int]$ElapsedMilliseconds = 1423
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$native = 'C:\Users\enjer\AppData\Roaming\npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe'
$package = 'C:\Users\enjer\AppData\Roaming\npm\node_modules\@openai\codex\package.json'
$git = 'C:\Program Files\Git\cmd\git.exe'
$schemaRoot = Join-Path $EnvelopeRoot 'fixture\schema'
$candidateRoot = Join-Path $EnvelopeRoot 'fixture\candidate'
$expectedNativeSha256 = 'FE12887B4AB4A4E988F0FA5BAAE9E5CB7D8505C26401378628E762DB9A2E798F'
$expectedPackageSha256 = '371B503B75F22FAAEC071D87C2DB45D9B438056CB52FE5959731EF1D6025C013'
$expectedGitSha256 = '81EF35AE005CA9318018D18E3327578CE939FB99FEAAD6B2D7C8AB15F3DE8DB5'
$utf8 = [Text.UTF8Encoding]::new($false)

function Get-Sha256Text([string]$Text) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($Text)))
}

function Write-NewUtf8([string]$Path, [string]$Text) {
    if (Test-Path -LiteralPath $Path) {
        throw "refusing to overwrite evidence path $Path"
    }
    [IO.File]::WriteAllText($Path, $Text, $utf8)
}

function Get-RelativeForwardPath([string]$Base, [string]$Path) {
    $Path.Substring($Base.Length + 1).Replace('\', '/')
}

function Get-FileId([string]$Path) {
    $line = (& fsutil file queryfileid $Path 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $line -notmatch '0x[0-9a-fA-F]+') {
        throw "unable to bind file identity for $Path"
    }
    $Matches[0].ToLowerInvariant()
}

if ($EnvelopeRoot -ne 'D:\CantorB1') {
    throw 'envelope root is not the commissioned literal path'
}
if (-not (Test-Path -LiteralPath $EnvelopeRoot -PathType Container)) {
    throw 'prepared envelope is absent'
}
if (Test-Path -LiteralPath $OutputRoot) {
    throw 'evidence output root already exists'
}
if ((Get-FileHash -LiteralPath $native -Algorithm SHA256).Hash -ne $expectedNativeSha256) {
    throw 'selected native executable drifted'
}
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ne $expectedPackageSha256) {
    throw 'selected package drifted'
}
if ((Get-FileHash -LiteralPath $git -Algorithm SHA256).Hash -ne $expectedGitSha256) {
    throw 'selected Git executable drifted'
}

$activeSelectedProcesses = @(
    Get-CimInstance Win32_Process |
        Where-Object { $_.ExecutablePath -eq $native }
)
if ($activeSelectedProcesses.Count -ne 0) {
    throw 'selected native executable still has active processes'
}

$schemaRows = @(
    Get-ChildItem -LiteralPath $schemaRoot -Recurse -File -Force |
        ForEach-Object {
            if ($_.LinkType) { throw "schema reparse object $($_.FullName)" }
            [pscustomobject]@{
                RelativePath = Get-RelativeForwardPath $schemaRoot $_.FullName
                Bytes = $_.Length
                SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        } |
        Sort-Object RelativePath
)
$schemaTsv = (($schemaRows | ForEach-Object { "$($_.RelativePath)`t$($_.Bytes)`t$($_.SHA256)" }) -join "`n") + "`n"

$envelopeRows = @(
    Get-ChildItem -LiteralPath $EnvelopeRoot -Recurse -File -Force |
        ForEach-Object {
            if ($_.LinkType) { throw "envelope reparse object $($_.FullName)" }
            [pscustomobject]@{
                RelativePath = Get-RelativeForwardPath $EnvelopeRoot $_.FullName
                Bytes = $_.Length
                SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        } |
        Sort-Object RelativePath
)
$envelopeTsv = (($envelopeRows | ForEach-Object { "$($_.RelativePath)`t$($_.Bytes)`t$($_.SHA256)" }) -join "`n") + "`n"

$directoryRows = @(
    @((Get-Item -LiteralPath $EnvelopeRoot)) + @(Get-ChildItem -LiteralPath $EnvelopeRoot -Recurse -Directory -Force) |
        ForEach-Object {
            if ($_.LinkType) { throw "directory reparse object $($_.FullName)" }
            $relative = if ($_.FullName -eq $EnvelopeRoot) { '.' } else { Get-RelativeForwardPath $EnvelopeRoot $_.FullName }
            [pscustomobject]@{
                RelativePath = $relative
                FileId = Get-FileId $_.FullName
                Attributes = [int]$_.Attributes
            }
        } |
        Sort-Object RelativePath
)
$directoryTsv = (($directoryRows | ForEach-Object { "$($_.RelativePath)`t$($_.FileId)`t$($_.Attributes)" }) -join "`n") + "`n"

$head = (& $git -C $candidateRoot rev-parse HEAD).Trim()
$branch = (& $git -C $candidateRoot symbolic-ref HEAD).Trim()
$commonDir = (& $git -C $candidateRoot rev-parse --path-format=absolute --git-common-dir).Trim().Replace('/', '\')
$gitDir = (& $git -C $candidateRoot rev-parse --path-format=absolute --git-dir).Trim().Replace('/', '\')
$status = (& $git -C $candidateRoot status --porcelain=v1 | Out-String).Trim()
$remotes = (& $git -C $candidateRoot remote | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $status -ne '' -or $remotes -ne '') {
    throw 'candidate Git post-state is not clean and remote-free'
}

$commandSchema = Get-Content -LiteralPath (Join-Path $schemaRoot 'v2\CommandExecParams.json') -Raw | ConvertFrom-Json
$sandboxDefinition = $commandSchema.definitions.SandboxPolicy.oneOf
$readOnlyPolicy = @($sandboxDefinition | Where-Object { $_.properties.type.enum -contains 'readOnly' })
$readOnlyProperties = @($readOnlyPolicy[0].properties.psobject.Properties.Name | Sort-Object)
$restrictedReadScopeRepresentable = @($readOnlyProperties | Where-Object { $_ -match 'read|root|path' }).Count -gt 0
$refusalCode = if ($restrictedReadScopeRepresentable) { $null } else { 'selected_schema_missing_read_scope_control' }

$environmentValues = [ordered]@{
    CODEX_HOME = 'D:\CantorB1\fixture\codex-home'
    CODEX_SQLITE_HOME = 'D:\CantorB1\fixture\codex-sqlite'
    RUST_LOG = 'error'
    SystemRoot = $env:SystemRoot
    TEMP = 'D:\CantorB1\fixture\temp'
    TMP = 'D:\CantorB1\fixture\temp'
}
$environmentDigests = @(
    foreach ($entry in $environmentValues.GetEnumerator()) {
        [ordered]@{ name = $entry.Key; value_sha256 = Get-Sha256Text $entry.Value }
    }
)

$rolePaths = [ordered]@{
    authorization_envelope = $EnvelopeRoot
    disposable_fixture = Join-Path $EnvelopeRoot 'fixture'
    candidate_workspace = $candidateRoot
    app_server_state = Join-Path $EnvelopeRoot 'fixture\codex-home'
    sqlite_state = Join-Path $EnvelopeRoot 'fixture\codex-sqlite'
    canary = Join-Path $EnvelopeRoot 'fixture\canary'
    temporary = Join-Path $EnvelopeRoot 'fixture\temp'
    schema_output = $schemaRoot
    prospective_evidence = Join-Path $EnvelopeRoot 'evidence'
}
$roleIdentities = @(
    foreach ($entry in $rolePaths.GetEnumerator()) {
        $item = Get-Item -LiteralPath $entry.Value
        [ordered]@{
            role = $entry.Key
            path = $item.FullName
            file_id = Get-FileId $item.FullName
            attributes = [int]$item.Attributes
            reparse = [bool]$item.LinkType
        }
    }
)

$result = [ordered]@{
    profile = 'cantor-self-work-update-broker-b1-npm-native-preparation/0.1'
    source_snapshot_uuid = 'ba57adf0-46fa-40e1-b29f-59c14f5c83f0'
    predecessor_commit = '12d9c8a71d653680056233d5b75b0fa05702926b'
    disposition = 'prepared_final_b1_not_run'
    recovery_owner = 'THEBRAIN\enjer'
    selected_executable = [ordered]@{
        path = $native
        bytes = (Get-Item -LiteralPath $native).Length
        sha256 = $expectedNativeSha256
        file_id = Get-FileId $native
        package_path = $package
        package_sha256 = $expectedPackageSha256
        package_version = '0.135.0'
        signer = 'OpenAI OpCo LLC'
        signer_thumbprint = 'E370424E072D7BD3CE08EBF7D30A8B5581605535'
    }
    fixture = [ordered]@{
        volume_id = '\\?\Volume{1bfda880-4592-426d-bc09-a5733fb130ac}\'
        roles = $roleIdentities
        directory_count = $directoryRows.Count
        directory_inventory_bytes = $utf8.GetByteCount($directoryTsv)
        directory_inventory_sha256 = Get-Sha256Text $directoryTsv
        file_count = $envelopeRows.Count
        file_inventory_bytes = $utf8.GetByteCount($envelopeTsv)
        file_inventory_sha256 = Get-Sha256Text $envelopeTsv
        candidate_head = $head
        candidate_branch = $branch
        candidate_common_dir = $commonDir
        candidate_git_dir = $gitDir
        candidate_clean = $true
        candidate_remote_count = 0
    }
    schema_generation = [ordered]@{
        argv = @('app-server', 'generate-json-schema', '--out', $schemaRoot)
        environment_clear_first = $true
        environment = $environmentDigests
        started_utc = $ProcessStartedUtc
        ended_utc = $ProcessEndedUtc
        elapsed_milliseconds = $ElapsedMilliseconds
        deadline_milliseconds = 60000
        stdout_bytes = 0
        stderr_bytes = 0
        exit_code = 0
        timed_out = $false
        selected_executable_post_sha256 = $expectedNativeSha256
        active_selected_process_count_after = 0
        schema_file_count = $schemaRows.Count
        schema_total_bytes = ($schemaRows | Measure-Object Bytes -Sum).Sum
        schema_inventory_bytes = $utf8.GetByteCount($schemaTsv)
        schema_inventory_sha256 = Get-Sha256Text $schemaTsv
        command_exec_params_sha256 = (Get-FileHash -LiteralPath (Join-Path $schemaRoot 'v2\CommandExecParams.json') -Algorithm SHA256).Hash
        command_exec_response_sha256 = (Get-FileHash -LiteralPath (Join-Path $schemaRoot 'v2\CommandExecResponse.json') -Algorithm SHA256).Hash
        initialize_params_sha256 = (Get-FileHash -LiteralPath (Join-Path $schemaRoot 'v1\InitializeParams.json') -Algorithm SHA256).Hash
        initialize_response_sha256 = (Get-FileHash -LiteralPath (Join-Path $schemaRoot 'v1\InitializeResponse.json') -Algorithm SHA256).Hash
    }
    final_b1_admission = [ordered]@{
        eligible = $restrictedReadScopeRepresentable
        run_count = 0
        transcript_frame_count = 0
        restricted_read_scope_representable = $restrictedReadScopeRepresentable
        read_only_policy_properties = $readOnlyProperties
        refusal_code = $refusalCode
        provider_contact_count = 0
        model_turn_count = 0
        mcp_call_count = 0
        external_network_count = 0
        mutation_count = 0
    }
}

[void](New-Item -ItemType Directory -Path $OutputRoot -ErrorAction Stop)
Write-NewUtf8 (Join-Path $OutputRoot 'schema_inventory.tsv') $schemaTsv
Write-NewUtf8 (Join-Path $OutputRoot 'envelope_inventory.tsv') $envelopeTsv
Write-NewUtf8 (Join-Path $OutputRoot 'directory_inventory.tsv') $directoryTsv
$resultJson = ($result | ConvertTo-Json -Depth 12) + "`n"
Write-NewUtf8 (Join-Path $OutputRoot 'preparation_result.json') $resultJson

$manifestRows = @(
    Get-ChildItem -LiteralPath $OutputRoot -File |
        ForEach-Object {
            [ordered]@{
                path = $_.Name
                bytes = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        } |
        Sort-Object path
)
$manifest = [ordered]@{
    profile = 'cantor-self-work-update-broker-b1-preparation-evidence-manifest/0.1'
    source_snapshot_uuid = 'ba57adf0-46fa-40e1-b29f-59c14f5c83f0'
    artifacts = $manifestRows
}
Write-NewUtf8 (Join-Path $OutputRoot 'manifest.json') (($manifest | ConvertTo-Json -Depth 6) + "`n")

Get-Content -LiteralPath (Join-Path $OutputRoot 'preparation_result.json') -Raw
