use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use cantor_core::{ProtocolRequest, SemanticId, sha256_digest};
use cantor_ecosystem::{
    AcceptanceCriterion, AuthorityGrant, CommissionContract, CommissionLifecycle, EcosystemBudget,
    LIVE_CODEX_CONFIG_PROFILE, LiveCodexConfig, ParticipantAddress, ParticipantRole, WorkPacket,
    mandatory_review_checks, sha256_file,
};
use serde::Serialize;

const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;

#[derive(Serialize)]
struct ProbeInput {
    config: LiveCodexConfig,
    commission: CommissionContract,
    work_packet: WorkPacket,
    cycle_namespace: SemanticId,
    request: ProtocolRequest,
}

fn main() -> ExitCode {
    match run() {
        Ok(path) => {
            println!("{}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("prepare_live_probe_failed: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let args = env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if args.len() != 6 {
        return Err(
            "usage: prepare_live_codex_probe <codex-exe> <cantor-mcp-exe> <environment.json> <request.json> <working-directory> <output.json>"
                .into(),
        );
    }
    let codex = canonical_file(&args[0], "Codex executable")?;
    let cantor_mcp = canonical_file(&args[1], "Cantor MCP executable")?;
    let environment = canonical_file(&args[2], "environment")?;
    let request_path = canonical_file(&args[3], "request")?;
    let cwd = fs::canonicalize(&args[4])?;
    if !cwd.is_dir() {
        return Err("working directory is not a directory".into());
    }
    let output = absolute_output(&args[5])?;
    let request = load_request(&request_path)?;
    let codex_version = command_version(&codex)?;
    let proof = id("proof:live_app_server_exchange")?;
    let evidence = id("evidence:live_probe_input")?;
    let commission_uuid = id("commission:read_only_live_probe")?;
    let work_packet_uuid = id("work:read_only_live_probe")?;
    let principal = ParticipantAddress::new(ParticipantRole::Principal, "principal:operator")?;
    let manager = ParticipantAddress::new(ParticipantRole::Manager, "manager:shaliach")?;
    let worker = ParticipantAddress::new(ParticipantRole::CodexThread, "codex:live_probe")?;
    let cantor = ParticipantAddress::new(ParticipantRole::CantorParticipant, "cantor:live_probe")?;
    let observer = ParticipantAddress::new(ParticipantRole::Observer, "observer:live_probe")?;
    let authority = AuthorityGrant {
        projects: ["Cantor".to_owned()].into_iter().collect(),
        semantic_operations: [request.request.name().to_owned()].into_iter().collect(),
        tool_capabilities: ["query_sop".to_owned()].into_iter().collect(),
        data_scopes: ["signed_corpus".to_owned()].into_iter().collect(),
        effect_classes: BTreeSet::new(),
    };
    let budget = EcosystemBudget {
        maximum_messages: 16,
        maximum_serialized_bytes: 4_000_000,
        maximum_call_depth: 4,
        maximum_logical_ticks: 32,
    };
    let commission = CommissionContract {
        profile: cantor_ecosystem::COMMISSION_PROFILE.to_owned(),
        commission_uuid: commission_uuid.clone(),
        principal,
        manager,
        purpose: "prove one pinned, read-only Codex App Server turn with one exact Cantor MCP call"
            .to_owned(),
        requested_result: "one protocol-verified, effect-free candidate and immutable transcript"
            .to_owned(),
        authority_grant: authority.clone(),
        required_review_checks: mandatory_review_checks(),
        evidence_obligation: [evidence].into_iter().collect(),
        proof_obligation: [proof].into_iter().collect(),
        budget,
        activated_at_tick: 1,
        expires_at_tick: 64,
        lifecycle: CommissionLifecycle::Active,
    };
    let work_packet = WorkPacket {
        profile: cantor_ecosystem::WORK_PACKET_PROFILE.to_owned(),
        work_packet_uuid,
        commission_uuid,
        worker,
        cantor_participant: cantor,
        observer,
        subject: "Cantor read-only live Codex adapter".to_owned(),
        purpose: "execute the supervisor-issued ProtocolRequest through the sole admitted MCP route"
            .to_owned(),
        requested_result: "a JSON candidate proving the exact call completed without effects"
            .to_owned(),
        acceptance_criteria: vec![AcceptanceCriterion {
            criterion_id: id("criterion:exact_live_cantor_exchange")?,
            description:
                "the pinned live turn used exactly one cantor.query_sop call and returned a verified ProtocolResponse without effects"
                    .to_owned(),
        }],
        authority_grant: authority,
        frame_digest: sha256_digest(&request)?,
        budget,
    };
    let input = ProbeInput {
        config: LiveCodexConfig {
            profile: LIVE_CODEX_CONFIG_PROFILE.to_owned(),
            codex_executable: codex.clone(),
            codex_executable_sha256: sha256_file(&codex)?,
            codex_version,
            cantor_mcp_executable: cantor_mcp.clone(),
            cantor_mcp_executable_sha256: sha256_file(&cantor_mcp)?,
            environment_file: environment.clone(),
            environment_file_sha256: sha256_file(&environment)?,
            working_directory: cwd,
            mcp_server_name: "cantor".to_owned(),
            mcp_tool_name: "query_sop".to_owned(),
            ..LiveCodexConfig::default()
        },
        commission,
        work_packet,
        cycle_namespace: id("cycle:read_only_live_probe")?,
        request,
    };
    let parent = output
        .parent()
        .ok_or("output path has no parent directory")?;
    fs::create_dir_all(parent)?;
    let bytes = serde_json::to_vec_pretty(&input)?;
    let mut file = File::create(&output)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(output)
}

fn id(value: &str) -> Result<SemanticId, cantor_core::EvaluationFault> {
    SemanticId::new(value)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_file() {
        return Err(format!("{label} is not a file").into());
    }
    Ok(canonical)
}

fn absolute_output(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn load_request(path: &Path) -> Result<ProtocolRequest, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    if length > MAX_REQUEST_BYTES as u64 {
        return Err("request exceeds the 2 MiB limit".into());
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn command_version(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(path).arg("--version").output()?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err("Codex version probe failed or was oversized".into());
    }
    let version = String::from_utf8(output.stdout)?.trim().to_owned();
    if version.is_empty() {
        return Err("Codex version is empty".into());
    }
    Ok(version)
}
