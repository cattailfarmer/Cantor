use std::{env, fs::File, io::Read, path::PathBuf, process::ExitCode};

use cantor_core::{ProtocolRequest, SemanticId};
use cantor_ecosystem::{
    CommissionContract, CycleIdentityPlan, LiveCodexAdapter, LiveCodexConfig, StdioAppServerDriver,
    WorkPacket, run_supervised_mock_cycle,
};
use serde::Deserialize;
use serde_json::json;

const MAX_PROBE_INPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeInput {
    config: LiveCodexConfig,
    commission: CommissionContract,
    work_packet: WorkPacket,
    cycle_namespace: SemanticId,
    request: ProtocolRequest,
}

fn main() -> ExitCode {
    match run() {
        Ok(value) => match serde_json::to_writer_pretty(std::io::stdout(), &value) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("live_probe_output_failed: {error}");
                ExitCode::from(70)
            }
        },
        Err(error) => {
            eprintln!("live_probe_failed: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: live_codex_probe <absolute-probe-input.json>")?;
    if !path.is_absolute() {
        return Err("probe input path must be absolute".into());
    }
    let file = File::open(&path)?;
    let length = file.metadata()?.len();
    if length > MAX_PROBE_INPUT_BYTES as u64 {
        return Err("probe input exceeds the 4 MiB limit".into());
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((MAX_PROBE_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let input: ProbeInput = serde_json::from_slice(&bytes)?;
    if input.work_packet.commission_uuid != input.commission.commission_uuid {
        return Err("work packet and commission are not correlated".into());
    }
    let driver = StdioAppServerDriver::new(input.config)?;
    let (mut codex, mut cantor) = LiveCodexAdapter::new(
        input.work_packet.work_packet_uuid.clone(),
        input.request,
        input.commission.proof_obligation.clone(),
        driver,
    );
    let identities = CycleIdentityPlan::new(input.cycle_namespace.to_string())?;
    let outcome = run_supervised_mock_cycle(
        input.commission,
        input.work_packet,
        &identities,
        &mut codex,
        &mut cantor,
    )
    .map_err(|failure| {
        let detail = serde_json::to_string(&*failure)
            .unwrap_or_else(|_| "unencodable cycle failure".to_owned());
        std::io::Error::other(detail)
    })?;
    let evidence = codex
        .evidence()
        .ok_or("live cycle completed without physical-turn evidence")?;
    Ok(json!({
        "profile": "cantor-live-codex-probe/0.1",
        "evidence": evidence,
        "outcome": outcome
    }))
}
