use std::{env, fs::File, io::Read, path::PathBuf, process::ExitCode};

use cantor_ecosystem::{CandidateWorkspaceRequest, admit_candidate_workspace};

const MAX_INPUT_BYTES: usize = 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(receipt) => match serde_json::to_writer_pretty(std::io::stdout(), &receipt) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("candidate_workspace_probe_output_failed: {error}");
                ExitCode::from(70)
            }
        },
        Err(error) => {
            eprintln!("candidate_workspace_probe_failed: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<cantor_ecosystem::AdmissionReceipt, Box<dyn std::error::Error>> {
    let path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: candidate_workspace_probe <absolute-request.json>")?;
    if !path.is_absolute() {
        return Err("request path must be absolute".into());
    }
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    if length > MAX_INPUT_BYTES as u64 {
        return Err("request exceeds the 1 MiB limit".into());
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let request: CandidateWorkspaceRequest = serde_json::from_slice(&bytes)?;
    admit_candidate_workspace(&request).map_err(Into::into)
}
