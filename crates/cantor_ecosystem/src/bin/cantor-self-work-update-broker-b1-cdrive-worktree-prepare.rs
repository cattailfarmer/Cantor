use std::{env, fs, process::ExitCode};

use cantor_ecosystem::{
    compile_cdrive_worktree_preparation_plan,
    from_cdrive_worktree_preparation_request_machine_form,
    parse_and_validate_cdrive_worktree_preparation_publication_proof,
    to_cdrive_worktree_preparation_plan_machine_form,
};

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 3 || arguments[0] != "--plan-only" {
        eprintln!(
            "usage: cantor-self-work-update-broker-b1-cdrive-worktree-prepare --plan-only <request.json> <publication-proof.json>"
        );
        return ExitCode::from(2);
    }
    let result = fs::read(&arguments[1])
        .map_err(|error| error.to_string())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|error| error.to_string()))
        .and_then(|machine_form| {
            from_cdrive_worktree_preparation_request_machine_form(&machine_form)
                .map_err(|error| error.to_string())
        })
        .and_then(|request| {
            fs::read(&arguments[2])
                .map_err(|error| error.to_string())
                .and_then(|bytes| {
                    parse_and_validate_cdrive_worktree_preparation_publication_proof(
                        &request, &bytes,
                    )
                    .map_err(|error| error.to_string())
                })
                .and_then(|proof| {
                    compile_cdrive_worktree_preparation_plan(&request, &proof)
                        .map_err(|error| error.to_string())
                })
        })
        .and_then(|plan| {
            to_cdrive_worktree_preparation_plan_machine_form(&plan)
                .map_err(|error| error.to_string())
        });
    match result {
        Ok(plan) => {
            println!("{plan}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
