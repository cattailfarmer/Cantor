use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use cantor_core::{
    ContentDigest, SemanticId, SjsRcxInputClass, seal_sjs_rcx_request, sha256_bytes,
    synthetic_sjs_rcx_request,
};
use cantor_ecosystem::sjs_compiled_lookahead_repository_slice_observation::{
    SJS_RSO_CANONICAL_UUID, SJS_RSO_NON_AUTHORITY, SJS_RSO_PARENT_COMPLETION_UUID,
    SJS_RSO_REQUEST_PROFILE, SJS_RSO_SIGNATURE_UUID, SJS_RSO_SOURCE_UUID, SjsRsoInputClass,
    SjsRsoLimits, SjsRsoRequest, build_sjs_rso_evidence_bundle,
    compile_sjs_rso_commit_tree_receipt, prepare_sjs_rso_git_runner, seal_sjs_rso_request,
    to_sjs_rso_evidence_bundle_machine_form,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 4
        || arguments[0] != "--repository-root"
        || arguments[2] != "--git-executable"
    {
        return Err(
            "usage: cantor-sjs-compiled-lookahead-repository-slice-observation-fixture --repository-root <empty-absolute-directory> --git-executable <absolute-file>"
                .to_owned(),
        );
    }
    let repository_root = PathBuf::from(&arguments[1]);
    let git_executable = PathBuf::from(&arguments[3]);
    require_empty_fixture_root(&repository_root)?;
    if !git_executable.is_absolute() || !git_executable.is_file() {
        return Err("Git executable must be an existing absolute file".to_owned());
    }

    run_fixture_git(
        &repository_root,
        &git_executable,
        &["init", "--quiet", "--initial-branch=fixture"],
    )?;
    let mut parent = synthetic_sjs_rcx_request().map_err(|error| error.to_string())?;
    parent.input_class = SjsRcxInputClass::SuppliedUnobservedRepositorySlice;
    parent.scope.repository = path_text(&repository_root)?.replace('\\', "/");
    parent.scope.branch = "fixture".to_owned();
    for (index, record) in parent.records.iter().enumerate() {
        let bytes = format!("supplied fixture content {}", index + 1).into_bytes();
        if sha256_bytes(&bytes) != record.content_digest {
            return Err(format!(
                "synthetic parent content digest differs at {}",
                record.locator
            ));
        }
        let path = repository_root.join(&record.locator);
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| "fixture locator lacks parent".to_owned())?,
        )
        .map_err(|error| format!("fixture parent creation failed: {error}"))?;
        fs::write(&path, bytes).map_err(|error| format!("fixture blob write failed: {error}"))?;
    }
    run_fixture_git(&repository_root, &git_executable, &["add", "--all"])?;
    run_fixture_git(
        &repository_root,
        &git_executable,
        &[
            "-c",
            "user.name=Cantor Fixture",
            "-c",
            "user.email=cantor-fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "deterministic fixture",
        ],
    )?;

    let expected_head = one_git_line(run_fixture_git(
        &repository_root,
        &git_executable,
        &["rev-parse", "HEAD"],
    )?)?;
    let object_format = one_git_line(run_fixture_git(
        &repository_root,
        &git_executable,
        &["rev-parse", "--show-object-format"],
    )?)?;
    let commit_raw = run_fixture_git(
        &repository_root,
        &git_executable,
        &["cat-file", "commit", "HEAD"],
    )?;
    parent.scope.commit_digest = sha256_bytes(&commit_raw);
    let parent = seal_sjs_rcx_request(parent).map_err(|error| error.to_string())?;

    let git_metadata = fs::metadata(&git_executable)
        .map_err(|error| format!("Git executable metadata failed: {error}"))?;
    if git_metadata.len() == 0 || git_metadata.len() > 67_108_864 {
        return Err("Git executable byte length differs".to_owned());
    }
    let git_bytes = fs::read(&git_executable)
        .map_err(|error| format!("Git executable read failed: {error}"))?;
    if git_bytes.len() as u64 != git_metadata.len() {
        return Err("Git executable changed during fixture request formation".to_owned());
    }
    let request = seal_sjs_rso_request(SjsRsoRequest {
        profile: SJS_RSO_REQUEST_PROFILE.to_owned(),
        request_id: semantic_id("request:85000000-0000-4000-8000-000000000001")?,
        run_id: semantic_id("run:85000000-0000-4000-8000-000000000002")?,
        receipt_id: semantic_id("receipt:85000000-0000-4000-8000-000000000003")?,
        input_class: SjsRsoInputClass::DisposableLocalGitFixture,
        canonical_uuid: SJS_RSO_CANONICAL_UUID.to_owned(),
        signature_uuid: SJS_RSO_SIGNATURE_UUID.to_owned(),
        source_snapshot_uuid: SJS_RSO_SOURCE_UUID.to_owned(),
        parent_canonical_uuid: cantor_core::SJS_RCX_CANONICAL_UUID.to_owned(),
        parent_completion_signature_uuid: SJS_RSO_PARENT_COMPLETION_UUID.to_owned(),
        parent_request: parent,
        repository_root: path_text(&repository_root)?,
        git_executable: path_text(&git_executable)?,
        expected_git_sha256: sha256_bytes(&git_bytes),
        expected_branch_ref: "refs/heads/fixture".to_owned(),
        expected_head,
        object_format,
        limits: SjsRsoLimits {
            maximum_git_commands: 23,
            maximum_command_milliseconds: 10_000,
            maximum_stdout_bytes: 8_388_608,
            maximum_stderr_bytes: 1_048_576,
            maximum_executable_bytes: 67_108_864,
            maximum_index_bytes: 67_108_864,
            maximum_commit_bytes: 4_194_304,
            maximum_blob_bytes: 8_388_608,
            maximum_total_blob_bytes: 67_108_864,
            maximum_path_bytes: 4_096,
            maximum_evidence_bytes: 8_388_608,
        },
        evidence_refs: BTreeSet::new(),
        non_authority: SJS_RSO_NON_AUTHORITY.to_owned(),
        request_digest: ContentDigest {
            algorithm: "sha256".to_owned(),
            value: "0".repeat(64),
        },
    })
    .map_err(|error| error.to_string())?;

    let dirty_path = repository_root.join(&request.parent_request.records[0].locator);
    fs::write(&dirty_path, b"dirty working tree contrast")
        .map_err(|error| format!("dirty contrast write failed: {error}"))?;

    let first_runner = prepare_sjs_rso_git_runner(&request).map_err(|error| error.to_string())?;
    let (receipt, verification) =
        compile_sjs_rso_commit_tree_receipt(first_runner).map_err(|error| error.to_string())?;
    let second_runner = prepare_sjs_rso_git_runner(&request).map_err(|error| error.to_string())?;
    let (replay_receipt, replay_verification) =
        compile_sjs_rso_commit_tree_receipt(second_runner).map_err(|error| error.to_string())?;
    let bundle = build_sjs_rso_evidence_bundle(
        &request,
        &receipt,
        &verification,
        &replay_receipt,
        &replay_verification,
    )
    .map_err(|error| error.to_string())?;
    let output =
        to_sjs_rso_evidence_bundle_machine_form(&bundle).map_err(|error| error.to_string())?;
    println!("{output}");
    Ok(())
}

fn require_empty_fixture_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() || !root.is_dir() {
        return Err("fixture repository root must be an existing absolute directory".to_owned());
    }
    let mut entries = fs::read_dir(root)
        .map_err(|error| format!("fixture repository root read failed: {error}"))?;
    if entries.next().is_some() {
        return Err("fixture repository root must be empty".to_owned());
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "fixture path is not UTF-8".to_owned())
}

fn semantic_id(value: &str) -> Result<SemanticId, String> {
    SemanticId::new(value).map_err(|error| error.to_string())
}

fn one_git_line(bytes: Vec<u8>) -> Result<String, String> {
    let value =
        String::from_utf8(bytes).map_err(|_| "fixture Git output is not UTF-8".to_owned())?;
    let body = value
        .strip_suffix('\n')
        .ok_or_else(|| "fixture Git output lacks terminal LF".to_owned())?;
    if body.is_empty() || body.contains(['\0', '\r', '\n']) {
        return Err("fixture Git output is not one exact line".to_owned());
    }
    Ok(body.to_owned())
}

fn run_fixture_git(
    root: &Path,
    git_executable: &Path,
    arguments: &[&str],
) -> Result<Vec<u8>, String> {
    let output = Command::new(git_executable)
        .args(arguments)
        .current_dir(root)
        .env_clear()
        .env("GIT_ALLOW_PROTOCOL", "none")
        .env("GIT_CONFIG_GLOBAL", "NUL")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "NUL")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", root)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("SYSTEMROOT", r"C:\Windows")
        .env("WINDIR", r"C:\Windows")
        .output()
        .map_err(|error| format!("fixture Git launch failed: {error}"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "fixture Git failed exit={:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}
