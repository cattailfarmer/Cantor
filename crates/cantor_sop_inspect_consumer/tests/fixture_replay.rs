mod support;

use std::{io, path::PathBuf, process::Stdio, time::Duration};

use cantor_sop_inspect_consumer::{MAX_STDERR_BYTES, Transcript, validate_receipt, verify};
use cantor_sop_inspect_wire::MAX_WIRE_RESPONSE_BYTES;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};

const GOLDEN: &[u8] =
    include_bytes!("../../../fixtures/semantic_inspection_consumer_handoff_p0/fixtures.json");
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);

fn host_binary() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    let profile_directory = executable.parent().unwrap().parent().unwrap();
    profile_directory.join(if cfg!(windows) {
        "cantor-sop-inspect-stdio.exe"
    } else {
        "cantor-sop-inspect-stdio"
    })
}

async fn capture_limited<R: AsyncRead + Unpin>(reader: R, maximum: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "capture bound exceeded",
        ));
    }
    Ok(bytes)
}

async fn exchange(request: &[u8]) -> io::Result<(i32, Vec<u8>, Vec<u8>)> {
    let mut child = Command::new(host_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    let error = child.stderr.take().unwrap();
    let result = timeout(EXCHANGE_TIMEOUT, async {
        tokio::try_join!(
            async {
                input.write_all(request).await?;
                input.shutdown().await?;
                drop(input);
                Ok::<_, io::Error>(())
            },
            capture_limited(output, MAX_WIRE_RESPONSE_BYTES),
            capture_limited(error, MAX_STDERR_BYTES),
            child.wait(),
        )
    })
    .await;
    match result {
        Ok(Ok(((), output, error, status))) => Ok((
            status
                .code()
                .ok_or_else(|| io::Error::other("host terminated without an exit code"))?,
            output,
            error,
        )),
        failure => {
            // Cancellation closes taken pipes; kill-on-drop also covers an
            // abandoned cleanup. The signed host does not spawn descendants.
            let _ = timeout(CLEANUP_TIMEOUT, child.kill()).await;
            let _ = timeout(CLEANUP_TIMEOUT, child.wait()).await;
            match failure {
                Ok(Err(error)) => Err(error),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "host exchange timed out",
                )),
                Ok(Ok(_)) => unreachable!(),
            }
        }
    }
}

#[test]
fn golden_bundle_is_byte_identical_to_deterministic_regeneration() {
    assert_eq!(support::bundle_bytes(), GOLDEN);
    let bundle: support::FixtureBundle = serde_json::from_slice(GOLDEN).unwrap();
    assert_eq!(bundle.profile, support::BUNDLE_PROFILE);
    assert_eq!(bundle.cases.len(), 8);
    let ids: std::collections::BTreeSet<_> = bundle.cases.iter().map(|case| &case.id).collect();
    assert_eq!(ids.len(), 8);
}

#[tokio::test(flavor = "current_thread")]
async fn all_eight_golden_cases_match_fresh_host_processes_and_receipts() {
    let bundle: support::FixtureBundle = serde_json::from_slice(GOLDEN).unwrap();
    for fixture in bundle.cases {
        let (exit_code, stdout, stderr) = exchange(fixture.request.as_bytes()).await.unwrap();
        assert_eq!(exit_code, fixture.exit_code, "{} exit", fixture.id);
        assert_eq!(stdout, fixture.stdout.as_bytes(), "{} stdout", fixture.id);
        assert_eq!(stderr, fixture.stderr.as_bytes(), "{} stderr", fixture.id);
        let transcript = Transcript {
            exit_code,
            stdout: &stdout,
            stderr: &stderr,
        };
        assert_eq!(
            verify(fixture.request.as_bytes(), transcript).unwrap(),
            fixture.receipt
        );
        validate_receipt(fixture.request.as_bytes(), transcript, &fixture.receipt).unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn output_capture_accepts_exact_limit_and_refuses_maximum_plus_one() {
    assert_eq!(
        capture_limited(&b"12345678"[..], 8).await.unwrap(),
        b"12345678"
    );
    assert_eq!(
        capture_limited(&b"123456789more unread data"[..], 8)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_eof_exchange_is_timed_out_killed_and_reaped() {
    let mut child = Command::new(host_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    // Tokio's Child::wait closes stdin still owned by Child. Take the pipe out
    // so this adversary genuinely withholds EOF until after cleanup.
    let held_input = child.stdin.take().unwrap();
    assert!(
        timeout(Duration::from_millis(30), child.wait())
            .await
            .is_err()
    );
    timeout(CLEANUP_TIMEOUT, child.kill())
        .await
        .unwrap()
        .unwrap();
    let status = timeout(CLEANUP_TIMEOUT, child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success());
    drop(held_input);
}
