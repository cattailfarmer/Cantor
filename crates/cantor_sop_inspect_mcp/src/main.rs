use std::{
    io::{self, Write},
    process::ExitCode,
    time::Duration,
};

use cantor_sop_inspect_mcp::{PUBLIC_HOST_FAULT, SHUTDOWN_MILLISECONDS, run_io};

#[cfg(windows)]
fn inherited_streams() -> io::Result<(std::fs::File, std::fs::File)> {
    use std::os::windows::io::AsHandle;
    Ok((
        std::io::stdin().as_handle().try_clone_to_owned()?.into(),
        std::io::stdout().as_handle().try_clone_to_owned()?.into(),
    ))
}
#[cfg(unix)]
fn inherited_streams() -> io::Result<(std::fs::File, std::fs::File)> {
    use std::os::fd::AsFd;
    Ok((
        std::io::stdin().as_fd().try_clone_to_owned()?.into(),
        std::io::stdout().as_fd().try_clone_to_owned()?.into(),
    ))
}
#[cfg(not(any(windows, unix)))]
fn inherited_streams() -> io::Result<(std::fs::File, std::fs::File)> {
    Err(io::Error::other("unsupported inherited streams"))
}

fn run() -> Result<(), ()> {
    if std::env::args_os().nth(1).is_some() {
        return Err(());
    }
    let (read, write) = inherited_streams().map_err(|_| ())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build()
        .map_err(|_| ())?;
    let result = runtime.block_on(run_io(
        tokio::fs::File::from_std(read),
        tokio::fs::File::from_std(write),
    ));
    // Blocking inherited-stream work may persist until this standalone process
    // exits. Never let default runtime Drop wait indefinitely for those workers.
    runtime.shutdown_timeout(Duration::from_millis(SHUTDOWN_MILLISECONDS));
    result.map(|_| ()).map_err(|_| ())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            let _ = std::io::stderr().lock().write_all(PUBLIC_HOST_FAULT);
            ExitCode::from(2)
        }
    }
}
