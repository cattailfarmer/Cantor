//! One-shot bounded stdio host for semantic inspection wire requests.

use std::{
    env,
    io::{self, Read, Write},
    process::ExitCode,
};

use cantor_sop_inspect_wire::{
    MAX_WIRE_REQUEST_BYTES, MAX_WIRE_RESPONSE_BYTES, parse_request, respond,
};

const BUFFER_BYTES: usize = 8_192;
const PUBLIC_FAULT: &[u8] = b"cantor_stdio_host_refused\n";
const REFUSED_EXIT: u8 = 2;

fn main() -> ExitCode {
    if env::args_os().len() != 1 {
        return public_fault();
    }

    let request = match read_request(io::stdin().lock()) {
        Ok(request) => request,
        Err(()) => return public_fault(),
    };
    if parse_request(&request).is_err() {
        return public_fault();
    }
    let response = match respond(&request) {
        Ok(response) if response.len() <= MAX_WIRE_RESPONSE_BYTES => response,
        Ok(_) | Err(_) => return public_fault(),
    };

    let mut stdout = io::stdout().lock();
    if stdout.write_all(&response).is_err() || stdout.flush().is_err() {
        return ExitCode::from(REFUSED_EXIT);
    }
    ExitCode::SUCCESS
}

fn read_request(mut input: impl Read) -> Result<Vec<u8>, ()> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; BUFFER_BYTES];
    loop {
        let remaining = MAX_WIRE_REQUEST_BYTES
            .saturating_add(1)
            .saturating_sub(request.len());
        if remaining == 0 {
            return Err(());
        }
        let read = input
            .read(&mut buffer[..remaining.min(BUFFER_BYTES)])
            .map_err(|_| ())?;
        if read == 0 {
            return if request.is_empty() {
                Err(())
            } else {
                Ok(request)
            };
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > MAX_WIRE_REQUEST_BYTES {
            return Err(());
        }
    }
}

fn public_fault() -> ExitCode {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(PUBLIC_FAULT);
    let _ = stderr.flush();
    ExitCode::from(REFUSED_EXIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;

    struct RefusingReader;

    impl Read for RefusingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(Error::other("test-only read refusal"))
        }
    }

    #[test]
    fn bounded_reader_accepts_exact_limit_and_refuses_limit_plus_one() {
        assert_eq!(read_request(&[b'x'; 8][..]).unwrap(), vec![b'x'; 8]);
        assert!(read_request(&vec![b'x'; MAX_WIRE_REQUEST_BYTES + 1][..]).is_err());
    }

    #[test]
    fn bounded_reader_refuses_empty_input() {
        assert!(read_request(&[][..]).is_err());
    }

    #[test]
    fn bounded_reader_refuses_read_failure() {
        assert!(read_request(RefusingReader).is_err());
    }
}
