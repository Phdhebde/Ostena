//! The TOTP code an authenticator application would show, for scripts and
//! demonstrations (`lab/demo-m1.sh`): reads the base32 secret shown by
//! `ostena core user totp-enroll` on standard input, prints the six-digit
//! code of the current step, or of the step `OFFSET` steps away.
//!
//! Never part of a release binary: an example of `ostena-crypto`, so the
//! computation stays in the only crate allowed to do cryptography.
//!
//! `cargo run -p ostena-crypto --example totp_code [-- [--algorithm sha1|sha256] [--offset N]] < secret`

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "command-line example: prints its result"
)]

use std::io::{self, BufRead};
use std::process::ExitCode;

use ostena_common::secret::SecretBytes;
use ostena_crypto::totp::{TotpAlgorithm, TotpSecret, step_at};

/// RFC 4648 base32, upper case, with or without padding.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.trim_end_matches('=').bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

fn run() -> Result<String, String> {
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut offset: i64 = 0;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--algorithm" => {
                let value = args.next().ok_or("--algorithm sans valeur")?;
                algorithm = TotpAlgorithm::parse(&value).ok_or("algorithme : sha1 ou sha256")?;
            }
            "--offset" => {
                offset = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--offset : un entier attendu")?;
            }
            other => return Err(format!("argument inconnu : {other}")),
        }
    }
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("entrée standard : {e}"))?;
    let bytes = base32_decode(line.trim()).ok_or("secret base32 illisible")?;
    let secret =
        TotpSecret::from_bytes(algorithm, SecretBytes::from(bytes)).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let step = step_at(now)
        .checked_add_signed(offset)
        .ok_or("pas hors bornes")?;
    // SECRET-EXPOSURE: the example prints the code, as an authenticator shows it.
    #[expect(clippy::disallowed_methods)]
    let code = secret.code(step).expose_secret().to_owned();
    Ok(code)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => {
            println!("{code}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("totp_code : {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn decodes_base32() {
        // RFC 4648 section 10.
        assert_eq!(super::base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(super::base32_decode("MZXW6YQ=").unwrap(), b"foob");
        assert!(super::base32_decode("mzxw").is_none());
    }
}
