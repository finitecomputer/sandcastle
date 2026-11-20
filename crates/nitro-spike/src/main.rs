//! `sandcastle-nitro-spike`: the Nitro spike's driver (docs/nitro-spike.md).
//!
//! `verify --document <file> --nonce <hex> [--now-ms <ms>] [--reveal-parent]`
//! checks an attestation document on the operator's machine, down to AWS's
//! pinned root, and prints what it attests as one JSON object. PCR3 (a
//! hash of the parent's role ARN), PCR4 (of its instance id) and the
//! module id name the project and the instance, so they are redacted
//! unless asked for: the evidence goes into a public repository, and an
//! ARN's hash is open to a search over the project's twelve digits.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::process::ExitCode;

use sandcastle_nitro_attest::{verify, Trust, DOCUMENT_BYTES_MAX};
use serde::Serialize;

/// PCRs that name the parent rather than the image.
const PARENT_PCRS: [u8; 2] = [3, 4];
const REDACTED: &str = "<redacted: names the parent>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("verify") => run_verify(&args[1..]),
        _ => Err("usage: sandcastle-nitro-spike verify --document <file> --nonce <hex> [--now-ms <ms>] [--reveal-parent]".to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sandcastle-nitro-spike: {e}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Serialize)]
struct Verified {
    verified: bool,
    root_sha256: String,
    module_id: String,
    timestamp_ms: u64,
    now_ms: u64,
    nonce: String,
    public_key_sha256: Option<String>,
    user_data_bytes: Option<usize>,
    /// Hex by index, each 48 bytes.
    pcrs: BTreeMap<u8, String>,
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--document").ok_or("--document is required")?;
    let nonce = hex::decode(flag(args, "--nonce").ok_or("--nonce is required")?).map_err(|e| format!("--nonce: {e}"))?;
    let now_ms = match flag(args, "--now-ms") {
        Some(ms) => ms.parse::<u64>().map_err(|e| format!("--now-ms: {e}"))?,
        None => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_millis() as u64,
    };
    let reveal = args.iter().any(|a| a == "--reveal-parent");
    // Read at most one byte past the limit, so a large file is refused
    // without being read whole.
    let mut document = Vec::with_capacity(DOCUMENT_BYTES_MAX + 1);
    std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?.take(DOCUMENT_BYTES_MAX as u64 + 1).read_to_end(&mut document).map_err(|e| format!("{path}: {e}"))?;
    let trust = Trust::aws_nitro_enclaves_root_g1();
    let a = verify(&trust, &document, &nonce, now_ms).map_err(|e| format!("refused: {e}"))?;
    let sha256 = |b: &[u8]| hex::encode(sandcastle_nitro_attest::sha256(b));
    let out = Verified {
        verified: true,
        root_sha256: hex::encode(trust.root_sha256()),
        module_id: if reveal { a.module_id.clone() } else { REDACTED.into() },
        timestamp_ms: a.timestamp_ms,
        now_ms,
        nonce: hex::encode(&nonce),
        public_key_sha256: a.public_key.as_deref().map(sha256),
        user_data_bytes: a.user_data.as_ref().map(Vec::len),
        pcrs: a.pcrs.iter().map(|(i, v)| (*i, if reveal || !PARENT_PCRS.contains(i) { hex::encode(v) } else { REDACTED.into() })).collect(),
    };
    println!("{}", serde_json::to_string_pretty(&out).expect("plain data serializes"));
    Ok(())
}
