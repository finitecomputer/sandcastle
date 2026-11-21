//! `sandcastle-nitro-spike`: the Nitro spike's driver (docs/nitro-spike.md).
//! The operator checks a document with the verifier's own `nitro-verify`.

use std::process::ExitCode;

const USAGE: &str = "usage: sandcastle-nitro-spike initrd --probe <nitro-probe> --out <initrd>
  on the parent, as root (docs/nitro-spike.md):
       sandcastle-nitro-spike boot|canary|attest|release --kernel <Image> --initrd <initrd> [--cmdline <args>] [--mode confidential|direct] [--overcommit true] [--debug true] [--vcpus N] [--mem-mib N] ...";

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("initrd") => run_initrd(&args[1..]),
        #[cfg(target_os = "linux")]
        Some(s @ ("boot" | "canary" | "attest" | "release" | "agent" | "network" | "lives" | "conformance" | "forged" | "hold" | "exec" | "density" | "busy")) => {
            use sandcastle_nitro_spike::{computer, scenarios};
            let rest = &args[1..];
            let r = match s {
                "boot" => scenarios::boot(rest),
                "canary" => scenarios::canary(rest),
                "attest" => scenarios::attest(rest),
                "release" => scenarios::release(rest),
                "agent" => computer::agent(rest),
                "network" => computer::network(rest),
                "lives" => computer::lives(rest),
                "conformance" => computer::conformance(rest),
                "hold" => computer::hold(rest),
                "exec" => computer::exec(rest),
                "density" => computer::density(rest),
                "busy" => computer::busy(rest),
                _ => computer::forged(rest),
            };
            r.map(|v| println!("{}", serde_json::to_string_pretty(&v).expect("JSON"))).map_err(|e| e.to_string())
        }
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sandcastle-nitro-spike: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_initrd(args: &[String]) -> Result<(), String> {
    // `--init` (sandcastle-guest) or `--probe` (the probe): the initrd's /init.
    let probe = flag(args, "--init").or_else(|| flag(args, "--probe")).ok_or("--init is required")?;
    let out = flag(args, "--out").ok_or("--out is required")?;
    let init = std::fs::read(probe).map_err(|e| format!("{probe}: {e}"))?;
    let archive = sandcastle_nitro_spike::initrd::probe(&init);
    std::fs::write(out, &archive).map_err(|e| format!("{out}: {e}"))?;
    println!("{} {} bytes, sha256 {}", out, archive.len(), hex::encode(sandcastle_nitro_attest::sha256(&archive)));
    Ok(())
}
