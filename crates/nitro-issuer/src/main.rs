//! `nitro-issuer`: a home's wildcard certificate, for its own key, by ACME
//! DNS-01 on the operator's side (docs/nitro-issuer.md).
//!
//! A home makes its key and a CSR for `<home>.<suffix>` and
//! `*.<home>.<suffix>` (`csr`); the key never leaves it. The issuer, outside
//! the home and holding the zone's DNS token, orders exactly those two names
//! (from `--home`, never from the CSR) from Let's Encrypt with the issuer's
//! own account, proves them by TXT records at `_acme-challenge.<home>.<suffix>`
//! (removed after, whatever the outcome), and finalizes with the home's CSR
//! (`issue`). CAA on the suffix names that account alone (`caa`). The home
//! checks what comes back against its key, its names and its expiry before
//! it serves it (`verify`).
//!
//! ```text
//! nitro-issuer account --state <dir> [--staging]
//! nitro-issuer issue --state <dir> --zone <zone> --token-file <file> --suffix <suffix> --home <name> --csr <csr.pem> --out <chain.pem> [--staging]
//! nitro-issuer caa --zone <zone> --token-file <file> --suffix <suffix> --account <uri> [--account <uri>]...
//! nitro-issuer csr --key <key.pem> --names <a,b> --out <csr.pem>
//! nitro-issuer verify --cert <chain.pem> (--key <key.pem> | --csr <csr.pem>) --names <a,b> [--renew-days <n>]
//! ```
//!
//! `verify` exits 0 when the certificate serves, 3 when it serves but its
//! renewal is due, 1 when it does not serve; the home checks it against its
//! key, the issuer (which has no key) against the CSR's.
//!
//! The home's build (`--no-default-features`) is `csr` and `verify` alone:
//! the ACME and DNS half (`issuer`, the default feature) is never in a home.

#[cfg(feature = "issuer")]
mod issuer;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

type Result<T> = std::result::Result<T, String>;

/// Renewal is due this many days before expiry, by default.
const RENEW_DAYS: i64 = 30;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("nitro-issuer: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode> {
    match args.first().map(String::as_str) {
        Some("csr") => {
            let names = list(&need(args, "--names")?);
            let pem = csr(Path::new(&need(args, "--key")?), &names)?;
            write_atomic(Path::new(&need(args, "--out")?), pem.as_bytes(), 0o644)?;
            Ok(ExitCode::SUCCESS)
        }
        Some("verify") => {
            let names = list(&need(args, "--names")?);
            let days = flag(args, "--renew-days").map(|d| d.parse::<i64>().map_err(|e| format!("--renew-days: {e}"))).transpose()?.unwrap_or(RENEW_DAYS);
            let chain = read(&need(args, "--cert")?, "--cert")?;
            let public = match (flag(args, "--key"), flag(args, "--csr")) {
                (Some(key), None) => key_public(&read(&key, "--key")?)?,
                (None, Some(csr)) => csr_public(&read(&csr, "--csr")?)?,
                _ => return Err("verify: --key or --csr, one of them".into()),
            };
            Ok(match verify(&chain, &public, &names, days, time::OffsetDateTime::now_utc()) {
                Ok(Verdict::Serves { days_left }) => {
                    eprintln!("nitro-issuer: serves, {days_left} days left");
                    ExitCode::SUCCESS
                }
                Ok(Verdict::RenewDue { days_left }) => {
                    eprintln!("nitro-issuer: serves, and its renewal is due ({days_left} days left)");
                    ExitCode::from(3)
                }
                Err(why) => {
                    eprintln!("nitro-issuer: does not serve: {why}");
                    ExitCode::FAILURE
                }
            })
        }
        #[cfg(feature = "issuer")]
        Some("account" | "issue" | "caa") => issuer::run(args),
        #[cfg(not(feature = "issuer"))]
        Some("account" | "issue" | "caa") => Err("the home's build is csr and verify alone (the issuer's has the `issuer` feature)".into()),
        _ => Err("account, issue, caa, csr or verify (the source's head says how)".into()),
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn need(args: &[String], name: &str) -> Result<String> {
    flag(args, name).ok_or_else(|| format!("{name} is required"))
}

fn read(path: &str, what: &str) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| format!("{what} {path}: {e}"))
}

fn list(names: &str) -> Vec<String> {
    names.split(',').map(str::to_string).collect()
}

/// The home's CSR for `names`, its key (P-256) made at `key` if there is
/// none (owner-only), and kept: the key never leaves the home.
fn csr(key: &Path, names: &[String]) -> Result<String> {
    let pair = match std::fs::read_to_string(key) {
        Ok(pem) => rcgen::KeyPair::from_pem(&pem).map_err(|e| format!("{}: {e}", key.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
            write_atomic(key, pair.serialize_pem().as_bytes(), 0o600)?;
            pair
        }
        Err(e) => return Err(format!("{}: {e}", key.display())),
    };
    let mut params = rcgen::CertificateParams::new(names.to_vec()).map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serialize_request(&pair).and_then(|r| r.pem()).map_err(|e| e.to_string())
}

fn csr_pem(pem: &str) -> Result<x509_parser::pem::Pem> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| format!("the CSR's PEM: {e}"))?;
    if p.label != "CERTIFICATE REQUEST" {
        return Err(format!("a CSR, not a {}", p.label));
    }
    Ok(p)
}

/// The public key a CSR asks for (its SubjectPublicKeyInfo's bits).
fn csr_public(pem: &str) -> Result<Vec<u8>> {
    let p = csr_pem(pem)?;
    let (_, request) = x509_parser::certification_request::X509CertificationRequest::from_der(&p.contents).map_err(|e| format!("the CSR: {e}"))?;
    Ok(request.certification_request_info.subject_pki.subject_public_key.data.to_vec())
}

/// A key's public half, as a certificate holds it.
fn key_public(pem: &str) -> Result<Vec<u8>> {
    Ok(rcgen::KeyPair::from_pem(pem).map_err(|e| format!("the key: {e}"))?.public_key_raw().to_vec())
}

fn dns_names(general: &[GeneralName]) -> Vec<String> {
    general.iter().filter_map(|g| if let GeneralName::DNSName(n) = g { Some(n.to_string()) } else { None }).collect()
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Serves { days_left: i64 },
    RenewDue { days_left: i64 },
}

/// Whether `chain`'s first certificate serves for `public` (a key's public
/// half) and `names` now:
/// its public key the key's, its names exactly `names`, valid now; and
/// whether its renewal is due (`renew_days` before it ends). Its chain to a
/// root is each client's to check, as for any certificate.
fn verify(chain: &str, public: &[u8], names: &[String], renew_days: i64, now: time::OffsetDateTime) -> Result<Verdict> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain.as_bytes()).map_err(|e| format!("the chain's PEM: {e}"))?;
    let cert = pem.parse_x509().map_err(|e| format!("the certificate: {e}"))?;
    if cert.public_key().subject_public_key.data.as_ref() != public {
        return Err("its public key is not this key's".into());
    }
    let mut got = cert.subject_alternative_name().map_err(|e| format!("its names: {e}"))?.map(|san| dns_names(&san.value.general_names)).unwrap_or_default();
    let mut want = names.to_vec();
    got.sort();
    want.sort();
    if got != want {
        return Err(format!("its names are {got:?}, not {want:?}"));
    }
    let validity = cert.validity();
    let (start, end) = (validity.not_before.to_datetime(), validity.not_after.to_datetime());
    if now < start || now >= end {
        return Err(format!("valid from {start} to {end}, not now"));
    }
    let days_left = (end - now).whole_days();
    Ok(if days_left < renew_days { Verdict::RenewDue { days_left } } else { Verdict::Serves { days_left } })
}

/// Whole or not at all, with `mode`.
fn write_atomic(at: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let part: PathBuf = at.with_extension("part");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(&part).map_err(|e| format!("{}: {e}", part.display()))?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", part.display()))?;
    std::fs::rename(&part, at).map_err(|e| format!("{}: {e}", at.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate for `names` and `key`, valid from a day ago for `days`
    /// more, signed by a CA of the test's own.
    pub(crate) fn certificate(key: &rcgen::KeyPair, names: &[String], days: i64) -> String {
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let mut p = rcgen::CertificateParams::new(names.to_vec()).unwrap();
        p.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        p.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days) + time::Duration::hours(1);
        p.signed_by(key, &issuer).unwrap().pem()
    }

    pub(crate) fn scratch(what: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nitro-issuer-{what}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Goal: the home makes its key once and keeps it, owner-only; its CSR
    // asks for that key; a certificate serves only for that key (checked
    // from the key or from the CSR alike), exactly those names, and now,
    // and says when its renewal is due.
    #[test]
    fn a_homes_key_csr_and_what_serves() {
        let dir = scratch("serves");
        let key_path = dir.join("key.pem");
        let home = vec!["test1.homes.example".to_string(), "*.test1.homes.example".to_string()];
        let first = csr(&key_path, &home).unwrap();
        let key = std::fs::read_to_string(&key_path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777, 0o600, "the key is the home's alone");
        let second = csr(&key_path, &home).unwrap();
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), key, "the same key, kept");
        let public = key_public(&key).unwrap();
        assert_eq!(csr_public(&first).unwrap(), public, "the CSR asks for the home's own key");
        assert_eq!(csr_public(&second).unwrap(), public);
        assert!(csr_public("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n").is_err());

        let pair = rcgen::KeyPair::from_pem(&key).unwrap();
        let now = time::OffsetDateTime::now_utc();
        assert_eq!(verify(&certificate(&pair, &home, 89), &public, &home, 30, now), Ok(Verdict::Serves { days_left: 89 }));
        assert_eq!(verify(&certificate(&pair, &home, 10), &public, &home, 30, now), Ok(Verdict::RenewDue { days_left: 10 }));
        let stranger = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        assert!(verify(&certificate(&stranger, &home, 89), &public, &home, 30, now).unwrap_err().contains("not this key's"));
        assert!(verify(&certificate(&pair, &home[..1], 89), &public, &home, 30, now).unwrap_err().contains("its names"));
        assert!(verify(&certificate(&pair, &home, 89), &public, &home, 30, now + time::Duration::days(100)).unwrap_err().contains("not now"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
