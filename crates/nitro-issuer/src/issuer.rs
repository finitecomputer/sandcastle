//! The issuer's half (docs/nitro-issuer.md): its ACME account, an order
//! proved by DNS-01 through the zone's API, and the suffix's CAA. Never in
//! a home's build.

use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use instant_acme::{Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy};
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

use super::{csr_pem, dns_names, need, read, write_atomic, Result};

/// How long a new TXT record is given before Let's Encrypt is told to look:
/// Let's Encrypt asks the zone's authoritative servers, which answer within
/// seconds of the API's write.
const PROPAGATION: Duration = Duration::from_secs(15);

/// How long an order may take to be ready, and then to give its certificate.
const ORDER_WAIT: Duration = Duration::from_secs(180);

/// A record's time to live.
const TTL: u32 = 60;

/// What the issuer's records say they are.
const NOTE: &str = "Nitro home certificate (nitro-issuer)";

/// A home's name, at most: one DNS label of its own.
const HOME_BYTES_MAX: usize = 32;

/// The zone's records of one type the issuer reads at once, at most.
const RECORDS_MAX: usize = 1000;

pub fn run(args: &[String]) -> Result<ExitCode> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| format!("a runtime: {e}"))?;
    rt.block_on(async {
        let staging = args.iter().any(|a| a == "--staging");
        match args.first().map(String::as_str) {
            Some("account") => {
                let account = account(Path::new(&need(args, "--state")?), staging).await?;
                println!("{}", account.id());
                Ok(ExitCode::SUCCESS)
            }
            Some("issue") => {
                let names = names(&need(args, "--home")?, &need(args, "--suffix")?)?;
                let csr = csr_der(&read(&need(args, "--csr")?, "--csr")?, &names)?;
                let dns = Dns::open(&need(args, "--zone")?, Path::new(&need(args, "--token-file")?)).await?;
                let account = account(Path::new(&need(args, "--state")?), staging).await?;
                let (chain, left) = issue(&account, &dns, &names, &csr).await;
                write_atomic(Path::new(&need(args, "--out")?), chain?.as_bytes(), 0o644)?;
                eprintln!("nitro-issuer: {} and {}: issued", names[0], names[1]);
                if left > 0 {
                    eprintln!("nitro-issuer: {left} challenge record(s) at {} left: `clean` removes them", challenge_name(&names[0]));
                    return Ok(ExitCode::from(CHALLENGE_LEFT));
                }
                Ok(ExitCode::SUCCESS)
            }
            Some("clean") => {
                let names = names(&need(args, "--home")?, &need(args, "--suffix")?)?;
                let dns = Dns::open(&need(args, "--zone")?, Path::new(&need(args, "--token-file")?)).await?;
                let at = challenge_name(&names[0]);
                let gone = clear(&dns, &at).await?;
                eprintln!("nitro-issuer: {gone} challenge record(s) at {at} removed");
                Ok(ExitCode::SUCCESS)
            }
            Some("caa") => {
                let dns = Dns::open(&need(args, "--zone")?, Path::new(&need(args, "--token-file")?)).await?;
                caa(&dns, &need(args, "--suffix")?, &flags(args, "--account")).await?;
                Ok(ExitCode::SUCCESS)
            }
            _ => Err("account, issue, clean or caa".into()),
        }
    })
}

fn flags(args: &[String], name: &str) -> Vec<String> {
    args.windows(2).filter(|w| w[0] == name).map(|w| w[1].clone()).collect()
}

/// A home's two names: its own and its fragments' wildcard.
fn names(home: &str, suffix: &str) -> Result<[String; 2]> {
    let label = |l: &str, max: usize| !l.is_empty() && l.len() <= max && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !l.starts_with('-') && !l.ends_with('-');
    if !label(home, HOME_BYTES_MAX) {
        return Err(format!("{home:?}: a home's name is one DNS label of 1 to {HOME_BYTES_MAX} of a-z, 0-9 and inner -"));
    }
    if !suffix.contains('.') || !suffix.split('.').all(|l| label(l, 63)) {
        return Err(format!("{suffix:?}: a suffix is a DNS name of two labels or more"));
    }
    Ok([format!("{home}.{suffix}"), format!("*.{home}.{suffix}")])
}

/// Where a name's DNS-01 answer goes: a wildcard's is its base's.
fn challenge_name(name: &str) -> String {
    format!("_acme-challenge.{}", name.strip_prefix("*.").unwrap_or(name))
}

/// The issuer's account: made once and kept in `state` (owner-only), its
/// URI what CAA names.
async fn account(state: &Path, staging: bool) -> Result<Account> {
    let file = state.join(if staging { "account-staging.json" } else { "account.json" });
    match std::fs::read(&file) {
        Ok(bytes) => {
            let credentials: AccountCredentials = serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", file.display()))?;
            return Account::builder().map_err(acme)?.from_credentials(credentials).await.map_err(acme);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", file.display())),
    }
    std::fs::create_dir_all(state).map_err(|e| format!("{}: {e}", state.display()))?;
    let directory = if staging { LetsEncrypt::Staging.url() } else { LetsEncrypt::Production.url() };
    let new = NewAccount { contact: &[], terms_of_service_agreed: true, only_return_existing: false };
    let (account, credentials) = Account::builder().map_err(acme)?.create(&new, directory.to_string(), None).await.map_err(acme)?;
    write_atomic(&file, &serde_json::to_vec(&credentials).expect("credentials serialize"), 0o600)?;
    eprintln!("nitro-issuer: a new account, kept in {}", file.display());
    Ok(account)
}

fn acme(e: instant_acme::Error) -> String {
    format!("ACME: {e}")
}

/// `issue`'s exit when the certificate was issued and written but a
/// challenge record could not be removed (`clean` removes it).
const CHALLENGE_LEFT: u8 = 4;
/// Tries at removing one challenge record, a second apart and doubling.
const DELETE_TRIES: u32 = 3;

/// Every TXT record at `at` (a home's challenge name, which the issuer
/// alone writes) removed: how many were.
async fn clear(dns: &Dns, at: &str) -> Result<usize> {
    let left = dns.records("TXT").await?.into_iter().filter(|r| r["name"].as_str() == Some(at)).collect::<Vec<_>>();
    for r in &left {
        dns.delete(r["id"].as_str().unwrap_or_default()).await?;
    }
    Ok(left.len())
}

/// One order for `names`, proved by DNS-01 and finalized with the home's
/// CSR: its certificate chain (PEM), and how many of the order's TXT
/// records could not be removed (each is tried, whatever the outcome).
async fn issue(account: &Account, dns: &Dns, names: &[String; 2], csr: &[u8]) -> (Result<String>, usize) {
    match order(account, dns, names, csr).await {
        Ok((outcome, made)) => {
            let at = challenge_name(&names[0]);
            let mut left = 0;
            for id in made {
                let mut tries = 0;
                while let Err(e) = dns.delete(&id).await {
                    tries += 1;
                    if tries == DELETE_TRIES {
                        eprintln!("nitro-issuer: a challenge record at {at} was not removed: {e}");
                        left += 1;
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1 << (tries - 1))).await;
                }
            }
            (outcome, left)
        }
        Err(e) => (Err(e), 0),
    }
}

/// The order itself: its outcome, and the records it made (to remove).
/// An error here is one before any record was made.
async fn order(account: &Account, dns: &Dns, names: &[String; 2], csr: &[u8]) -> Result<(Result<String>, Vec<String>)> {
    let identifiers: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await.map_err(acme)?;
    let mut answers = Vec::new();
    let mut authorizations = order.authorizations();
    // Bounded by the order's two names.
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization.map_err(acme)?;
        if authorization.status != AuthorizationStatus::Pending {
            continue;
        }
        let challenge = authorization.challenge(ChallengeType::Dns01).ok_or("the order offers no dns-01 challenge")?;
        answers.push(challenge.key_authorization().dns_value());
    }
    let at = challenge_name(&names[0]);
    // A run cut short leaves its records: the issuer owns this name, so they
    // go, and Let's Encrypt's resolvers are given a TTL to forget them (a
    // value they still hold fails the new order's check).
    let left = clear(dns, &at).await?;
    if left > 0 {
        eprintln!("nitro-issuer: {left} challenge record(s) of an earlier run at {at} removed; waiting {TTL} s");
        tokio::time::sleep(Duration::from_secs(TTL.into())).await;
    }
    let mut made = Vec::new();
    let outcome: Result<String> = async {
        for answer in &answers {
            made.push(dns.add_txt(&at, answer).await?);
        }
        if !answers.is_empty() {
            tokio::time::sleep(PROPAGATION).await;
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization = authorization.map_err(acme)?;
                if authorization.status != AuthorizationStatus::Pending {
                    continue;
                }
                let mut challenge = authorization.challenge(ChallengeType::Dns01).ok_or("the order offers no dns-01 challenge")?;
                challenge.set_ready().await.map_err(acme)?;
            }
        }
        let retries = RetryPolicy::new().timeout(ORDER_WAIT);
        let status = order.poll_ready(&retries).await.map_err(acme)?;
        if status != OrderStatus::Ready {
            // Let's Encrypt's reason, from each name's failed challenge
            let mut why = Vec::new();
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let authorization = authorization.map_err(acme)?;
                why.extend(authorization.challenges.iter().filter_map(|c| c.error.as_ref()).map(|p| p.detail.clone().unwrap_or_else(|| p.to_string())));
            }
            return Err(format!("the order is {status:?}, not ready: {}", if why.is_empty() { "no reason given".to_string() } else { why.join("; ") }));
        }
        order.finalize_csr(csr).await.map_err(acme)?;
        order.poll_certificate(&retries).await.map_err(acme)
    }
    .await;
    Ok((outcome, made))
}

/// CAA at `suffix` becomes exactly `accounts` at Let's Encrypt, for names
/// and wildcards, and every CAA record below the suffix goes: its names
/// inherit the suffix's. A name outside the suffix is never touched.
async fn caa(dns: &Dns, suffix: &str, accounts: &[String]) -> Result<()> {
    if accounts.is_empty() || accounts.iter().any(|a| !account_uri(a)) {
        return Err("--account: one or more Let's Encrypt account URIs".into());
    }
    names("x", suffix)?;
    let want = caa_records(accounts);
    let have = dns.records("CAA").await?;
    let (mut added, mut removed) = (0, 0);
    let (mut kept, mut gone) = (Vec::new(), Vec::new());
    for r in &have {
        let name = r["name"].as_str().unwrap_or_default();
        let tag_value = (r["data"]["tag"].as_str().unwrap_or_default().to_string(), r["data"]["value"].as_str().unwrap_or_default().to_string());
        match caa_fate(name, &tag_value, suffix, &want) {
            Fate::Keep => kept.push(tag_value),
            Fate::Remove => gone.push(r["id"].as_str().unwrap_or_default().to_string()),
            Fate::Outside => {}
        }
    }
    // the suffix's records first, then the rest removed: cut short at any
    // point, no name under the suffix is left without a CAA that names the
    // issuer alone or a stricter one of its own
    for (tag, value) in &want {
        if !kept.contains(&(tag.clone(), value.clone())) {
            dns.add_caa(suffix, tag, value).await?;
            added += 1;
        }
    }
    for id in &gone {
        dns.delete(id).await?;
        removed += 1;
    }
    eprintln!("nitro-issuer: {suffix}'s CAA names {} account(s): {added} added, {removed} removed at and below it", accounts.len());
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Fate {
    Keep,
    Remove,
    Outside,
}

/// What becomes of one CAA record when the suffix's CAA is set to `want`.
fn caa_fate(name: &str, tag_value: &(String, String), suffix: &str, want: &[(String, String)]) -> Fate {
    if name == suffix {
        if want.contains(tag_value) {
            Fate::Keep
        } else {
            Fate::Remove
        }
    } else if name.ends_with(&format!(".{suffix}")) {
        Fate::Remove
    } else {
        Fate::Outside
    }
}

fn account_uri(a: &str) -> bool {
    ["https://acme-v02.api.letsencrypt.org/acme/acct/", "https://acme-staging-v02.api.letsencrypt.org/acme/acct/"].iter().any(|p| a.strip_prefix(p).is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit())))
}

/// The suffix's CAA: each account may issue for its names and wildcards.
fn caa_records(accounts: &[String]) -> Vec<(String, String)> {
    let mut want = Vec::new();
    for tag in ["issue", "issuewild"] {
        for account in accounts {
            want.push((tag.to_string(), format!("letsencrypt.org; accounturi={account}")));
        }
    }
    want
}

/// The CSR's DER, when it asks for exactly `names`: the issuer orders the
/// home's names, never the CSR's, and Let's Encrypt would refuse a CSR
/// whose names are not the order's; this says so before an order is spent.
fn csr_der(pem: &str, names: &[String; 2]) -> Result<Vec<u8>> {
    let p = csr_pem(pem)?;
    let (_, request) = x509_parser::certification_request::X509CertificationRequest::from_der(&p.contents).map_err(|e| format!("the CSR: {e}"))?;
    let mut got: Vec<String> = request.requested_extensions().into_iter().flatten().filter_map(|x| if let ParsedExtension::SubjectAlternativeName(san) = x { Some(dns_names(&san.general_names)) } else { None }).flatten().collect();
    let mut want = names.to_vec();
    got.sort();
    want.sort();
    if got != want {
        return Err(format!("the CSR asks for {got:?}, not this home's {want:?}"));
    }
    Ok(p.contents)
}

type Https = hyper_util::client::legacy::Client<hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Full<Bytes>>;

/// The zone's DNS, through Cloudflare's API, with a token read from its file
/// and sent to the API alone, never printed.
struct Dns {
    http: Https,
    token: String,
    zone: String,
}

const API: &str = "https://api.cloudflare.com/client/v4";

impl Dns {
    async fn open(zone: &str, token_file: &Path) -> Result<Dns> {
        let token = std::fs::read_to_string(token_file).map_err(|e| format!("{}: {e}", token_file.display()))?.trim().to_string();
        let https = hyper_rustls::HttpsConnectorBuilder::new().try_with_platform_verifier().map_err(|e| format!("TLS: {e}"))?.https_only().enable_http1().build();
        let http = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https);
        let mut dns = Dns { http, token, zone: String::new() };
        let found = dns.call("GET", &format!("/zones?name={zone}"), None).await?;
        dns.zone = found.as_array().and_then(|z| z.first()).and_then(|z| z["id"].as_str()).ok_or_else(|| format!("no zone {zone} for this token"))?.to_string();
        Ok(dns)
    }

    async fn call(&self, method: &str, path: &str, body: Option<serde_json::Value>) -> Result<serde_json::Value> {
        let route = path.split('?').next().unwrap_or(path).to_string();
        let body = body.map(|b| Bytes::from(serde_json::to_vec(&b).expect("serializes"))).unwrap_or_default();
        let req = hyper::Request::builder()
            .method(method)
            .uri(format!("{API}{path}"))
            .header("authorization", format!("Bearer {}", self.token))
            .header("content-type", "application/json")
            .body(Full::new(body))
            .map_err(|e| e.to_string())?;
        let r = self.http.request(req).await.map_err(|e| format!("{method} {route}: {e}"))?;
        let bytes = r.into_body().collect().await.map_err(|e| format!("{method} {route}: {e}"))?.to_bytes();
        let out: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| format!("{method} {route}: Cloudflare's answer: {e}"))?;
        if out["success"] != true {
            return Err(format!("{method} {route}: {}", out["errors"]));
        }
        Ok(out["result"].clone())
    }

    async fn records(&self, kind: &str) -> Result<Vec<serde_json::Value>> {
        let found = self.call("GET", &format!("/zones/{}/dns_records?type={kind}&per_page={RECORDS_MAX}", self.zone), None).await?;
        let found = found.as_array().cloned().unwrap_or_default();
        if found.len() >= RECORDS_MAX {
            return Err(format!("{RECORDS_MAX} {kind} records or more: more than one page, which the issuer does not read"));
        }
        Ok(found)
    }

    async fn add_txt(&self, name: &str, value: &str) -> Result<String> {
        let body = serde_json::json!({ "type": "TXT", "name": name, "content": format!("\"{value}\""), "ttl": TTL, "comment": NOTE });
        let made = self.call("POST", &format!("/zones/{}/dns_records", self.zone), Some(body)).await?;
        made["id"].as_str().map(str::to_string).ok_or_else(|| "a TXT record without an id".into())
    }

    async fn add_caa(&self, name: &str, tag: &str, value: &str) -> Result<()> {
        let body = serde_json::json!({ "type": "CAA", "name": name, "data": { "flags": 0, "tag": tag, "value": value }, "ttl": TTL, "comment": NOTE });
        self.call("POST", &format!("/zones/{}/dns_records", self.zone), Some(body)).await.map(|_| ())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(format!("{id:?} is no record id"));
        }
        self.call("DELETE", &format!("/zones/{}/dns_records/{id}", self.zone), None).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: a home's names are its own and its fragments' wildcard, under
    // the suffix, and both prove at one TXT name; a name that is not one
    // label, or a suffix that is not a name, is refused.
    #[test]
    fn a_homes_names_and_their_challenge() {
        let n = names("test1", "homes.example.com").unwrap();
        assert_eq!(n, ["test1.homes.example.com", "*.test1.homes.example.com"]);
        assert_eq!(challenge_name(&n[0]), "_acme-challenge.test1.homes.example.com");
        assert_eq!(challenge_name(&n[1]), "_acme-challenge.test1.homes.example.com");
        for bad in ["", "Test1", "a.b", "-x", "x-", "a b", &"a".repeat(33), "*"] {
            assert!(names(bad, "homes.example.com").is_err(), "{bad}");
        }
        for bad in ["", "homes", ".homes.x", "homes.x.", "homes finite.x", "homes..x"] {
            assert!(names("test1", bad).is_err(), "{bad}");
        }
    }

    // Goal: the suffix's CAA names each account at Let's Encrypt, for names
    // and wildcards alike; its other CAA records go, and every one below it
    // (a home's own) goes; a name outside the suffix is left alone, even
    // one that ends with the suffix's text without being below it.
    #[test]
    fn caa_names_the_issuers_accounts_alone() {
        let a = "https://acme-v02.api.letsencrypt.org/acme/acct/123".to_string();
        let want = caa_records(std::slice::from_ref(&a));
        let value = format!("letsencrypt.org; accounturi={a}");
        assert_eq!(want, [("issue".to_string(), value.clone()), ("issuewild".to_string(), value.clone())]);
        let suffix = "homes.example.com";
        let tv = |t: &str, v: &str| (t.to_string(), v.to_string());
        assert_eq!(caa_fate(suffix, &tv("issue", &value), suffix, &want), Fate::Keep);
        assert_eq!(caa_fate(suffix, &tv("issue", "letsencrypt.org"), suffix, &want), Fate::Remove);
        assert_eq!(caa_fate("test1.homes.example.com", &tv("issue", "letsencrypt.org; accounturi=x"), suffix, &want), Fate::Remove);
        assert_eq!(caa_fate("test1.homes.example.com", &tv("issuewild", ";"), suffix, &want), Fate::Remove);
        assert_eq!(caa_fate("nitro.example.com", &tv("issue", "letsencrypt.org"), suffix, &want), Fate::Outside);
        assert_eq!(caa_fate("example.com", &tv("issue", "letsencrypt.org"), suffix, &want), Fate::Outside);
        assert_eq!(caa_fate("myhomes.example.com", &tv("issue", "letsencrypt.org"), suffix, &want), Fate::Outside);
        assert!(account_uri(&a) && account_uri("https://acme-staging-v02.api.letsencrypt.org/acme/acct/9"));
        for bad in ["https://acme-v02.api.letsencrypt.org/acme/acct/", "https://acme-v02.api.letsencrypt.org/acme/acct/12x", "https://example.com/acme/acct/1", ";"] {
            assert!(!account_uri(bad), "{bad}");
        }
    }

    // Goal: the issuer finalizes only a CSR that asks for exactly the
    // home's names; one for another home's names, or for fewer, is refused
    // before an order is spent.
    #[test]
    fn a_csr_for_other_names_is_refused() {
        let dir = crate::tests::scratch("csr");
        let home = names("test1", "homes.example.com").unwrap();
        let mine = crate::csr(&dir.join("key.pem"), &home).unwrap();
        assert!(csr_der(&mine, &home).is_ok());
        assert!(csr_der(&mine, &names("test2", "homes.example.com").unwrap()).unwrap_err().contains("not this home's"));
        let fewer = crate::csr(&dir.join("key.pem"), &home[..1]).unwrap();
        assert!(csr_der(&fewer, &home).unwrap_err().contains("not this home's"));
        assert!(csr_der("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n", &home).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
