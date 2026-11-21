//! AWS Signature Version 4 for the parent's one signing job (acceptance 8):
//! a KMS request the guest composed, which the parent signs with its role's
//! credentials without seeing more than its target and its body's hash.
//! Pure: the caller passes the credentials and the time.

use ring::{digest, hmac};

#[derive(Clone)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the secret, never the token.
        f.write_str("Credentials(<redacted>)")
    }
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, b))
}

fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data).as_ref().to_vec()
}

/// The `Authorization` header for one request. `headers` are lowercase
/// names and trimmed values, sorted by name, every one signed.
#[allow(clippy::too_many_arguments)]
pub fn authorization(creds: &Credentials, method: &str, path: &str, query: &str, headers: &[(&str, &str)], body_sha256: &str, region: &str, service: &str, amz_date: &str) -> String {
    assert!(amz_date.len() == 16 && amz_date.as_bytes()[8] == b'T' && amz_date.ends_with('Z'), "YYYYMMDDTHHMMSSZ");
    assert!(headers.windows(2).all(|w| w[0].0 < w[1].0), "headers sorted, each once");
    assert!(headers.iter().all(|(n, _)| n.bytes().all(|b| !b.is_ascii_uppercase())), "names lowercase");
    let date = &amz_date[..8];
    let mut canonical = format!("{method}\n{path}\n{query}\n");
    for (n, v) in headers {
        canonical.push_str(&format!("{n}:{v}\n"));
    }
    let signed: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
    let signed = signed.join(";");
    canonical.push_str(&format!("\n{signed}\n{body_sha256}"));
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let k_date = mac(format!("AWS4{}", creds.secret_key).as_bytes(), date.as_bytes());
    let k_region = mac(&k_date, region.as_bytes());
    let k_service = mac(&k_region, service.as_bytes());
    let k_signing = mac(&k_service, b"aws4_request");
    let signature = hex::encode(mac(&k_signing, to_sign.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}", creds.access_key)
}

/// What a KMS JSON request carries besides its body: the headers the
/// guest must send exactly as signed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KmsSignature {
    pub amz_date: String,
    pub authorization: String,
    pub security_token: Option<String>,
}

pub const KMS_CONTENT_TYPE: &str = "application/x-amz-json-1.1";

/// Signs `POST /` to `host` with `x-amz-target: target`.
pub fn kms(creds: &Credentials, region: &str, host: &str, target: &str, body_sha256: &str, amz_date: &str) -> KmsSignature {
    let token = creds.token.as_deref();
    let mut headers: Vec<(&str, &str)> = vec![("content-type", KMS_CONTENT_TYPE), ("host", host), ("x-amz-date", amz_date)];
    if let Some(t) = token {
        headers.push(("x-amz-security-token", t));
    }
    headers.push(("x-amz-target", target));
    let authorization = authorization(creds, "POST", "/", "", &headers, body_sha256, region, "kms", amz_date);
    KmsSignature { amz_date: amz_date.to_string(), authorization, security_token: creds.token.clone() }
}

/// The signed headers' names for a KMS request, in the order signed:
/// what the guest's request must carry.
pub fn kms_signed_headers(with_token: bool) -> &'static str {
    if with_token {
        "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
    } else {
        "content-type;host;x-amz-date;x-amz-target"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: our signature is AWS's for AWS's own worked example (the
    // Signature Version 4 guide's IAM ListUsers request, with its example
    // keys, 2015-08-30T12:36:00Z, us-east-1). Method: the published
    // signature, byte for byte.
    #[test]
    fn matches_awss_worked_example() {
        let creds = Credentials { access_key: "AKIDEXAMPLE".into(), secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(), token: None };
        let headers = [("content-type", "application/x-www-form-urlencoded; charset=utf-8"), ("host", "iam.amazonaws.com"), ("x-amz-date", "20150830T123600Z")];
        let auth = authorization(&creds, "GET", "/", "Action=ListUsers&Version=2010-05-08", &headers, &sha256_hex(b""), "us-east-1", "iam", "20150830T123600Z");
        assert_eq!(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
    }

    // Goal: a KMS signature covers the token and the target, and changes
    // with the body. Method: two bodies, one credential set.
    #[test]
    fn kms_signs_the_body_and_the_target() {
        let creds = Credentials { access_key: "AKIDEXAMPLE".into(), secret_key: "secret".into(), token: Some("token".into()) };
        let a = kms(&creds, "us-east-2", "kms.us-east-2.amazonaws.com", "TrentService.Decrypt", &sha256_hex(b"{}"), "20261120T000000Z");
        let b = kms(&creds, "us-east-2", "kms.us-east-2.amazonaws.com", "TrentService.Decrypt", &sha256_hex(b"{ }"), "20261120T000000Z");
        assert!(a.authorization.contains(&format!("SignedHeaders={}", kms_signed_headers(true))));
        assert_ne!(a.authorization, b.authorization);
        assert!(!format!("{creds:?}").contains("secret"));
    }
}
