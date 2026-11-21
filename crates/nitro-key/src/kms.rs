//! KMS's two calls, as the guest composes and reads them: pure, so every
//! rule is tested on any host. The guest checks what it can of an answer
//! itself (the key it names, no plaintext); the rest TLS proves (that the
//! answer is KMS's, to this request).

use base64::Engine as _;
use serde_json::{json, Value};

pub const GENERATE_DATA_KEY: &str = "TrentService.GenerateDataKey";
pub const DECRYPT: &str = "TrentService.Decrypt";
/// An answer's head and body, read whole: KMS's are a few KiB.
pub const HEAD_BYTES_MAX: usize = 16 * 1024;
pub const BODY_BYTES_MAX: usize = 64 * 1024;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn recipient(document: &[u8]) -> Value {
    json!({"KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256", "AttestationDocument": b64().encode(document)})
}

/// A new disk's key: AES-256, released to the document's key.
pub fn generate_data_key(key_id: &str, document: &[u8]) -> Vec<u8> {
    json!({"KeyId": key_id, "KeySpec": "AES_256", "Recipient": recipient(document)}).to_string().into_bytes()
}

/// A wake: the stored wrapped key, released again to this life's key.
pub fn decrypt(key_id: &str, wrapped: &[u8], document: &[u8]) -> Vec<u8> {
    json!({"KeyId": key_id, "CiphertextBlob": b64().encode(wrapped), "Recipient": recipient(document)}).to_string().into_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Released {
    /// The CMS envelope for the guest's key.
    pub for_recipient: Vec<u8>,
    /// The key wrapped by KMS, for the parent to keep (a new disk only).
    pub wrapped: Option<Vec<u8>>,
}

/// Reads KMS's JSON answer: the key it names must be ours, and no
/// plaintext may be in it (with a recipient, KMS returns none).
pub fn released(status: u16, body: &[u8], key_id: &str) -> Result<Released, String> {
    let v: Value = serde_json::from_slice(body).map_err(|e| format!("KMS's answer is not JSON: {e}"))?;
    if status != 200 {
        let kind = v["__type"].as_str().unwrap_or("?");
        return Err(format!("KMS refused ({status}): {kind}: {}", v["message"].as_str().or(v["Message"].as_str()).unwrap_or("")));
    }
    let named = v["KeyId"].as_str().ok_or("KMS's answer names no key")?;
    if !named.ends_with(&format!(":key/{key_id}")) {
        return Err(format!("KMS's answer names another key: {named}"));
    }
    if !v["Plaintext"].is_null() {
        return Err("KMS's answer carries a plaintext: it was not released to a recipient".into());
    }
    let for_recipient = b64().decode(v["CiphertextForRecipient"].as_str().ok_or("KMS's answer has no CiphertextForRecipient")?).map_err(|e| format!("the envelope: {e}"))?;
    let wrapped = match v["CiphertextBlob"].as_str() {
        Some(b) => Some(b64().decode(b).map_err(|e| format!("the wrapped key: {e}"))?),
        None => None,
    };
    Ok(Released { for_recipient, wrapped })
}

/// One HTTP/1.1 request, its headers exactly as the parent signed them.
pub fn request(host: &str, target: &str, body: &[u8], sig: &Signature) -> Vec<u8> {
    let mut head = format!(
        "POST / HTTP/1.1\r\nhost: {host}\r\ncontent-type: application/x-amz-json-1.1\r\nx-amz-target: {target}\r\nx-amz-date: {}\r\nauthorization: {}\r\n",
        sig.amz_date, sig.authorization
    );
    if let Some(t) = &sig.security_token {
        head.push_str(&format!("x-amz-security-token: {t}\r\n"));
    }
    head.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", body.len()));
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// The parent's signature: the shape of `sigv4::KmsSignature` there.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Signature {
    pub amz_date: String,
    pub authorization: String,
    pub security_token: Option<String>,
}

/// Reads one HTTP/1.1 answer: its status and body, bounded. A body is
/// framed by `content-length`, or runs to the connection's close.
pub fn read_answer<R: std::io::Read>(r: &mut R) -> Result<(u16, Vec<u8>), String> {
    let mut all = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    let head_end;
    // Bounded by HEAD_BYTES_MAX.
    loop {
        if let Some(i) = all.windows(4).position(|w| w == b"\r\n\r\n") {
            head_end = i + 4;
            break;
        }
        if all.len() > HEAD_BYTES_MAX {
            return Err("an answer's head over its limit".into());
        }
        let n = r.read(&mut buf).map_err(|e| format!("reading KMS's answer: {e}"))?;
        if n == 0 {
            return Err("KMS closed before its answer's head".into());
        }
        all.extend_from_slice(&buf[..n]);
    }
    let head = String::from_utf8_lossy(&all[..head_end]).into_owned();
    let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).ok_or("no status")?;
    let length = head.lines().find_map(|l| l.split_once(':').filter(|(n, _)| n.trim().eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse::<usize>().ok()));
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        return Err("a chunked answer, which KMS does not send".into());
    }
    let mut body = all[head_end..].to_vec();
    // Bounded by BODY_BYTES_MAX.
    loop {
        if length.is_some_and(|l| body.len() >= l) || body.len() > BODY_BYTES_MAX {
            break;
        }
        let n = r.read(&mut buf).map_err(|e| format!("reading KMS's answer: {e}"))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    if body.len() > BODY_BYTES_MAX {
        return Err("an answer's body over its limit".into());
    }
    if let Some(l) = length {
        if body.len() < l {
            return Err("KMS's answer cut short".into());
        }
        body.truncate(l);
    }
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "11111111-2222-3333-4444-555555555555";

    // Goal: the requests carry the recipient and nothing secret.
    #[test]
    fn requests_name_the_key_and_the_recipient() {
        let g: Value = serde_json::from_slice(&generate_data_key(KEY, b"doc")).unwrap();
        assert_eq!(g["KeySpec"], "AES_256");
        assert_eq!(g["Recipient"]["KeyEncryptionAlgorithm"], "RSAES_OAEP_SHA_256");
        assert_eq!(g["Recipient"]["AttestationDocument"], b64().encode(b"doc"));
        let d: Value = serde_json::from_slice(&decrypt(KEY, b"wrapped", b"doc")).unwrap();
        assert_eq!(d["CiphertextBlob"], b64().encode(b"wrapped"));
        let sig = Signature { amz_date: "20261120T000000Z".into(), authorization: "AWS4-HMAC-SHA256 x".into(), security_token: Some("t".into()) };
        let r = String::from_utf8(request("kms.us-east-2.amazonaws.com", DECRYPT, b"{}", &sig)).unwrap();
        assert!(r.starts_with("POST / HTTP/1.1\r\nhost: kms.us-east-2.amazonaws.com\r\n"));
        assert!(r.contains("x-amz-security-token: t\r\n") && r.ends_with("\r\n\r\n{}"));
    }

    // Goal: an answer for another key, one with a plaintext, or a refusal
    // is refused; ours reads. Method: each.
    #[test]
    fn answers_checked() {
        let ok = json!({"KeyId": format!("arn:aws:kms:us-east-2:000000000000:key/{KEY}"), "CiphertextForRecipient": b64().encode(b"cms"), "CiphertextBlob": b64().encode(b"wrapped")}).to_string();
        assert_eq!(released(200, ok.as_bytes(), KEY).unwrap(), Released { for_recipient: b"cms".to_vec(), wrapped: Some(b"wrapped".to_vec()) });
        let other = ok.replace(KEY, "99999999-2222-3333-4444-555555555555");
        assert!(released(200, other.as_bytes(), KEY).unwrap_err().contains("another key"));
        let plain = json!({"KeyId": format!("arn:aws:kms:us-east-2:0:key/{KEY}"), "Plaintext": "AAAA", "CiphertextForRecipient": "AAAA"}).to_string();
        assert!(released(200, plain.as_bytes(), KEY).unwrap_err().contains("plaintext"));
        let denied = json!({"__type": "AccessDeniedException", "message": "no"}).to_string();
        assert!(released(400, denied.as_bytes(), KEY).unwrap_err().contains("AccessDeniedException"));
    }

    // Goal: HTTP answers read whole, cut ones refused.
    #[test]
    fn answers_framed() {
        let mut ok: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(read_answer(&mut ok).unwrap(), (200, b"{}".to_vec()));
        let mut cut: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}";
        assert!(read_answer(&mut cut).is_err());
        let mut chunked: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert!(read_answer(&mut chunked).is_err());
    }
}
