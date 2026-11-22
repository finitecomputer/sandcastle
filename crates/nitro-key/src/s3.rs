//! An S3 object read and conditionally written by the guest itself, signed
//! with credentials the home's bundle holds (AWS Signature V4), so the
//! parent carries the bytes and holds no key to them. Pure: the caller
//! sends the request over TLS it ends, and reads the answer.

use ring::{digest, hmac};

/// An answer read, at most: a counter's record is a few hundred bytes.
pub const ANSWER_BYTES_MAX: usize = 64 * 1024;

#[derive(Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials(..)")
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, bytes))
}

fn mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message).as_ref().to_vec()
}

/// One request: `path` is the object's key, already safe in a URL
/// (`[A-Za-z0-9/_.-]`), so its canonical form is itself.
pub struct Request<'a> {
    pub method: &'static str,
    pub host: &'a str,
    pub path: &'a str,
    /// Headers beyond those signing adds (`if-match`, `if-none-match`),
    /// lowercase.
    pub headers: Vec<(&'static str, String)>,
    pub body: &'a [u8],
}

pub fn safe_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 512 && !key.contains("//") && key.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
}

/// The signature of `request` at `amz_date` (`YYYYMMDDTHHMMSSZ`): the
/// headers it is sent with, `authorization` last.
pub fn sign(credentials: &Credentials, region: &str, amz_date: &str, request: &Request) -> Vec<(String, String)> {
    assert!(safe_key(request.path.trim_start_matches('/')), "an object key of [A-Za-z0-9/_.-]");
    assert!(amz_date.len() == 16 && amz_date.as_bytes()[8] == b'T', "an x-amz-date");
    let payload = hex_sha256(request.body);
    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), request.host.to_string()),
        ("x-amz-content-sha256".into(), payload.clone()),
        ("x-amz-date".into(), amz_date.to_string()),
    ];
    headers.extend(request.headers.iter().map(|(n, v)| (n.to_string(), v.trim().to_string())));
    headers.sort();
    let signed: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
    let signed = signed.join(";");
    let canonical_headers: String = headers.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
    let canonical = format!("{}\n{}\n\n{canonical_headers}\n{signed}\n{payload}", request.method, request.path);
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", hex_sha256(canonical.as_bytes()));
    let k_date = mac(format!("AWS4{}", credentials.secret_access_key).as_bytes(), date.as_bytes());
    let k_region = mac(&k_date, region.as_bytes());
    let k_service = mac(&k_region, b"s3");
    let k_signing = mac(&k_service, b"aws4_request");
    let signature = hex::encode(mac(&k_signing, to_sign.as_bytes()));
    headers.push((
        "authorization".into(),
        format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}", credentials.access_key_id),
    ));
    headers
}

/// The request's bytes on the wire, HTTP/1.1, one per connection.
pub fn http(request: &Request, signed: &[(String, String)]) -> Vec<u8> {
    let mut head = format!("{} {} HTTP/1.1\r\n", request.method, request.path);
    for (name, value) in signed {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", request.body.len()));
    [head.as_bytes(), request.body].concat()
}

/// An answer: its status, its ETag, its body.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub etag: Option<String>,
    pub body: Vec<u8>,
}

/// The answer to a `connection: close` request, read whole (at most
/// `ANSWER_BYTES_MAX`): fixed-length or chunked.
pub fn parse_answer(bytes: &[u8]) -> Result<Answer, String> {
    let end = bytes.windows(4).position(|w| w == b"\r\n\r\n").ok_or("an answer without its head")?;
    let head = std::str::from_utf8(&bytes[..end]).map_err(|_| "an answer's head is not text")?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|s| s.parse().ok()).ok_or("an answer without a status")?;
    let (mut etag, mut chunked, mut length) = (None, false, None);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "etag" => etag = Some(value.to_string()),
            "transfer-encoding" => chunked = value.eq_ignore_ascii_case("chunked"),
            "content-length" => length = value.parse::<usize>().ok(),
            _ => {}
        }
    }
    let rest = &bytes[end + 4..];
    let body = if chunked {
        let mut body = Vec::new();
        let mut at = 0;
        loop {
            let line_end = rest[at..].windows(2).position(|w| w == b"\r\n").ok_or("a chunk without its size")? + at;
            let size = usize::from_str_radix(std::str::from_utf8(&rest[at..line_end]).map_err(|_| "a chunk's size")?.split(';').next().unwrap_or("").trim(), 16).map_err(|_| "a chunk's size")?;
            at = line_end + 2;
            if size == 0 {
                break;
            }
            body.extend_from_slice(rest.get(at..at + size).ok_or("a chunk cut short")?);
            at += size + 2;
        }
        body
    } else {
        match length {
            Some(n) => rest.get(..n).ok_or("a body cut short")?.to_vec(),
            None => rest.to_vec(),
        }
    };
    Ok(Answer { status, etag, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's own example (Signature Version 4, "GET Object"): its documented
    /// signature, from its documented secret.
    #[test]
    fn the_signature_is_aws_s_own_example_s() {
        let credentials = Credentials { access_key_id: "EXAMPLE".into(), secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into() };
        let request = Request { method: "GET", host: "examplebucket.s3.amazonaws.com", path: "/test.txt", headers: vec![("range", "bytes=0-9".into())], body: b"" };
        let signed = sign(&credentials, "us-east-1", "20130524T000000Z", &request);
        let authorization = &signed.last().unwrap().1;
        assert!(authorization.ends_with("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"), "{authorization}");
    }

    #[test]
    fn a_key_outside_the_safe_set_is_not_signed() {
        assert!(safe_key("homes/home-1/disk"));
        assert!(!safe_key("a b"));
        assert!(!safe_key(""));
        assert!(!safe_key("a//b"));
    }

    #[test]
    fn answers_are_read_fixed_or_chunked() {
        let fixed = b"HTTP/1.1 200 OK\r\nETag: \"abc\"\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(parse_answer(fixed).unwrap(), Answer { status: 200, etag: Some("\"abc\"".into()), body: b"hello".to_vec() });
        let chunked = b"HTTP/1.1 412 Precondition Failed\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_answer(chunked).unwrap(), Answer { status: 412, etag: None, body: b"abcde".to_vec() });
        assert!(parse_answer(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort").is_err());
        assert!(parse_answer(b"nothing").is_err());
    }
}
