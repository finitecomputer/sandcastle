//! The two facts read from a certificate's DER that webpki does not hand
//! back: a trust anchor's validity (webpki checks every certificate's but
//! the anchor's, and AWS's process checks the root's too) and the signing
//! certificate's key usage (it must allow `digitalSignature`). A walk of
//! RFC 5280's TBSCertificate, bounded and non-recursive; webpki has
//! already parsed and checked the same bytes in full where it matters.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DerFault {
    #[error("the input ends inside an element")]
    Truncated,
    #[error("a multi-byte tag")]
    LongTag,
    #[error("a length longer than four bytes")]
    LongLength,
    #[error("expected tag {expected:#04x}, found {found:#04x}")]
    Tag { expected: u8, found: u8 },
    #[error("a time that is not RFC 5280's UTCTime or GeneralizedTime in UTC")]
    Time,
    #[error("more than {0} extensions")]
    Extensions(usize),
}

/// Extensions a certificate may carry before the walk gives up. AWS's
/// carry four or five.
pub const EXTENSIONS_MAX: usize = 32;

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BOOLEAN: u8 = 0x01;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const VERSION: u8 = 0xa0;
const ISSUER_UNIQUE_ID: u8 = 0x81;
const SUBJECT_UNIQUE_ID: u8 = 0x82;
const EXTENSIONS: u8 = 0xa3;
/// id-ce-keyUsage, 2.5.29.15.
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];

/// One element: its tag, its content, and what follows it.
fn element(input: &[u8]) -> Result<(u8, &[u8], &[u8]), DerFault> {
    let (&tag, rest) = input.split_first().ok_or(DerFault::Truncated)?;
    if tag & 0x1f == 0x1f {
        return Err(DerFault::LongTag);
    }
    let (&first, rest) = rest.split_first().ok_or(DerFault::Truncated)?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return Err(DerFault::LongLength);
        }
        if rest.len() < n {
            return Err(DerFault::Truncated);
        }
        let mut len = 0usize;
        for b in &rest[..n] {
            len = (len << 8) | usize::from(*b);
        }
        (len, &rest[n..])
    };
    if rest.len() < len {
        return Err(DerFault::Truncated);
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn expect(input: &[u8], expected: u8) -> Result<(&[u8], &[u8]), DerFault> {
    let (tag, content, rest) = element(input)?;
    if tag == expected {
        Ok((content, rest))
    } else {
        Err(DerFault::Tag { expected, found: tag })
    }
}

/// Skips `tag` if it comes next.
fn skip_if(input: &[u8], tag: u8) -> Result<&[u8], DerFault> {
    match input.first() {
        Some(&t) if t == tag => Ok(element(input)?.2),
        _ => Ok(input),
    }
}

/// The TBSCertificate's fields after the validity: subject onward.
struct Tbs<'a> {
    validity: &'a [u8],
    after_validity: &'a [u8],
}

fn tbs(certificate: &[u8]) -> Result<Tbs<'_>, DerFault> {
    let (cert, _) = expect(certificate, SEQUENCE)?;
    let (tbs, _) = expect(cert, SEQUENCE)?;
    let rest = skip_if(tbs, VERSION)?;
    let (_, rest) = expect(rest, INTEGER)?; // serialNumber
    let (_, rest) = expect(rest, SEQUENCE)?; // signature
    let (_, rest) = expect(rest, SEQUENCE)?; // issuer
    let (validity, after_validity) = expect(rest, SEQUENCE)?;
    Ok(Tbs { validity, after_validity })
}

/// A certificate's validity, in seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Validity {
    pub not_before_s: i64,
    pub not_after_s: i64,
}

impl Validity {
    pub fn holds_at(&self, now_s: i64) -> bool {
        self.not_before_s <= now_s && now_s <= self.not_after_s
    }
}

pub(crate) fn validity(certificate: &[u8]) -> Result<Validity, DerFault> {
    let t = tbs(certificate)?;
    let (tag, not_before, rest) = element(t.validity)?;
    let not_before_s = time(tag, not_before)?;
    let (tag, not_after, _) = element(rest)?;
    let not_after_s = time(tag, not_after)?;
    Ok(Validity { not_before_s, not_after_s })
}

/// Whether the key usage extension is present and allows
/// `digitalSignature` (bit 0). Absent, it does not: AWS's process
/// requires it on the signing certificate.
pub(crate) fn allows_digital_signature(certificate: &[u8]) -> Result<bool, DerFault> {
    let t = tbs(certificate)?;
    let (_, rest) = expect(t.after_validity, SEQUENCE)?; // subject
    let (_, rest) = expect(rest, SEQUENCE)?; // subjectPublicKeyInfo
    let rest = skip_if(rest, ISSUER_UNIQUE_ID)?;
    let rest = skip_if(rest, SUBJECT_UNIQUE_ID)?;
    if rest.first() != Some(&EXTENSIONS) {
        return Ok(false);
    }
    let (wrapper, _) = expect(rest, EXTENSIONS)?;
    let (mut list, _) = expect(wrapper, SEQUENCE)?;
    let mut seen = 0usize;
    while !list.is_empty() {
        seen += 1;
        if seen > EXTENSIONS_MAX {
            return Err(DerFault::Extensions(EXTENSIONS_MAX));
        }
        let (extension, next) = expect(list, SEQUENCE)?;
        list = next;
        let (oid, rest) = expect(extension, OID)?;
        if oid != KEY_USAGE {
            continue;
        }
        let rest = skip_if(rest, BOOLEAN)?; // critical
        let (value, _) = expect(rest, OCTET_STRING)?;
        let (bits, _) = expect(value, BIT_STRING)?;
        // The first byte counts the unused bits; digitalSignature is the
        // first named bit, the high bit of the next byte.
        return Ok(bits.len() >= 2 && bits[1] & 0x80 != 0);
    }
    Ok(false)
}

/// RFC 5280's times: UTCTime `YYMMDDHHMMSSZ` (years 1950 to 2049) or
/// GeneralizedTime `YYYYMMDDHHMMSSZ`, in UTC, with seconds and no fraction.
fn time(tag: u8, s: &[u8]) -> Result<i64, DerFault> {
    let (year, rest) = match (tag, s.len()) {
        (UTC_TIME, 13) => {
            let yy = digits(&s[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        (GENERALIZED_TIME, 15) => (digits(&s[..4])?, &s[4..]),
        _ => return Err(DerFault::Time),
    };
    if rest[10] != b'Z' {
        return Err(DerFault::Time);
    }
    let (month, day) = (digits(&rest[0..2])?, digits(&rest[2..4])?);
    let (hour, minute, second) = (digits(&rest[4..6])?, digits(&rest[6..8])?, digits(&rest[8..10])?);
    let in_range = (1..=12).contains(&month) && (1..=31).contains(&day) && hour < 24 && minute < 60 && second < 60;
    if !in_range {
        return Err(DerFault::Time);
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

fn digits(s: &[u8]) -> Result<i64, DerFault> {
    let mut v = 0i64;
    for c in s {
        if !c.is_ascii_digit() {
            return Err(DerFault::Time);
        }
        v = v * 10 + i64::from(c - b'0');
    }
    Ok(v)
}

/// Days from 1970-01-01 to a proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: dates land on the right second. Method: known instants, the
    // epoch, a leap day, and both encodings' century rule.
    #[test]
    fn times_parse_to_unix_seconds() {
        assert_eq!(time(UTC_TIME, b"700101000000Z"), Ok(0));
        assert_eq!(time(UTC_TIME, b"000229120000Z"), Ok(951_825_600));
        assert_eq!(time(UTC_TIME, b"491231235959Z"), Ok(2_524_607_999));
        assert_eq!(time(GENERALIZED_TIME, b"20491028142805Z"), Ok(2_519_044_085));
        assert_eq!(time(GENERALIZED_TIME, b"20500101000000Z"), Ok(2_524_608_000));
    }

    // Goal: anything but the two exact forms is refused.
    #[test]
    fn malformed_times_refused() {
        for (tag, s) in [(UTC_TIME, &b"7001010000Z"[..]), (UTC_TIME, b"700101000000+"), (UTC_TIME, b"701301000000Z"), (UTC_TIME, b"70010100000aZ"), (GENERALIZED_TIME, b"700101000000Z"), (0x13, b"700101000000Z"), (UTC_TIME, b"700101240000Z")] {
            assert_eq!(time(tag, s), Err(DerFault::Time), "{}", String::from_utf8_lossy(s));
        }
    }

    // Goal: a length that claims more than remains is a fault, never a
    // read past the end. Method: every prefix of a small element.
    #[test]
    fn elements_never_read_past_the_end() {
        let full = [0x30, 0x82, 0x00, 0x03, 1, 2, 3];
        for cut in 0..full.len() {
            assert!(element(&full[..cut]).is_err(), "cut at {cut}");
        }
        assert_eq!(element(&full), Ok((0x30, &[1u8, 2, 3][..], &[][..])));
        assert_eq!(element(&[0x1f, 0x01, 0x00]), Err(DerFault::LongTag));
        assert_eq!(element(&[0x30, 0x85, 0, 0, 0, 0, 1]), Err(DerFault::LongLength));
    }
}
