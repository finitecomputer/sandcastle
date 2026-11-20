//! The document's two layers: the COSE_Sign1 envelope, and the payload
//! inside it (attestation_process.md, 3.2.2, "syntactical validation").
//! Each is parsed into slices of the input and checked field by field;
//! nothing here trusts a byte, since the signature is checked after.

use thiserror::Error;

use crate::cbor::{self, Reader};
use crate::{AttestError, Attested, CABUNDLE_LEN_MAX, CERTIFICATE_BYTES_MAX, DOCUMENT_BYTES_MAX, MODULE_ID_BYTES_MAX, NONCE_FIELD_BYTES_MAX, PAYLOAD_BYTES_MAX, PCRS_MAX, PCR_BYTES, PUBLIC_KEY_BYTES_MAX, SIGNATURE_BYTES, USER_DATA_BYTES_MAX};

/// COSE_Sign1's CBOR tag (RFC 9052). AWS's documents come bare; the NSM
/// API's own examples carry it. Both are taken.
const COSE_SIGN1_TAG: u64 = 18;
/// COSE's algorithm label and ES384's value (RFC 9053).
const LABEL_ALG: u64 = 1;
const ES384: i64 = -35;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CoseFault {
    #[error("{0} items, not 4")]
    Items(u64),
    #[error("the protected header is not exactly {{1: -35}} (ES384)")]
    NotEs384,
    #[error("the unprotected header holds {0} entries; it is empty in a Nitro document")]
    UnprotectedHeader(u64),
    #[error("the payload is {0} bytes, outside 1 to 16384")]
    PayloadLength(usize),
    #[error("the signature is {0} bytes, not 96")]
    SignatureLength(usize),
}

/// The payload's fields, named by their keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// The payload's map itself (its size, an unknown key).
    Map,
    ModuleId,
    Digest,
    Timestamp,
    Pcrs,
    Certificate,
    Cabundle,
    PublicKey,
    UserData,
    Nonce,
}

/// Every field and its key, in the NSM's order. The first six are
/// mandatory.
const FIELDS: [(Field, &str); 9] = [
    (Field::ModuleId, "module_id"),
    (Field::Digest, "digest"),
    (Field::Timestamp, "timestamp"),
    (Field::Pcrs, "pcrs"),
    (Field::Certificate, "certificate"),
    (Field::Cabundle, "cabundle"),
    (Field::PublicKey, "public_key"),
    (Field::UserData, "user_data"),
    (Field::Nonce, "nonce"),
];
const MANDATORY: usize = 6;

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match FIELDS.iter().find(|(field, _)| field == self) {
            Some((_, key)) => f.write_str(key),
            None => f.write_str("map"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FieldFault {
    #[error("missing")]
    Missing,
    #[error("given twice")]
    Repeated,
    #[error("an unknown key")]
    UnknownKey,
    #[error("{len} bytes, outside {min} to {max}")]
    Length { len: usize, min: usize, max: usize },
    #[error("{n} entries, outside {min} to {max}")]
    Count { n: u64, min: u64, max: u64 },
    #[error("not SHA384")]
    NotSha384,
    #[error("zero")]
    Zero,
    #[error("PCR index {0}, past 31")]
    PcrIndex(u64),
    #[error("PCR {0} listed twice")]
    PcrRepeated(u64),
}

fn field_err(field: Field, fault: FieldFault) -> AttestError {
    AttestError::Field { field, fault }
}

fn length(field: Field, s: &[u8], min: usize, max: usize) -> Result<(), AttestError> {
    if s.len() >= min && s.len() <= max {
        Ok(())
    } else {
        Err(field_err(field, FieldFault::Length { len: s.len(), min, max }))
    }
}

fn count(field: Field, n: u64, min: u64, max: u64) -> Result<(), AttestError> {
    if n >= min && n <= max {
        Ok(())
    } else {
        Err(field_err(field, FieldFault::Count { n, min, max }))
    }
}

pub(crate) struct Envelope<'a> {
    pub protected: &'a [u8],
    pub payload: &'a [u8],
    pub signature: &'a [u8],
}

pub(crate) fn envelope(document: &[u8]) -> Result<Envelope<'_>, AttestError> {
    if document.len() > DOCUMENT_BYTES_MAX {
        return Err(AttestError::TooLarge { len: document.len(), max: DOCUMENT_BYTES_MAX });
    }
    let mut r = Reader::new(document);
    r.tag_if(COSE_SIGN1_TAG)?;
    let items = r.array()?;
    if items != 4 {
        return Err(AttestError::Cose(CoseFault::Items(items)));
    }
    let protected = r.bytes()?;
    let unprotected = r.map()?;
    if unprotected != 0 {
        return Err(AttestError::Cose(CoseFault::UnprotectedHeader(unprotected)));
    }
    let payload = r.bytes()?;
    let signature = r.bytes()?;
    r.finish()?;
    if !es384(protected) {
        return Err(AttestError::Cose(CoseFault::NotEs384));
    }
    if payload.is_empty() || payload.len() > PAYLOAD_BYTES_MAX {
        return Err(AttestError::Cose(CoseFault::PayloadLength(payload.len())));
    }
    if signature.len() != SIGNATURE_BYTES {
        return Err(AttestError::Cose(CoseFault::SignatureLength(signature.len())));
    }
    Ok(Envelope { protected, payload, signature })
}

/// Whether the protected header is exactly `{1: -35}`: one entry, the
/// algorithm, ES384. Anything else, extra labels included, is not ours.
fn es384(protected: &[u8]) -> bool {
    let mut r = Reader::new(protected);
    let entries = r.map();
    let label = r.uint();
    let alg = r.negative();
    match (entries, label, alg, r.finish()) {
        (Ok(1), Ok(LABEL_ALG), Ok(n), Ok(())) => -1 - i64::try_from(n).unwrap_or(i64::MAX) == ES384,
        _ => false,
    }
}

/// COSE's `Sig_structure` for a Sign1: what the signature covers
/// (RFC 9052, 4.4): `["Signature1", protected, external_aad = h'', payload]`.
pub(crate) fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    const CONTEXT: &[u8] = b"Signature1";
    let mut out = Vec::with_capacity(32 + protected.len() + payload.len());
    cbor::write_head(&mut out, 4, 4);
    cbor::write_head(&mut out, 3, CONTEXT.len() as u64);
    out.extend_from_slice(CONTEXT);
    cbor::write_head(&mut out, 2, protected.len() as u64);
    out.extend_from_slice(protected);
    cbor::write_head(&mut out, 2, 0);
    cbor::write_head(&mut out, 2, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

pub(crate) struct Payload<'a> {
    pub module_id: &'a str,
    pub timestamp_ms: u64,
    pub pcrs: Vec<(u8, &'a [u8])>,
    pub certificate: &'a [u8],
    pub cabundle: Vec<&'a [u8]>,
    pub public_key: Option<&'a [u8]>,
    pub user_data: Option<&'a [u8]>,
    pub nonce: Option<&'a [u8]>,
}

impl Payload<'_> {
    pub fn into_attested(self) -> Attested {
        let mut pcrs: Vec<(u8, [u8; PCR_BYTES])> = self.pcrs.iter().map(|(i, v)| (*i, <[u8; PCR_BYTES]>::try_from(*v).expect("48 bytes, checked when parsed"))).collect();
        pcrs.sort_by_key(|(i, _)| *i);
        Attested {
            module_id: self.module_id.to_string(),
            timestamp_ms: self.timestamp_ms,
            pcrs,
            public_key: self.public_key.map(<[u8]>::to_vec),
            user_data: self.user_data.map(<[u8]>::to_vec),
            nonce: self.nonce.map(<[u8]>::to_vec),
        }
    }
}

pub(crate) fn payload(bytes: &[u8]) -> Result<Payload<'_>, AttestError> {
    let mut r = Reader::new(bytes);
    let entries = r.map()?;
    count(Field::Map, entries, MANDATORY as u64, FIELDS.len() as u64)?;
    let mut seen = [false; FIELDS.len()];
    let mut p = Payload { module_id: "", timestamp_ms: 0, pcrs: Vec::new(), certificate: &[], cabundle: Vec::new(), public_key: None, user_data: None, nonce: None };
    // Bounded: entries is at most nine, checked above.
    for _ in 0..entries {
        let key = r.text()?;
        let Some(slot) = FIELDS.iter().position(|(_, k)| *k == key) else {
            return Err(field_err(Field::Map, FieldFault::UnknownKey));
        };
        let field = FIELDS[slot].0;
        if seen[slot] {
            return Err(field_err(field, FieldFault::Repeated));
        }
        seen[slot] = true;
        match field {
            Field::ModuleId => {
                let t = r.text()?;
                length(field, t.as_bytes(), 1, MODULE_ID_BYTES_MAX)?;
                p.module_id = t;
            }
            Field::Digest => {
                if r.text()? != "SHA384" {
                    return Err(field_err(field, FieldFault::NotSha384));
                }
            }
            Field::Timestamp => {
                p.timestamp_ms = r.uint()?;
                if p.timestamp_ms == 0 {
                    return Err(field_err(field, FieldFault::Zero));
                }
            }
            Field::Pcrs => p.pcrs = pcrs(&mut r)?,
            Field::Certificate => {
                p.certificate = r.bytes()?;
                length(field, p.certificate, 1, CERTIFICATE_BYTES_MAX)?;
            }
            Field::Cabundle => {
                let n = r.array()?;
                count(field, n, 1, CABUNDLE_LEN_MAX)?;
                // Bounded by CABUNDLE_LEN_MAX, checked above.
                for _ in 0..n {
                    let c = r.bytes()?;
                    length(field, c, 1, CERTIFICATE_BYTES_MAX)?;
                    p.cabundle.push(c);
                }
            }
            Field::PublicKey => {
                p.public_key = r.null_or_bytes()?;
                if let Some(k) = p.public_key {
                    length(field, k, 1, PUBLIC_KEY_BYTES_MAX)?;
                }
            }
            Field::UserData => {
                p.user_data = r.null_or_bytes()?;
                if let Some(d) = p.user_data {
                    length(field, d, 0, USER_DATA_BYTES_MAX)?;
                }
            }
            Field::Nonce => {
                p.nonce = r.null_or_bytes()?;
                if let Some(n) = p.nonce {
                    length(field, n, 0, NONCE_FIELD_BYTES_MAX)?;
                }
            }
            Field::Map => unreachable!("not in FIELDS"),
        }
    }
    r.finish()?;
    for (slot, (field, _)) in FIELDS.iter().enumerate().take(MANDATORY) {
        if !seen[slot] {
            return Err(field_err(*field, FieldFault::Missing));
        }
    }
    assert!(!p.module_id.is_empty() && p.timestamp_ms > 0 && !p.certificate.is_empty());
    assert!(!p.pcrs.is_empty() && !p.cabundle.is_empty());
    Ok(p)
}

/// The PCR map: 1 to 32 entries, indexes below 32, none twice, each 48
/// bytes (SHA-384, the digest the payload names).
fn pcrs<'a>(r: &mut Reader<'a>) -> Result<Vec<(u8, &'a [u8])>, AttestError> {
    let n = r.map()?;
    count(Field::Pcrs, n, 1, PCRS_MAX)?;
    let mut seen = 0u32;
    let mut out = Vec::with_capacity(n as usize);
    // Bounded by PCRS_MAX, checked above.
    for _ in 0..n {
        let index = r.uint()?;
        if index >= PCRS_MAX {
            return Err(field_err(Field::Pcrs, FieldFault::PcrIndex(index)));
        }
        let bit = 1u32 << index;
        if seen & bit != 0 {
            return Err(field_err(Field::Pcrs, FieldFault::PcrRepeated(index)));
        }
        seen |= bit;
        let value = r.bytes()?;
        length(Field::Pcrs, value, PCR_BYTES, PCR_BYTES)?;
        out.push((index as u8, value));
    }
    assert_eq!(out.len() as u64, n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, Fields};

    fn field_fault(doc: &[u8]) -> (Field, FieldFault) {
        let e = envelope(doc).expect("the envelope is fine");
        match payload(e.payload) {
            Err(AttestError::Field { field, fault }) => (field, fault),
            Err(other) => panic!("expected a field fault, got {other}"),
            Ok(_) => panic!("expected a field fault, got a payload"),
        }
    }

    // Goal: a payload as the NSM writes it parses to its fields. Method:
    // the test kit's document (self-made chain), every field set.
    #[test]
    fn a_whole_payload_parses() {
        let chain = testkit::Chain::new();
        let f = Fields::new();
        let doc = testkit::document(&chain, &f);
        let e = envelope(&doc).unwrap();
        let p = payload(e.payload).unwrap();
        assert_eq!(p.module_id, f.module_id);
        assert_eq!(p.timestamp_ms, f.timestamp_ms);
        assert_eq!(p.pcrs.len(), f.pcrs.len());
        assert_eq!(p.nonce, f.nonce.as_deref());
        assert_eq!(p.public_key, f.public_key.as_deref());
        assert_eq!(p.cabundle.len(), 2, "root and intermediate");
    }

    // Goal: the envelope's shape is exact. Method: each item of it wrong.
    #[test]
    fn envelope_shape_refused() {
        let chain = testkit::Chain::new();
        let f = Fields::new();
        let payload = testkit::payload(&chain, &f);
        let cose = |protected: &[u8], unprotected_entries: u64, sig_len: usize| {
            let mut out = Vec::new();
            cbor::write_head(&mut out, 4, 4);
            cbor::write_head(&mut out, 2, protected.len() as u64);
            out.extend_from_slice(protected);
            cbor::write_head(&mut out, 5, unprotected_entries);
            for i in 0..unprotected_entries {
                cbor::write_head(&mut out, 0, 4 + i);
                cbor::write_head(&mut out, 0, 0);
            }
            cbor::write_head(&mut out, 2, payload.len() as u64);
            out.extend_from_slice(&payload);
            cbor::write_head(&mut out, 2, sig_len as u64);
            out.extend(std::iter::repeat_n(1u8, sig_len));
            out
        };
        assert!(envelope(&cose(testkit::PROTECTED_ES384, 0, 96)).is_ok());
        // ES256 (-7) and ES512 (-36): not ours.
        assert_eq!(envelope(&cose(&[0xa1, 0x01, 0x26], 0, 96)).err(), Some(AttestError::Cose(CoseFault::NotEs384)));
        assert_eq!(envelope(&cose(&[0xa1, 0x01, 0x38, 0x23], 0, 96)).err(), Some(AttestError::Cose(CoseFault::NotEs384)));
        // ES384 with another label beside it.
        assert_eq!(envelope(&cose(&[0xa2, 0x01, 0x38, 0x22, 0x04, 0x00], 0, 96)).err(), Some(AttestError::Cose(CoseFault::NotEs384)));
        assert_eq!(envelope(&cose(testkit::PROTECTED_ES384, 1, 96)).err(), Some(AttestError::Cose(CoseFault::UnprotectedHeader(1))));
        assert_eq!(envelope(&cose(testkit::PROTECTED_ES384, 0, 64)).err(), Some(AttestError::Cose(CoseFault::SignatureLength(64))));
        let mut three = cose(testkit::PROTECTED_ES384, 0, 96);
        three[0] = 0x83;
        assert!(matches!(envelope(&three), Err(AttestError::Cose(CoseFault::Items(3))) | Err(AttestError::Cbor { .. })));
        let mut big = vec![0u8; DOCUMENT_BYTES_MAX + 1];
        big[0] = 0x84;
        assert_eq!(envelope(&big).err(), Some(AttestError::TooLarge { len: DOCUMENT_BYTES_MAX + 1, max: DOCUMENT_BYTES_MAX }));
    }

    // Goal: every field's rule refuses its breach, naming the field.
    // Method: the test kit's payload, one field wrong at a time.
    #[test]
    fn each_field_rule_refuses() {
        let chain = testkit::Chain::new();
        type Change = Box<dyn Fn(&mut Fields)>;
        let cases: Vec<(Change, Field, FieldFault)> = vec![
            (Box::new(|f| f.digest = "SHA256".into()), Field::Digest, FieldFault::NotSha384),
            (Box::new(|f| f.timestamp_ms = 0), Field::Timestamp, FieldFault::Zero),
            (Box::new(|f| f.module_id = String::new()), Field::ModuleId, FieldFault::Length { len: 0, min: 1, max: MODULE_ID_BYTES_MAX }),
            (Box::new(|f| f.pcrs = vec![]), Field::Pcrs, FieldFault::Count { n: 0, min: 1, max: PCRS_MAX }),
            (Box::new(|f| f.pcrs = vec![(32, vec![0; 48])]), Field::Pcrs, FieldFault::PcrIndex(32)),
            (Box::new(|f| f.pcrs = vec![(3, vec![0; 48]), (3, vec![1; 48])]), Field::Pcrs, FieldFault::PcrRepeated(3)),
            (Box::new(|f| f.pcrs = vec![(0, vec![0; 32])]), Field::Pcrs, FieldFault::Length { len: 32, min: 48, max: 48 }),
            (Box::new(|f| f.public_key = Some(vec![])), Field::PublicKey, FieldFault::Length { len: 0, min: 1, max: PUBLIC_KEY_BYTES_MAX }),
            (Box::new(|f| f.nonce = Some(vec![0; NONCE_FIELD_BYTES_MAX + 1])), Field::Nonce, FieldFault::Length { len: NONCE_FIELD_BYTES_MAX + 1, min: 0, max: NONCE_FIELD_BYTES_MAX }),
            (Box::new(|f| f.user_data = Some(vec![0; USER_DATA_BYTES_MAX + 1])), Field::UserData, FieldFault::Length { len: USER_DATA_BYTES_MAX + 1, min: 0, max: USER_DATA_BYTES_MAX }),
            (Box::new(|f| f.cabundle = Some(vec![])), Field::Cabundle, FieldFault::Count { n: 0, min: 1, max: CABUNDLE_LEN_MAX }),
            (Box::new(|f| f.cabundle = Some(vec![vec![0x30]; CABUNDLE_LEN_MAX as usize + 1])), Field::Cabundle, FieldFault::Count { n: CABUNDLE_LEN_MAX + 1, min: 1, max: CABUNDLE_LEN_MAX }),
            (Box::new(|f| f.cabundle = Some(vec![vec![]])), Field::Cabundle, FieldFault::Length { len: 0, min: 1, max: CERTIFICATE_BYTES_MAX }),
            (Box::new(|f| f.append = vec!["debug"]), Field::Map, FieldFault::Count { n: 10, min: 6, max: 9 }),
            (Box::new(|f| (f.omit, f.append) = (vec!["user_data"], vec!["debug"])), Field::Map, FieldFault::UnknownKey),
            (Box::new(|f| (f.omit, f.append) = (vec!["user_data"], vec!["nonce"])), Field::Nonce, FieldFault::Repeated),
            (Box::new(|f| f.omit = vec!["certificate"]), Field::Certificate, FieldFault::Missing),
            (Box::new(|f| f.omit = vec!["digest", "pcrs", "timestamp", "public_key"]), Field::Map, FieldFault::Count { n: 5, min: 6, max: 9 }),
        ];
        for (i, (change, field, fault)) in cases.into_iter().enumerate() {
            let mut f = Fields::new();
            change(&mut f);
            assert_eq!(field_fault(&testkit::document(&chain, &f)), (field, fault), "case {i}");
        }
    }

    // Goal: the optional fields may be null or absent, as the NSM's
    // encoder writes them either way. Method: all three null, then absent.
    #[test]
    fn optional_fields_null_or_absent() {
        let chain = testkit::Chain::new();
        let mut f = Fields::new();
        f.public_key = None;
        f.user_data = None;
        f.nonce = None;
        let doc = testkit::document(&chain, &f);
        let p = payload(envelope(&doc).unwrap().payload).unwrap();
        assert!(p.public_key.is_none() && p.user_data.is_none() && p.nonce.is_none());
        f.omit = vec!["public_key", "user_data", "nonce"];
        let doc = testkit::document(&chain, &f);
        let p = payload(envelope(&doc).unwrap().payload).unwrap();
        assert!(p.nonce.is_none());
    }
}
