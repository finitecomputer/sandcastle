//! A home's data disk, refused when it is older than its counter or not
//! this home's (docs/nitro-home.md, "Rollback and disk swaps"). Pure: the
//! caller reads block 0 and the counter, and writes what this returns.
//!
//! Block 0 of the disk holds its header, one line, padded with NULs:
//!
//! ```text
//! nitro-home-disk v2 <wrapped> <home> <disk> <generation> <mac>
//! ```
//!
//! - `wrapped`: KMS's ciphertext of the disk's key (base64), as in v1;
//! - `home`: the home this disk is, from the home's measured image, never
//!   the parent's word;
//! - `disk`: 16 random bytes (hex), made with the disk;
//! - `generation`: a count the home raises at each open and while it runs;
//! - `mac`: HMAC-SHA256 of the rest under a key derived from the disk's
//!   key, so only a home that opened this disk could have written it.
//!
//! The counter, outside the parent (an object behind the home's own
//! credentials), holds the disk's id and its latest generation, MAC'd the
//! same way. A disk opens only when its header is this home's, names the
//! counter's disk, and is at the counter's generation, or one past it (a
//! stop between the header's write and the counter's). An older header is
//! an older disk: refused.

use base64::Engine as _;
use ring::{hkdf, hmac};

pub const BLOCK_BYTES: usize = 4096;
pub const V1: &str = "nitro-home-disk v1 ";
pub const V2: &str = "nitro-home-disk v2 ";
/// A home's name, at most: the counter's object is named by it.
pub const HOME_BYTES_MAX: usize = 64;
pub const DISK_ID_BYTES: usize = 16;
/// KMS's ciphertext of a 32-byte key is about 184 bytes.
const WRAPPED_BYTES_MAX: usize = 1024;

const _: () = assert!(V2.len() + 4 * WRAPPED_BYTES_MAX / 3 + HOME_BYTES_MAX + 2 * DISK_ID_BYTES + 20 + 44 + 8 < BLOCK_BYTES, "a header fits in block 0");

/// Why a disk does not open. Each names what the guest saw, never a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    Malformed(&'static str),
    /// Its MAC does not verify under this disk's key: changed, or not a
    /// header this disk's home wrote.
    Forged,
    /// Another home's disk.
    OtherHome { found: String },
    /// The counter names another disk: this one is a stranger, or the home's
    /// own was replaced.
    OtherDisk,
    /// Older than the counter: a disk the parent kept.
    Older { header: u64, counter: u64 },
    /// Ahead of the counter by more than a stop can leave.
    Ahead { header: u64, counter: u64 },
    /// A disk with this home's header, and no counter: the counter was
    /// removed, or this is not its home.
    NoCounter,
    /// A blank or v1 disk, and a counter: an older form of a disk that has
    /// one, or a blank one in its place.
    Replaced,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Malformed(why) => write!(f, "the disk's header is malformed: {why}"),
            Refused::Forged => f.write_str("the disk's header does not verify under its own key"),
            Refused::OtherHome { found } => write!(f, "the disk is the home {found:?}'s, not this one's"),
            Refused::OtherDisk => f.write_str("the counter names another disk: this one is not this home's"),
            Refused::Older { header, counter } => write!(f, "the disk is at generation {header}, its counter at {counter}: an older copy of the disk"),
            Refused::Ahead { header, counter } => write!(f, "the disk is at generation {header}, its counter only at {counter}"),
            Refused::NoCounter => f.write_str("the disk has this home's header but its counter holds nothing: refused"),
            Refused::Replaced => f.write_str("the counter names this home's disk, and this disk is blank or of the older form: refused"),
        }
    }
}

impl std::error::Error for Refused {}

/// What block 0 says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    Blank,
    V1 { wrapped: Vec<u8> },
    V2(V2Header),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Header {
    pub wrapped: Vec<u8>,
    pub home: String,
    pub disk: [u8; DISK_ID_BYTES],
    pub generation: u64,
    mac: Vec<u8>,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub fn valid_home(home: &str) -> bool {
    !home.is_empty() && home.len() <= HOME_BYTES_MAX && home.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Block 0, read.
pub fn parse(block: &[u8]) -> Result<Header, Refused> {
    let text = block.split(|b| *b == 0).next().unwrap_or_default();
    if text.is_empty() {
        return Ok(Header::Blank);
    }
    let text = std::str::from_utf8(text).map_err(|_| Refused::Malformed("not text"))?;
    if let Some(wrapped) = text.strip_prefix(V1) {
        let wrapped = b64().decode(wrapped.trim()).map_err(|_| Refused::Malformed("v1's key is not base64"))?;
        return Ok(Header::V1 { wrapped });
    }
    let rest = text.strip_prefix(V2).ok_or(Refused::Malformed("neither v1 nor v2"))?;
    let fields: Vec<&str> = rest.split(' ').collect();
    let [wrapped, home, disk, generation, mac] = fields.as_slice() else {
        return Err(Refused::Malformed("v2 has five fields"));
    };
    let wrapped = b64().decode(wrapped).map_err(|_| Refused::Malformed("the key is not base64"))?;
    if wrapped.is_empty() || wrapped.len() > WRAPPED_BYTES_MAX {
        return Err(Refused::Malformed("the key's length"));
    }
    if !valid_home(home) {
        return Err(Refused::Malformed("the home's name"));
    }
    let disk: [u8; DISK_ID_BYTES] = hex::decode(disk).ok().and_then(|d| d.try_into().ok()).ok_or(Refused::Malformed("the disk's id"))?;
    let generation: u64 = generation.parse().map_err(|_| Refused::Malformed("the generation"))?;
    let mac = b64().decode(mac).map_err(|_| Refused::Malformed("the mac"))?;
    Ok(Header::V2(V2Header { wrapped, home: home.to_string(), disk, generation, mac }))
}

/// The keys the disk's key derives: one for its header, one for its counter.
/// They sign; they open nothing on the disk, so a running home keeps them
/// (on a tmpfs) for its raises while the disk's key is gone.
pub struct Macs {
    header: hmac::Key,
    counter: hmac::Key,
    raw: [u8; 64],
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

impl Macs {
    pub fn new(disk_key: &[u8; 32]) -> Macs {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"nitro-home disk v2").extract(disk_key);
        let mut raw = [0u8; 64];
        prk.expand(&[b"header"], Len(32)).expect("32 bytes").fill(&mut raw[..32]).expect("32 bytes");
        prk.expand(&[b"counter"], Len(32)).expect("32 bytes").fill(&mut raw[32..]).expect("32 bytes");
        Macs::from_raw(raw)
    }

    pub fn from_raw(raw: [u8; 64]) -> Macs {
        Macs { header: hmac::Key::new(hmac::HMAC_SHA256, &raw[..32]), counter: hmac::Key::new(hmac::HMAC_SHA256, &raw[32..]), raw }
    }

    pub fn raw(&self) -> &[u8; 64] {
        &self.raw
    }
}

fn header_message(wrapped: &[u8], home: &str, disk: &[u8; DISK_ID_BYTES], generation: u64) -> String {
    format!("{}{} {home} {} {generation}", V2, b64().encode(wrapped), hex::encode(disk))
}

/// Block 0 for a v2 header: the line, then NULs.
pub fn write(macs: &Macs, wrapped: &[u8], home: &str, disk: &[u8; DISK_ID_BYTES], generation: u64) -> Vec<u8> {
    assert!(valid_home(home), "a home's name is [A-Za-z0-9_-], 1 to {HOME_BYTES_MAX} bytes");
    assert!(!wrapped.is_empty() && wrapped.len() <= WRAPPED_BYTES_MAX, "a wrapped key's length");
    let message = header_message(wrapped, home, disk, generation);
    let mac = hmac::sign(&macs.header, message.as_bytes());
    let line = format!("{message} {}", b64().encode(mac.as_ref()));
    let mut block = line.into_bytes();
    assert!(block.len() < BLOCK_BYTES, "a header fits in block 0");
    block.resize(BLOCK_BYTES, 0);
    block
}

impl V2Header {
    /// Its MAC, checked under this disk's key, and its home, checked.
    pub fn verify(&self, macs: &Macs, home: &str) -> Result<(), Refused> {
        let message = header_message(&self.wrapped, &self.home, &self.disk, self.generation);
        hmac::verify(&macs.header, message.as_bytes(), &self.mac).map_err(|_| Refused::Forged)?;
        if self.home != home {
            return Err(Refused::OtherHome { found: self.home.clone() });
        }
        Ok(())
    }
}

/// The counter's record: the disk it names and its generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counter {
    pub disk: [u8; DISK_ID_BYTES],
    pub generation: u64,
}

impl Counter {
    pub fn to_json(&self, macs: &Macs) -> String {
        let message = format!("{} {}", hex::encode(self.disk), self.generation);
        let mac = hmac::sign(&macs.counter, message.as_bytes());
        serde_json::json!({ "v": 2, "disk": hex::encode(self.disk), "generation": self.generation, "mac": b64().encode(mac.as_ref()) }).to_string()
    }

    /// The record, checked under the disk's key: a record no holder of this
    /// disk's key wrote is another disk's.
    pub fn from_json(text: &[u8], macs: &Macs) -> Result<Counter, Refused> {
        let v: serde_json::Value = serde_json::from_slice(text).map_err(|_| Refused::Malformed("the counter is not JSON"))?;
        let disk: [u8; DISK_ID_BYTES] = v["disk"].as_str().and_then(|d| hex::decode(d).ok()).and_then(|d| d.try_into().ok()).ok_or(Refused::Malformed("the counter's disk"))?;
        let generation = v["generation"].as_u64().ok_or(Refused::Malformed("the counter's generation"))?;
        let mac = v["mac"].as_str().and_then(|m| b64().decode(m).ok()).ok_or(Refused::Malformed("the counter's mac"))?;
        let message = format!("{} {generation}", hex::encode(disk));
        hmac::verify(&macs.counter, message.as_bytes(), &mac).map_err(|_| Refused::OtherDisk)?;
        Ok(Counter { disk, generation })
    }
}

/// What a v2 disk and its counter allow: the generation this open moves
/// both to.
///
/// A header at generation 1 with no counter is a first open that stopped
/// before the counter's write (the header is written first): its counter is
/// made now. Past 1, a missing counter is refused.
pub fn admit(header: &V2Header, counter: Option<&Counter>) -> Result<u64, Refused> {
    let Some(counter) = counter else {
        return if header.generation == 1 { Ok(2) } else { Err(Refused::NoCounter) };
    };
    if counter.disk != header.disk {
        return Err(Refused::OtherDisk);
    }
    let (h, c) = (header.generation, counter.generation);
    if h < c {
        return Err(Refused::Older { header: h, counter: c });
    }
    if h > c + 1 {
        return Err(Refused::Ahead { header: h, counter: c });
    }
    Ok(h.max(c).checked_add(1).expect("a disk's generations fit in u64"))
}

/// A blank or v1 disk may become v2 only while the home's counter holds
/// nothing: after that, such a disk is an older form, or a stand-in.
pub fn admit_first(counter_exists: bool) -> Result<(), Refused> {
    if counter_exists {
        Err(Refused::Replaced)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [3; 32];
    const DISK: [u8; DISK_ID_BYTES] = [9; DISK_ID_BYTES];

    fn header(generation: u64) -> V2Header {
        let block = write(&Macs::new(&KEY), b"wrapped-key", "home-1", &DISK, generation);
        match parse(&block).unwrap() {
            Header::V2(h) => h,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_header_round_trips_and_fits_its_block() {
        let block = write(&Macs::new(&KEY), b"wrapped-key", "home-1", &DISK, 7);
        assert_eq!(block.len(), BLOCK_BYTES);
        let h = header(7);
        assert_eq!((h.wrapped.as_slice(), h.home.as_str(), h.disk, h.generation), (b"wrapped-key".as_slice(), "home-1", DISK, 7));
        h.verify(&Macs::new(&KEY), "home-1").unwrap();
        assert_eq!(parse(&[0u8; BLOCK_BYTES]).unwrap(), Header::Blank);
        assert_eq!(parse(format!("{V1}d3JhcHBlZA==").as_bytes()).unwrap(), Header::V1 { wrapped: b"wrapped".to_vec() });
    }

    #[test]
    fn a_changed_or_foreign_header_is_refused() {
        let h = header(7);
        assert_eq!(h.verify(&Macs::new(&[4; 32]), "home-1"), Err(Refused::Forged), "another disk's key");
        assert_eq!(h.verify(&Macs::new(&KEY), "home-2"), Err(Refused::OtherHome { found: "home-1".into() }));
        let mut raised = h.clone();
        raised.generation = 8;
        assert_eq!(raised.verify(&Macs::new(&KEY), "home-1"), Err(Refused::Forged), "a generation raised without the key");
        let mut moved = h.clone();
        moved.home = "home-2".into();
        assert_eq!(moved.verify(&Macs::new(&KEY), "home-2"), Err(Refused::Forged), "a home renamed without the key");
        assert!(matches!(parse(b"something else"), Err(Refused::Malformed(_))));
        assert!(matches!(parse(format!("{V2}a b c d").as_bytes()), Err(Refused::Malformed(_))));
    }

    #[test]
    fn the_counter_decides_which_generation_opens() {
        let at = |g| Counter { disk: DISK, generation: g };
        assert_eq!(admit(&header(5), Some(&at(5))), Ok(6), "the same generation: raised by one");
        assert_eq!(admit(&header(6), Some(&at(5))), Ok(7), "one ahead: a stop between the two writes");
        assert_eq!(admit(&header(4), Some(&at(5))), Err(Refused::Older { header: 4, counter: 5 }));
        assert_eq!(admit(&header(7), Some(&at(5))), Err(Refused::Ahead { header: 7, counter: 5 }));
        assert_eq!(admit(&header(5), None), Err(Refused::NoCounter));
        assert_eq!(admit(&header(1), None), Ok(2), "a first open stopped before its counter's write");
        let other = Counter { disk: [1; DISK_ID_BYTES], generation: 5 };
        assert_eq!(admit(&header(5), Some(&other)), Err(Refused::OtherDisk));
        assert_eq!(admit_first(false), Ok(()));
        assert_eq!(admit_first(true), Err(Refused::Replaced));
    }

    #[test]
    fn the_raw_macs_sign_as_the_derived_ones() {
        let macs = Macs::new(&KEY);
        let again = Macs::from_raw(*macs.raw());
        let block = write(&again, b"wrapped-key", "home-1", &DISK, 3);
        let Header::V2(h) = parse(&block).unwrap() else { panic!() };
        h.verify(&macs, "home-1").unwrap();
        assert_ne!(&macs.raw()[..32], &KEY, "derived, not the disk's key");
    }

    #[test]
    fn a_counter_record_opens_only_under_its_disk_s_key() {
        let macs = Macs::new(&KEY);
        let record = Counter { disk: DISK, generation: 12 }.to_json(&macs);
        assert_eq!(Counter::from_json(record.as_bytes(), &macs).unwrap(), Counter { disk: DISK, generation: 12 });
        assert_eq!(Counter::from_json(record.as_bytes(), &Macs::new(&[4; 32])), Err(Refused::OtherDisk));
        let raised = record.replace("\"generation\":12", "\"generation\":13");
        assert_eq!(Counter::from_json(raised.as_bytes(), &macs), Err(Refused::OtherDisk));
    }
}
