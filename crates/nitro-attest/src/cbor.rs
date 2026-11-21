//! A reader for the CBOR an attestation document is made of, and nothing
//! more: integers, byte and text strings of definite length, arrays and
//! maps of definite or indefinite length (the NSM writes its payload's map
//! as an indefinite one, closed by a break), one tag, and null. It is schema-directed, so the caller says what
//! comes next and nothing recurses; every string it hands back is a slice
//! of the input, so no length in the input can make it allocate.

use thiserror::Error;

use crate::AttestError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Uint,
    Negative,
    Bytes,
    Text,
    Array,
    Map,
    Tag,
    Simple,
}

impl Kind {
    fn of(major: u8) -> Kind {
        match major {
            0 => Kind::Uint,
            1 => Kind::Negative,
            2 => Kind::Bytes,
            3 => Kind::Text,
            4 => Kind::Array,
            5 => Kind::Map,
            6 => Kind::Tag,
            _ => Kind::Simple,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CborFault {
    #[error("the input ends inside an item")]
    Truncated,
    #[error("an indefinite length where only a map or an array may have one")]
    Indefinite,
    #[error("a break (0xff) outside an indefinite map or array")]
    Break,
    #[error("a reserved additional-information value")]
    Reserved,
    #[error("expected {expected:?}, found {found:?}")]
    Type { expected: Kind, found: Kind },
    #[error("a simple value other than null ({0})")]
    Simple(u8),
    #[error("text that is not UTF-8")]
    NotUtf8,
    #[error("bytes after the last item")]
    Trailing,
}

/// The null simple value (major 7, 22).
const NULL: u8 = 0xf6;
/// An indefinite array's and map's first bytes, and the break that ends
/// either.
const ARRAY_INDEFINITE: u8 = 0x9f;
const MAP_INDEFINITE: u8 = 0xbf;
const BREAK: u8 = 0xff;

/// A map's or an array's length: a count, or "until the break".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Count {
    Definite(u64),
    Indefinite,
}

pub(crate) struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Reader<'a> {
        Reader { input, at: 0 }
    }

    fn fault(&self, at: usize, fault: CborFault) -> AttestError {
        AttestError::Cbor { at, fault }
    }

    /// The next item's head: its kind and its argument (a value, a length
    /// or a count). Consumes it.
    fn head(&mut self) -> Result<(Kind, u64), AttestError> {
        let start = self.at;
        let Some(&initial) = self.input.get(self.at) else {
            return Err(self.fault(start, CborFault::Truncated));
        };
        let kind = Kind::of(initial >> 5);
        let info = initial & 0x1f;
        let extra = match info {
            0..=23 => 0,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 if initial == BREAK => return Err(self.fault(start, CborFault::Break)),
            31 => return Err(self.fault(start, CborFault::Indefinite)),
            _ => return Err(self.fault(start, CborFault::Reserved)),
        };
        let end = self.at + 1 + extra;
        if end > self.input.len() {
            return Err(self.fault(start, CborFault::Truncated));
        }
        let arg = if extra == 0 {
            u64::from(info)
        } else {
            let mut v = 0u64;
            for b in &self.input[self.at + 1..end] {
                v = (v << 8) | u64::from(*b);
            }
            v
        };
        self.at = end;
        Ok((kind, arg))
    }

    fn expect(&mut self, expected: Kind) -> Result<u64, AttestError> {
        let start = self.at;
        let (kind, arg) = self.head()?;
        if kind == expected {
            Ok(arg)
        } else {
            Err(self.fault(start, CborFault::Type { expected, found: kind }))
        }
    }

    /// A string's content: `len` bytes from here, within the input.
    fn content(&mut self, start: usize, len: u64) -> Result<&'a [u8], AttestError> {
        let remaining = (self.input.len() - self.at) as u64;
        if len > remaining {
            return Err(self.fault(start, CborFault::Truncated));
        }
        let end = self.at + len as usize;
        let s = &self.input[self.at..end];
        self.at = end;
        Ok(s)
    }

    pub fn uint(&mut self) -> Result<u64, AttestError> {
        self.expect(Kind::Uint)
    }

    /// A negative integer's argument `n`, whose value is `-1 - n`.
    pub fn negative(&mut self) -> Result<u64, AttestError> {
        self.expect(Kind::Negative)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], AttestError> {
        let start = self.at;
        let len = self.expect(Kind::Bytes)?;
        self.content(start, len)
    }

    pub fn text(&mut self) -> Result<&'a str, AttestError> {
        let start = self.at;
        let len = self.expect(Kind::Text)?;
        let s = self.content(start, len)?;
        std::str::from_utf8(s).map_err(|_| self.fault(start, CborFault::NotUtf8))
    }

    /// An array's count. The caller bounds it before it loops.
    pub fn array(&mut self) -> Result<u64, AttestError> {
        self.expect(Kind::Array)
    }

    /// A map's count of entries. The caller bounds it before it loops.
    pub fn map(&mut self) -> Result<u64, AttestError> {
        self.expect(Kind::Map)
    }

    fn counted(&mut self, kind: Kind, indefinite: u8) -> Result<Count, AttestError> {
        if self.input.get(self.at) == Some(&indefinite) {
            self.at += 1;
            Ok(Count::Indefinite)
        } else {
            self.expect(kind).map(Count::Definite)
        }
    }

    /// A map's length, definite or indefinite.
    pub fn map_count(&mut self) -> Result<Count, AttestError> {
        self.counted(Kind::Map, MAP_INDEFINITE)
    }

    /// An array's length, definite or indefinite.
    pub fn array_count(&mut self) -> Result<Count, AttestError> {
        self.counted(Kind::Array, ARRAY_INDEFINITE)
    }

    /// Whether the next byte is a break, consuming it if so.
    pub fn take_break(&mut self) -> bool {
        if self.input.get(self.at) == Some(&BREAK) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    /// Consumes tag `tag` if it comes next; any other item is left.
    pub fn tag_if(&mut self, tag: u64) -> Result<bool, AttestError> {
        let mark = self.at;
        let (kind, arg) = self.head()?;
        if kind == Kind::Tag && arg == tag {
            Ok(true)
        } else {
            self.at = mark;
            Ok(false)
        }
    }

    /// Null, or a byte string.
    pub fn null_or_bytes(&mut self) -> Result<Option<&'a [u8]>, AttestError> {
        match self.input.get(self.at) {
            Some(&NULL) => {
                self.at += 1;
                Ok(None)
            }
            Some(&b) if b >> 5 == 7 => Err(self.fault(self.at, CborFault::Simple(b & 0x1f))),
            _ => self.bytes().map(Some),
        }
    }

    /// The input must end here.
    pub fn finish(&self) -> Result<(), AttestError> {
        if self.at == self.input.len() {
            Ok(())
        } else {
            Err(self.fault(self.at, CborFault::Trailing))
        }
    }
}

/// Writes a head with the shortest argument, as the NSM's encoder does.
pub(crate) fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    assert!(major <= 7);
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= u64::from(u8::MAX) {
        out.extend_from_slice(&[m | 24, arg as u8]);
    } else if arg <= u64::from(u16::MAX) {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u64::from(u32::MAX) {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fault(r: Result<impl std::fmt::Debug, AttestError>) -> (usize, CborFault) {
        match r {
            Err(AttestError::Cbor { at, fault }) => (at, fault),
            other => panic!("expected a CBOR fault, got {other:?}"),
        }
    }

    // Goal: heads of every width read back as written, and the writer
    // picks the shortest. Method: each boundary and one past it.
    #[test]
    fn heads_round_trip_at_each_width() {
        for (arg, len) in [(0u64, 1usize), (23, 1), (24, 2), (255, 2), (256, 3), (65_535, 3), (65_536, 5), (u64::from(u32::MAX), 5), (u64::from(u32::MAX) + 1, 9), (u64::MAX, 9)] {
            let mut out = Vec::new();
            write_head(&mut out, 0, arg);
            assert_eq!(out.len(), len, "{arg}");
            let mut r = Reader::new(&out);
            assert_eq!(r.uint().unwrap(), arg);
            r.finish().unwrap();
        }
    }

    // Goal: no input makes the reader read past its end or allocate by a
    // length it was told. Method: a string claiming more than remains, and
    // every head cut short.
    #[test]
    fn truncation_is_a_fault_not_a_read() {
        assert_eq!(fault(Reader::new(&[0x5a, 0xff, 0xff, 0xff, 0xff, 1, 2]).bytes()), (0, CborFault::Truncated));
        assert_eq!(fault(Reader::new(&[0x19, 0x01]).uint()), (0, CborFault::Truncated));
        assert_eq!(fault(Reader::new(&[]).uint()), (0, CborFault::Truncated));
        let mut full = Vec::new();
        write_head(&mut full, 2, 300);
        full.extend(std::iter::repeat_n(7u8, 300));
        for cut in 0..full.len() {
            assert!(Reader::new(&full[..cut]).bytes().is_err(), "cut at {cut}");
        }
        assert_eq!(Reader::new(&full).bytes().unwrap().len(), 300);
    }

    // Goal: maps and arrays take either length; a break ends only an
    // indefinite one. Method: both forms, and a stray break.
    #[test]
    fn indefinite_maps_and_arrays() {
        let mut r = Reader::new(&[0xbf, 0x00, 0x01, 0xff]);
        assert_eq!(r.map_count().unwrap(), Count::Indefinite);
        assert!(!r.take_break());
        assert_eq!((r.uint().unwrap(), r.uint().unwrap()), (0, 1));
        assert!(r.take_break());
        r.finish().unwrap();
        assert_eq!(Reader::new(&[0x82]).array_count().unwrap(), Count::Definite(2));
        assert_eq!(Reader::new(&[0x9f]).array_count().unwrap(), Count::Indefinite);
        assert_eq!(fault(Reader::new(&[0xff]).uint()), (0, CborFault::Break));
        assert_eq!(fault(Reader::new(&[0xbf]).map()), (0, CborFault::Indefinite), "map() is definite only");
    }

    // Goal: what the NSM never writes is refused, never guessed at.
    #[test]
    fn indefinite_reserved_and_wrong_kinds_refused() {
        assert_eq!(fault(Reader::new(&[0x5f]).bytes()), (0, CborFault::Indefinite));
        assert_eq!(fault(Reader::new(&[0x1c]).uint()), (0, CborFault::Reserved));
        assert_eq!(fault(Reader::new(&[0x41, 0]).uint()), (0, CborFault::Type { expected: Kind::Uint, found: Kind::Bytes }));
        assert_eq!(fault(Reader::new(&[0x62, 0xff, 0xfe]).text()), (0, CborFault::NotUtf8));
        assert_eq!(fault(Reader::new(&[0xf5]).null_or_bytes()), (0, CborFault::Simple(21)));
        assert_eq!(Reader::new(&[0xf6]).null_or_bytes().unwrap(), None);
        let mut r = Reader::new(&[0x00, 0x00]);
        r.uint().unwrap();
        assert_eq!(fault(r.finish()), (1, CborFault::Trailing));
    }

    // Goal: an optional tag is consumed only when it is the one named.
    #[test]
    fn tag_if_leaves_other_items() {
        let mut r = Reader::new(&[0xd2, 0x80]);
        assert!(r.tag_if(18).unwrap());
        assert_eq!(r.array().unwrap(), 0);
        let mut r = Reader::new(&[0x80]);
        assert!(!r.tag_if(18).unwrap());
        assert_eq!(r.array().unwrap(), 0);
        let mut r = Reader::new(&[0xd1, 0x80]);
        assert!(!r.tag_if(18).unwrap(), "tag 17 is not 18");
    }
}
