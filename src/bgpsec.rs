//! Types for BGPsec.

use std::{error, fmt, str};
use std::str::FromStr;


//------------ KeyIdentifier -------------------------------------------------

/// A key identifier.
///
/// This is the SHA-1 hash over the public key’s bits.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct KeyIdentifier([u8; 20]);

impl KeyIdentifier {
    /// Returns an octet slice of the key identifier’s value.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Returns a octet array with the hex representation of the identifier.
    pub fn into_hex(self) -> [u8; 40] {
        let mut res = [0u8; 40];
        hex_encode(self.as_slice(), &mut res);
        res
    }
}


//--- From, TryFrom and FromStr

impl From<[u8; 20]> for KeyIdentifier {
    fn from(src: [u8; 20]) -> Self {
        KeyIdentifier(src)
    }
}

impl From<KeyIdentifier> for [u8; 20] {
    fn from(src: KeyIdentifier) -> Self {
        src.0
    }
}

impl<'a> TryFrom<&'a [u8]> for KeyIdentifier {
    type Error = KeyIdentifierSliceError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        value.try_into()
            .map(KeyIdentifier)
            .map_err(|_| KeyIdentifierSliceError)
    }
}

impl FromStr for KeyIdentifier {
    type Err = ParseKeyIdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 40 || !value.is_ascii() {
            return Err(ParseKeyIdentifierError)
        }
        let mut res = KeyIdentifier(Default::default());
        for (pos, ch) in value.as_bytes().chunks(2).enumerate() {
            let ch = unsafe { str::from_utf8_unchecked(ch) };
            res.0[pos] = u8::from_str_radix(ch, 16)
                            .map_err(|_| ParseKeyIdentifierError)?;
        }
        Ok(res)
    }
}


//--- AsRef

impl AsRef<[u8]> for KeyIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


//--- PartialEq

impl<T: AsRef<[u8]>> PartialEq<T> for KeyIdentifier {
    fn eq(&self, other: &T) -> bool {
        self.0.as_ref().eq(other.as_ref())
    }
}


//--- Display and Debug

impl fmt::Display for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; 40];
        write!(f, "{}", hex_encode(self.as_slice(), &mut buf))
    }
}

impl fmt::Debug for KeyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyIdentifier({})", self)
    }
}


//============ Helper ========================================================

/// Encodes a octet sequence as a hex string.
///
/// The function uses `dest` as the buffer for encoding which therefore must
/// be exactly twice the length of `src`. It returns a reference to this
/// buffer as a `&str`.
///
/// # Panics
///
/// The function panics if `dest` is shorter than twice the length of `src`.
fn hex_encode<'a>(src: &[u8], dest: &'a mut [u8]) -> &'a str {
    let dest = &mut dest[..src.len() * 2];
    for (s, d) in src.iter().zip(dest.chunks_mut(2)) {
        d[0] = HEX_DIGITS[usize::from(s >> 4)];
        d[1] = HEX_DIGITS[usize::from(s & 0x0F)];
    }
    unsafe { str::from_utf8_unchecked(dest) }
}

const HEX_DIGITS: &[u8] = b"0123456789ABCDEF";


//============ Errors ========================================================

//------------ KeyIdentifierSliceError ----------------------------------

/// Creating a prefix has failed.
#[derive(Clone, Debug)]
pub struct KeyIdentifierSliceError;

impl fmt::Display for KeyIdentifierSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid slice for key identifier")
    }
}

impl error::Error for KeyIdentifierSliceError { }


//------------ ParseKeyIdentifierError ---------------------------------------

/// Creating a prefix has failed.
#[derive(Clone, Debug)]
pub struct ParseKeyIdentifierError;

impl fmt::Display for ParseKeyIdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid key identifier")
    }
}

impl error::Error for ParseKeyIdentifierError { }

