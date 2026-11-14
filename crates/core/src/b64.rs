//! Standard base64, by hand, for the DSSE payload.
//!
//! # Why not the `base64` crate
//!
//! The same reason SHA-256 is in `sha256.rs` and the civil-date arithmetic is in
//! `civil.rs`: `Cargo.toml` keeps a list of what this tool deliberately does not depend on,
//! and the argument is always that a tool whose subject is what a build pulls in has to be
//! able to answer that question about itself. This is RFC 4648 §4, it is forty lines, and
//! the tests below are the RFC's own vectors.
//!
//! A signer outside this repository may well depend on `base64`, and that is not an
//! inconsistency: it already links `ring` for signing, so its closure is a different
//! shape and the trade is a different one.
//!
//! # Standard alphabet, not URL-safe
//!
//! DSSE's `payload` is standard base64 with padding — `+`, `/` and `=`. This project's own
//! `BCA1` envelope used URL-safe-no-pad, and the two are not interchangeable: decoding a
//! DSSE payload with a URL-safe decoder fails on any payload containing `+` or `/`, which
//! is most of them, and does so intermittently enough to look like a corrupt file.
//!
//! [`decode`] is deliberately **strict**: it rejects a character outside the alphabet,
//! wrong padding, and a length that cannot be a base64 encoding. A lenient decoder here
//! would accept two different strings as the same payload, and a signature covers bytes.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode with the standard alphabet and padding.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Everything a base64 string can be wrong about.
///
/// Named rather than collapsed into one error, because "this is not base64" and "this is
/// base64 of the wrong length" send a reader to different places — the first to the tool
/// that wrote the file, the second to whatever truncated it.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Base64Error {
    #[error("`{0}` is not a base64 character")]
    BadCharacter(char),
    #[error("the length is not a multiple of four, so this is not padded base64")]
    BadLength,
    #[error("padding appears before the end")]
    MisplacedPadding,
    #[error("the characters before the padding set bits the padding discards, so this is a second spelling of the same bytes")]
    NonCanonicalTail,
}

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode, strictly.
pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    let b = input.as_bytes();
    if !b.len().is_multiple_of(4) {
        return Err(Base64Error::BadLength);
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, quad) in b.as_chunks::<4>().0.iter().enumerate() {
        // `i + 1 == count` rather than `i == count - 1`: the second underflows on an empty
        // input, which is a legal encoding of no bytes.
        let last = i + 1 == b.len() / 4;
        let mut n: u32 = 0;
        let mut pads = 0usize;
        for (j, c) in quad.iter().enumerate() {
            if *c == b'=' {
                // Padding is only ever the last one or two characters of the last quad.
                // Anywhere else it is a string that decodes under a lenient reader and does
                // not under a strict one, which is two different payloads for one signature.
                if !last || j < 2 {
                    return Err(Base64Error::MisplacedPadding);
                }
                pads += 1;
                n <<= 6;
                continue;
            }
            // A character after padding within the same quad is the same ambiguity.
            if pads != 0 {
                return Err(Base64Error::MisplacedPadding);
            }
            let v = value(*c).ok_or(Base64Error::BadCharacter(*c as char))?;
            n = (n << 6) | v;
        }
        // The `pads` padding characters drop the last `pads` bytes of this quad, so the
        // sextets that fed them must be zero. If they are not, another string decodes to the
        // same bytes under a lenient reader — `Zg==` and `Zh==` both yield `f` — and a
        // signature covers bytes, so the two spellings would be one payload a signature could
        // be replayed across. `pads` is 0, 1 or 2, so the shift is always in range.
        if pads != 0 && n & ((1u32 << (8 * pads)) - 1) != 0 {
            return Err(Base64Error::NonCanonicalTail);
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pads]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded, "encoding {plain:?}");
            assert_eq!(
                decode(encoded).expect("the RFC's own vectors decode"),
                plain.as_bytes(),
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn the_two_characters_that_differ_from_the_url_safe_alphabet() {
        // `+` and `/`. A URL-safe decoder rejects both, which is why decoding a DSSE
        // payload with one fails on most payloads and looks like a corrupt file.
        let bytes = [0xfb, 0xff, 0xfe];
        let text = encode(&bytes);
        assert!(text.contains('+') || text.contains('/'), "{text}");
        assert_eq!(decode(&text).unwrap(), bytes);
    }

    #[test]
    fn every_byte_survives_a_round_trip() {
        for len in 0..200usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(decode(&encode(&bytes)).unwrap(), bytes, "length {len}");
        }
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn a_lenient_reading_is_refused() {
        // Each of these decodes under some base64 library and not under this one. A
        // signature covers bytes, so two strings that mean the same payload to a lenient
        // decoder are two payloads one signature could be replayed across.
        assert_eq!(decode("Zg="), Err(Base64Error::BadLength));
        assert_eq!(decode("Zm9vYg"), Err(Base64Error::BadLength)); // no padding
                                                                   // Eight characters, so the length check passes and the alphabet check is the one
                                                                   // that fires. `"Zm9v Zm9v"` would be nine and would be caught a step earlier.
        assert_eq!(decode("Zm9v Zm8"), Err(Base64Error::BadCharacter(' ')));
        assert_eq!(decode("Zm9-"), Err(Base64Error::BadCharacter('-'))); // URL-safe
        assert_eq!(decode("Zm9_"), Err(Base64Error::BadCharacter('_')));
        assert_eq!(decode("Zm==Zm9v"), Err(Base64Error::MisplacedPadding));
        assert_eq!(decode("Z==="), Err(Base64Error::MisplacedPadding));
        assert_eq!(decode("Zm=v"), Err(Base64Error::MisplacedPadding));
        // A newline, which is what a file that was wrapped at 76 columns contains.
        assert_eq!(decode("Zm9v\nZm9v"), Err(Base64Error::BadLength));
        // The tail must be canonical. `Zg==` is `f`; `Zh==` decodes to the same byte under a
        // lenient reader by setting bits the padding discards, and the canonical spelling of
        // the two bytes `Zm9=` claims is `ZmA=`. Both are refused — two strings, one payload
        // is the ambiguity a signature cannot tolerate.
        assert_eq!(decode("Zh=="), Err(Base64Error::NonCanonicalTail));
        assert_eq!(decode("Zm9="), Err(Base64Error::NonCanonicalTail));
        // The canonical spellings still decode.
        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("ZmA=").unwrap(), vec![0x66, 0x60]);
    }
}
