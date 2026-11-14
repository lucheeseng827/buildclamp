//! Reading a document written by a newer buildclamp than the one reading it.
//!
//! The report is a wire format with a version gate ([`crate::Report::from_json`]), and
//! the gate answers the coarse question: a *higher* `format_version` is refused by name
//! rather than half-understood. This module answers the finer one — what happens to a
//! value inside a document whose version this build does accept, when that value is a
//! name this build has never heard of.
//!
//! Measured before it was fixed: `["net", "fs-read"]` in a report's `granted` list failed
//! with serde's `unknown variant` error, and because the failure is at the top of the
//! document the *whole run* was unreadable. One capability nobody here had implemented
//! made eight units, their request streams and their tiers vanish.
//!
//! `fs-read` has since shipped, which is the point rather than a footnote: the name chosen
//! as an example of something this build would never know became something it knows, and a
//! report written by the older build still has to read. The tests below use a name that has
//! not shipped, and whoever makes *that* one real should move them again rather than
//! deleting them. That is the wrong
//! direction for the same reason the version gate exists: a report that fails to load
//! sends a person to look for a bug in the tool, while a report short by one field reads
//! exactly like a clean run.
//!
//! # Why a wrapper rather than an `Unknown` variant on each enum
//!
//! The obvious shape is `#[serde(other)] Unknown(String)` on [`crate::Capability`]. It
//! cannot be had, twice over:
//!
//! * `#[serde(other)]` is only supported on unit variants of internally- and
//!   adjacently-tagged enums. `Capability` is an ordinary string enum, so serde rejects
//!   the attribute outright.
//! * A variant carrying a `String` would cost `Capability` its `Copy` and its
//!   fieldless-ness, and [`crate::CapabilitySet`] is a `u8` bitmask built with
//!   `1 << (c as u8)`. A payload-carrying variant has no discriminant to shift by, so
//!   the whole set type would have to become an allocating collection — to represent a
//!   capability this build cannot enforce, grant or reason about anyway.
//!
//! So the closed enums stay closed, which is a property `capability.rs` argues for at
//! length, and the tolerance lives at the wire positions where an unrecognised name can
//! actually arrive. `Forward<T>` serialises as the plain string either way, so an
//! unknown name **round-trips verbatim**: a reader that re-emits a document does not
//! quietly rewrite `fs-read` as `unknown`, which would be a worse failure than refusing
//! to read it at all.

use std::fmt;

use serde::de::value::{Error as ValueError, StrDeserializer};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A value read from a document, which may be a name this build does not know.
///
/// Ordering, equality and hashing are derived, so a `Forward<Capability>` works as a
/// `BTreeMap` key — which is what the report's `tiers` map needs. `Known` sorts before
/// `Unknown`, so a report's known capabilities keep the report order they have always
/// had and anything new sorts after them rather than interleaving.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Forward<T> {
    /// A name in this build's closed set.
    Known(T),
    /// A name that is not, carried verbatim so it survives being read and written again.
    Unknown(String),
}

impl<T> Forward<T> {
    /// The value, when this build understands it.
    pub fn known(&self) -> Option<&T> {
        match self {
            Forward::Known(t) => Some(t),
            Forward::Unknown(_) => None,
        }
    }

    /// Is this a name from a newer buildclamp?
    pub fn is_unknown(&self) -> bool {
        matches!(self, Forward::Unknown(_))
    }
}

impl<T: Copy> Forward<T> {
    /// The value by copy, for the closed `Copy` enums this wraps.
    pub fn copied(&self) -> Option<T> {
        match self {
            Forward::Known(t) => Some(*t),
            Forward::Unknown(_) => None,
        }
    }
}

impl<T> From<T> for Forward<T> {
    fn from(t: T) -> Self {
        Forward::Known(t)
    }
}

impl<T: fmt::Display> fmt::Display for Forward<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Forward::Known(t) => t.fmt(f),
            Forward::Unknown(s) => f.write_str(s),
        }
    }
}

impl<T: Serialize> Serialize for Forward<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            // The known value serialises as itself, so a document this build wrote is
            // byte-identical to one written before the wrapper existed.
            Forward::Known(t) => t.serialize(s),
            Forward::Unknown(u) => s.serialize_str(u),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Forward<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Read the string first, then offer it to `T`. Doing it the other way round —
        // trying `T` and falling back — would need the input buffered, which a
        // `Deserializer` does not promise. Every type this wraps is a string enum, so
        // there is nothing else it could have been.
        let s = String::deserialize(d)?;
        match T::deserialize(StrDeserializer::<ValueError>::new(&s)) {
            Ok(t) => Ok(Forward::Known(t)),
            Err(_) => Ok(Forward::Unknown(s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;

    #[test]
    fn a_known_name_is_indistinguishable_from_the_bare_enum_on_the_wire() {
        let f: Forward<Capability> = Capability::FsWrite.into();
        assert_eq!(serde_json::to_string(&f).unwrap(), "\"fs-write\"");
        assert_eq!(
            serde_json::to_string(&Capability::FsWrite).unwrap(),
            "\"fs-write\""
        );
    }

    #[test]
    fn a_capability_from_a_newer_buildclamp_round_trips_verbatim() {
        // The failure this exists for was measured with `fs-read`, which has since become
        // a real capability — so the example moved to one that has not. One unimplemented
        // capability used to make every unit, every request and every tier in the report
        // unreadable.
        let f: Forward<Capability> = serde_json::from_str("\"fs-append\"").unwrap();
        assert_eq!(f, Forward::Unknown("fs-append".into()));
        assert!(f.is_unknown());
        assert_eq!(f.copied(), None);
        // Verbatim, not rewritten as "unknown": a reader that re-emitted the document
        // having renamed a capability it did not recognise would corrupt it, which is
        // worse than having refused to read it.
        assert_eq!(serde_json::to_string(&f).unwrap(), "\"fs-append\"");
    }

    #[test]
    fn a_name_that_was_once_unknown_and_has_since_shipped_reads_as_known() {
        // The other direction, and the one a fleet actually hits: an older agent wrote
        // `fs-read` as a name this build did not have, this build has it now, and the
        // document must read as the capability rather than as a string that looks like it.
        let f: Forward<Capability> = serde_json::from_str("\"fs-read\"").unwrap();
        assert_eq!(f, Forward::Known(Capability::FsRead));
        assert!(!f.is_unknown());
    }

    #[test]
    fn it_keys_a_map_because_it_is_a_string_on_the_wire() {
        // The report's `tiers` is a map keyed by capability, and serde_json only accepts
        // map keys that serialise as strings.
        use std::collections::BTreeMap;
        let mut m: BTreeMap<Forward<Capability>, u8> = BTreeMap::new();
        m.insert(Capability::Net.into(), 1);
        m.insert(Forward::Unknown("fs-append".into()), 2);
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"net\""), "{json}");
        assert!(json.contains("\"fs-append\""), "{json}");
        let back: BTreeMap<Forward<Capability>, u8> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn known_names_sort_before_unknown_ones() {
        // So a report keeps the capability order it has always had, and anything a newer
        // agent adds sorts after it rather than interleaving and re-ordering the file.
        let mut v = vec![
            Forward::Unknown("fs-append".to_string()),
            Forward::Known(Capability::Exec),
            Forward::Known(Capability::Net),
        ];
        v.sort();
        assert_eq!(
            v,
            vec![
                Forward::Known(Capability::Net),
                Forward::Known(Capability::Exec),
                Forward::Unknown("fs-append".to_string()),
            ]
        );
    }
}
