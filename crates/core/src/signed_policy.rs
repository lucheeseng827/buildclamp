//! Verifying that a policy layer was signed by a key the repository already trusts.
//!
//! # The authority model, and what it deliberately is not
//!
//! `policy_sha256` answers "is this the byte-identical policy that was recorded?" — a
//! content hash proves *integrity*, not *authority*. A curl'd bundle hashes the same as a
//! committed one, so a hash alone cannot say a policy came from someone allowed to write it.
//! This module adds the authority half: a detached Ed25519 signature over the policy bytes,
//! checked against a **trust root the customer commits in their own repository** (under
//! CODEOWNERS, so changing it is a reviewed act).
//!
//! Three properties hold by construction, and each is a design decision rather than an
//! accident:
//!
//! 1. **Verify only.** Nothing here can *sign*. The signing key lives with the signer,
//!    outside this repository; this binary can check a signature and never create one,
//!    so a reader of `cargo tree` sees a verifier, not a key holder.
//! 2. **No vendor key.** The trust root is always the customer's — passed in from their
//!    committed policy — and buildclamp compiles in no key of its own. A vendor key would
//!    make a vendor's key rotation or lapse a customer's build outage, and would make the
//!    vendor an authority over what the customer's builds may do. Neither is acceptable, and
//!    `no_vendor_key_is_compiled_in` (crates/cli) is the test that keeps it true.
//! 3. **One asymmetric-crypto implementation.** Verification is `ring`'s Ed25519, the same
//!    implementation a signer would use. A review then counts one implementation, not
//!    two, which is why `ed25519-dalek` is not used even though it would be the more
//!    obvious choice, and why this is not hand-written. See `SECURITY.md`.
//!
//! What this is NOT: a revocation system, a transport, or a fetch. Distribution — a pull
//! request against each repo, or a CI step that curls a signed bundle before the unmodified
//! binary runs — happens *outside* the enforcing binary, on purpose. The binary never makes
//! a live network request to decide a build; it verifies bytes that are already on disk.

use crate::b64;
use crate::sha256;
use ring::signature::{UnparsedPublicKey, ED25519};

/// The raw length of an Ed25519 public key, in bytes.
const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// The raw length of an Ed25519 signature, in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// A public key the repository trusts to sign policy layers.
///
/// Holds the 32 raw bytes and nothing more: there is no private half here and no way to
/// construct one, because this type exists in the free binary where signing must be
/// unreachable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TrustedKey {
    bytes: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl TrustedKey {
    /// Parse a base64-encoded 32-byte Ed25519 public key, the form it takes in a policy's
    /// `trust-root`.
    pub fn from_base64(s: &str) -> Result<Self, TrustRootError> {
        let raw = b64::decode(s.trim()).map_err(|_| TrustRootError::NotBase64)?;
        let bytes: [u8; ED25519_PUBLIC_KEY_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| TrustRootError::WrongKeyLength { found: raw.len() })?;
        Ok(TrustedKey { bytes })
    }

    /// A short, stable identifier for this key: the first 16 hex characters of the SHA-256
    /// of its bytes.
    ///
    /// It is content-derived so two repositories naming the same key agree on its id without
    /// coordinating, and short because it goes in a report a human reads. It is an *id*, not
    /// a security boundary — the verification is the signature check, not a string compare —
    /// so the content-naming SHA-256 in `sha256.rs` is the right tool for it.
    pub fn key_id(&self) -> String {
        sha256::hex(&self.bytes)[..16].to_string()
    }
}

/// The set of keys a repository trusts to have signed a policy layer.
///
/// A set rather than a single key so a customer can rotate: publish the new key alongside
/// the old, re-sign, then drop the old one, with no window in which builds break. Empty is a
/// legitimate state — a repository that has not adopted signed policy — and it verifies
/// nothing, which is why `--require-signed-policy` is a separate, explicit switch.
#[derive(Clone, Default, Debug)]
pub struct TrustRoot {
    keys: Vec<TrustedKey>,
}

impl TrustRoot {
    /// Build a trust root from the base64 keys a policy declares. Order is irrelevant;
    /// duplicates are harmless.
    pub fn from_base64_keys<I, S>(keys: I) -> Result<Self, TrustRootError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let keys = keys
            .into_iter()
            .map(|k| TrustedKey::from_base64(k.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TrustRoot { keys })
    }

    /// Whether the repository has declared any trust root at all.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// How many keys are trusted, for a `doctor`-style report.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Verify a detached signature over `message`.
    ///
    /// Returns the [`TrustedKey::key_id`] of the key that verified it, or `None` if no
    /// trusted key does — which covers an untrusted signer, a tampered message, a tampered
    /// or wrong-length signature, and an empty trust root, all as the same answer: not
    /// verified. The caller decides what a `None` means, and under `--require-signed-policy`
    /// it means refuse.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Option<String> {
        // A signature of the wrong length can never verify; ring would reject it, but
        // checking here keeps the intent legible and avoids handing ring a malformed input.
        if signature.len() != ED25519_SIGNATURE_LEN {
            return None;
        }
        self.keys.iter().find_map(|k| {
            UnparsedPublicKey::new(&ED25519, &k.bytes)
                .verify(message, signature)
                .ok()
                .map(|()| k.key_id())
        })
    }
}

/// A base64 detached signature, decoded to its raw bytes.
///
/// The distributed form of a signature is base64 in a sidecar file; this is the one place
/// that turns it into the bytes [`TrustRoot::verify`] wants, so a malformed signature is
/// rejected once, here, rather than misread downstream.
pub fn decode_signature(s: &str) -> Result<Vec<u8>, TrustRootError> {
    let raw = b64::decode(s.trim()).map_err(|_| TrustRootError::NotBase64)?;
    if raw.len() != ED25519_SIGNATURE_LEN {
        return Err(TrustRootError::WrongSignatureLength { found: raw.len() });
    }
    Ok(raw)
}

/// What went wrong parsing a trust root or a signature.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustRootError {
    /// A key or signature was not valid base64.
    #[error("trust-root value is not base64")]
    NotBase64,
    /// A key decoded to the wrong number of bytes for Ed25519.
    #[error("an Ed25519 public key is {ED25519_PUBLIC_KEY_LEN} bytes; this decoded to {found}")]
    WrongKeyLength {
        /// The length that was found.
        found: usize,
    },
    /// A signature decoded to the wrong number of bytes for Ed25519.
    #[error("an Ed25519 signature is {ED25519_SIGNATURE_LEN} bytes; this decoded to {found}")]
    WrongSignatureLength {
        /// The length that was found.
        found: usize,
    },
}

/// One layer's material for the signature check: its bytes, whether it is the committed
/// anchor, and its detached signature if it has one.
///
/// The bytes and the signature are read by the caller (the CLI does the I/O); the decision
/// about what they mean is made here, so it is testable with no files.
#[derive(Debug)]
pub struct LayerSignature<'a> {
    /// The layer's name, for naming an unverified one in a refusal.
    pub name: &'a str,
    /// The committed anchor — the repository's own `buildclamp.toml` — is trusted because it
    /// is committed under CODEOWNERS, not because it carries a signature. It is never
    /// signature-checked, and it is where the trust root itself is read from.
    pub is_anchor: bool,
    /// The exact bytes the signature is over.
    pub bytes: &'a [u8],
    /// The detached signature, if a `<layer>.sig` sidecar was present.
    pub signature: Option<&'a [u8]>,
}

/// What could be established about where a policy stack's layers came from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyProvenance {
    /// True iff every distributed (non-anchor) layer verified against the trust root.
    /// Vacuously true when there are no distributed layers — there was nothing unverified to
    /// let in. False the moment one distributed layer is unsigned or wrongly signed.
    pub signature_verified: bool,
    /// The ids of the trust-root keys that verified a layer, in layer order, deduplicated.
    /// Empty when nothing was verified.
    pub signer_key_ids: Vec<String>,
    /// The names of distributed layers that no trusted key verified.
    pub unverified_layers: Vec<String>,
}

impl PolicyProvenance {
    /// A single signer id for the report's `policy_signer_key_id`, when exactly one key
    /// signed. More than one (a rotation window, or several org layers) is reported as the
    /// joined set rather than a misleading single name.
    pub fn signer_key_id(&self) -> Option<String> {
        match self.signer_key_ids.as_slice() {
            [] => None,
            [one] => Some(one.clone()),
            many => Some(many.join(",")),
        }
    }
}

/// Decide the provenance of a policy stack, and under `require` refuse an unverified one.
///
/// The anchor is never checked — its authority is that it is committed. Every other layer is
/// a distributed one and must carry a signature a trust-root key verifies. With `require`
/// set, an unverified distributed layer is an error naming it, evaluated here before the
/// build starts rather than after a target directory is half written. Without `require`, an
/// unverified layer is recorded in the provenance and the build proceeds — the report then
/// shows `signature_verified = false`, which is visible rather than fatal.
pub fn check_layers(
    layers: &[LayerSignature],
    root: &TrustRoot,
    require: bool,
) -> Result<PolicyProvenance, SignedPolicyError> {
    let mut prov = PolicyProvenance {
        signature_verified: true,
        signer_key_ids: Vec::new(),
        unverified_layers: Vec::new(),
    };
    for layer in layers {
        if layer.is_anchor {
            continue;
        }
        let verified = layer
            .signature
            .and_then(|sig| root.verify(layer.bytes, sig));
        match verified {
            Some(key_id) => {
                if !prov.signer_key_ids.contains(&key_id) {
                    prov.signer_key_ids.push(key_id);
                }
            }
            None => {
                prov.signature_verified = false;
                prov.unverified_layers.push(layer.name.to_string());
            }
        }
    }
    if require && !prov.unverified_layers.is_empty() {
        return Err(SignedPolicyError::Unverified {
            layers: prov.unverified_layers.clone(),
        });
    }
    Ok(prov)
}

/// The build was refused because a distributed policy layer was not signed by a trusted key.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignedPolicyError {
    /// `--require-signed-policy` was set and these distributed layers did not verify.
    #[error(
        "--require-signed-policy is set, but these policy layers are not signed by any key \
         in the trust root: {}. A distributed layer must carry a detached `<layer>.sig` \
         made by a key the committed buildclamp.toml lists under `trust-root`.",
        layers.join(", ")
    )]
    Unverified {
        /// The distributed layers that no trusted key verified.
        layers: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// A throwaway signer, for producing the vectors the verifier is tested against. This
    /// uses ring's SIGNING API, which the shipped code never touches — the point of the test
    /// is that the verify-only path accepts exactly what a real signer produces.
    struct Signer {
        pair: Ed25519KeyPair,
    }

    impl Signer {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
            let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("from pkcs8");
            Signer { pair }
        }

        fn public_base64(&self) -> String {
            b64::encode(self.pair.public_key().as_ref())
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.pair.sign(message).as_ref().to_vec()
        }
    }

    #[test]
    fn a_signature_from_a_trusted_key_verifies_and_names_that_key() {
        let signer = Signer::new();
        let root = TrustRoot::from_base64_keys([signer.public_base64()]).unwrap();
        let msg = b"version = 1\n[defaults]\nhold-compile-units = true\n";
        let sig = signer.sign(msg);

        let key_id = root
            .verify(msg, &sig)
            .expect("a trusted signature verifies");
        // The id is the trusted key's own id, so a report can say which key vouched.
        assert_eq!(
            key_id,
            TrustedKey::from_base64(&signer.public_base64())
                .unwrap()
                .key_id()
        );
    }

    #[test]
    fn a_signature_from_an_untrusted_key_does_not_verify() {
        let trusted = Signer::new();
        let attacker = Signer::new();
        let root = TrustRoot::from_base64_keys([trusted.public_base64()]).unwrap();
        let msg = b"version = 1\n";
        // The attacker signs a perfectly valid signature — over the same bytes — with a key
        // the repository never trusted. Authority, not integrity, is what fails.
        let sig = attacker.sign(msg);
        assert_eq!(root.verify(msg, &sig), None);
    }

    #[test]
    fn a_tampered_message_does_not_verify() {
        let signer = Signer::new();
        let root = TrustRoot::from_base64_keys([signer.public_base64()]).unwrap();
        let sig = signer.sign(b"net = false\n");
        // One byte flipped in what the policy says.
        assert_eq!(root.verify(b"net = true\n", &sig), None);
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let signer = Signer::new();
        let root = TrustRoot::from_base64_keys([signer.public_base64()]).unwrap();
        let msg = b"version = 1\n";
        let mut sig = signer.sign(msg);
        sig[0] ^= 0x01;
        assert_eq!(root.verify(msg, &sig), None);
    }

    #[test]
    fn any_key_in_the_root_can_verify_which_is_what_makes_rotation_safe() {
        let old = Signer::new();
        let new = Signer::new();
        let root = TrustRoot::from_base64_keys([old.public_base64(), new.public_base64()]).unwrap();
        let msg = b"version = 2\n";
        // A bundle signed by EITHER key verifies, so a customer can add the new key, re-sign,
        // and retire the old one with no window where builds break.
        assert!(root.verify(msg, &old.sign(msg)).is_some());
        assert!(root.verify(msg, &new.sign(msg)).is_some());
    }

    #[test]
    fn an_empty_trust_root_verifies_nothing() {
        let signer = Signer::new();
        let root = TrustRoot::default();
        assert!(root.is_empty());
        // Even a genuine signature verifies against no keys: an empty root is "authority not
        // established", which is why requiring signatures is a separate switch.
        assert_eq!(root.verify(b"x", &signer.sign(b"x")), None);
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused_before_ring_sees_it() {
        let signer = Signer::new();
        let root = TrustRoot::from_base64_keys([signer.public_base64()]).unwrap();
        assert_eq!(root.verify(b"x", &[0u8; 10]), None);
        assert_eq!(root.verify(b"x", &[]), None);
    }

    #[test]
    fn a_key_that_is_not_thirty_two_bytes_is_refused() {
        assert_eq!(
            TrustedKey::from_base64(&b64::encode(&[0u8; 31])),
            Err(TrustRootError::WrongKeyLength { found: 31 })
        );
        assert_eq!(
            TrustedKey::from_base64("not base64!!!"),
            Err(TrustRootError::NotBase64)
        );
    }

    #[test]
    fn a_signature_decodes_from_base64_and_rejects_the_wrong_length() {
        let signer = Signer::new();
        let sig = signer.sign(b"m");
        let decoded = decode_signature(&b64::encode(&sig)).unwrap();
        assert_eq!(decoded, sig);
        assert_eq!(
            decode_signature(&b64::encode(&[0u8; 10])),
            Err(TrustRootError::WrongSignatureLength { found: 10 })
        );
    }

    #[test]
    fn the_key_id_is_stable_and_distinguishes_keys() {
        let a = Signer::new();
        let b = Signer::new();
        let ka = TrustedKey::from_base64(&a.public_base64()).unwrap();
        let kb = TrustedKey::from_base64(&b.public_base64()).unwrap();
        assert_eq!(ka.key_id(), ka.key_id(), "stable");
        assert_ne!(ka.key_id(), kb.key_id(), "distinguishes");
        assert_eq!(ka.key_id().len(), 16);
    }

    #[test]
    fn the_anchor_is_never_signature_checked() {
        // The repository's own committed policy is trusted because it is committed under
        // CODEOWNERS, not because it carries a signature. An anchor with no signature, and
        // no distributed layers beneath it, is fully verified: nothing unsigned got in.
        let root = TrustRoot::default();
        let anchor = LayerSignature {
            name: "repo",
            is_anchor: true,
            bytes: b"version = 1\n",
            signature: None,
        };
        let prov = check_layers(&[anchor], &root, true).expect("an anchor alone never refuses");
        assert!(prov.signature_verified);
        assert!(prov.signer_key_ids.is_empty());
    }

    #[test]
    fn a_signed_distributed_layer_verifies_and_names_its_signer() {
        let signer = Signer::new();
        let root = TrustRoot::from_base64_keys([signer.public_base64()]).unwrap();
        let org = b"[layer]\nname = \"org\"\n";
        let sig = signer.sign(org);
        let layers = [
            LayerSignature {
                name: "org",
                is_anchor: false,
                bytes: org,
                signature: Some(&sig),
            },
            LayerSignature {
                name: "repo",
                is_anchor: true,
                bytes: b"version = 1\n",
                signature: None,
            },
        ];
        let prov = check_layers(&layers, &root, true).expect("a signed layer is accepted");
        assert!(prov.signature_verified);
        assert_eq!(
            prov.signer_key_id().as_deref(),
            Some(signer_key(&signer)).as_deref()
        );
        assert!(prov.unverified_layers.is_empty());
    }

    #[test]
    fn an_unsigned_distributed_layer_is_recorded_and_refused_only_when_required() {
        let signer = Signer::new();
        let root = TrustRoot::from_base64_keys([signer.public_base64()]).unwrap();
        let layers = [LayerSignature {
            name: "org",
            is_anchor: false,
            bytes: b"[layer]\nname = \"org\"\n",
            signature: None,
        }];

        // Without the switch: recorded, not fatal. The report will show it.
        let prov = check_layers(&layers, &root, false).expect("not required, so not fatal");
        assert!(!prov.signature_verified);
        assert_eq!(prov.unverified_layers, vec!["org".to_string()]);

        // With the switch: refused, and the error names the layer.
        let err = check_layers(&layers, &root, true).unwrap_err();
        assert_eq!(
            err,
            SignedPolicyError::Unverified {
                layers: vec!["org".to_string()]
            }
        );
    }

    #[test]
    fn a_distributed_layer_signed_by_an_untrusted_key_does_not_pass() {
        let trusted = Signer::new();
        let attacker = Signer::new();
        let root = TrustRoot::from_base64_keys([trusted.public_base64()]).unwrap();
        let org = b"[layer]\nname = \"org\"\n";
        let sig = attacker.sign(org); // a real signature, wrong signer
        let layers = [LayerSignature {
            name: "org",
            is_anchor: false,
            bytes: org,
            signature: Some(&sig),
        }];
        let err = check_layers(&layers, &root, true).unwrap_err();
        assert!(matches!(err, SignedPolicyError::Unverified { .. }));
    }

    #[test]
    fn two_signers_are_reported_as_a_set_not_a_single_misleading_name() {
        let a = Signer::new();
        let b = Signer::new();
        let root = TrustRoot::from_base64_keys([a.public_base64(), b.public_base64()]).unwrap();
        let l1 = b"[layer]\nname = \"a\"\n";
        let l2 = b"[layer]\nname = \"b\"\n";
        let s1 = a.sign(l1);
        let s2 = b.sign(l2);
        let layers = [
            LayerSignature {
                name: "a",
                is_anchor: false,
                bytes: l1,
                signature: Some(&s1),
            },
            LayerSignature {
                name: "b",
                is_anchor: false,
                bytes: l2,
                signature: Some(&s2),
            },
        ];
        let prov = check_layers(&layers, &root, true).unwrap();
        assert!(prov.signature_verified);
        assert_eq!(prov.signer_key_ids.len(), 2);
        assert!(prov.signer_key_id().unwrap().contains(','));
    }

    fn signer_key(s: &Signer) -> String {
        TrustedKey::from_base64(&s.public_base64())
            .unwrap()
            .key_id()
    }
}
