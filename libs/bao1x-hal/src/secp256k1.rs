//! secp256k1 ECDSA/ECDH support, built on RustCrypto's pure-Rust `k256` crate.
//!
//! This module is a thin convenience wrapper: it re-exports the `k256` types that
//! callers need and provides small helper functions that plug directly into any
//! `rand_core::{RngCore, CryptoRng}` source -- for example the on-chip TRNG exposed
//! by `bao1x-hal-service::trng::Trng` -- so callers don't need to take a direct
//! dependency on `k256`/`rand_core` themselves.
//!
//! Note this is unrelated to the `ed25519`/`curve25519` support used elsewhere in this
//! crate for the secure boot chain: that uses a Twisted Edwards curve (Curve25519),
//! whereas this module implements the short Weierstrass curve `secp256k1`.

pub use k256::ecdsa::signature::rand_core::CryptoRngCore;
pub use k256::ecdsa::signature::{Signer, Verifier};
pub use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
pub use k256::ecdh::{EphemeralSecret, SharedSecret};
pub use k256::elliptic_curve::sec1::ToEncodedPoint;
pub use k256::PublicKey;

/// Generates a new secp256k1 signing keypair using the supplied CSPRNG (e.g. the on-chip TRNG).
pub fn generate_keypair<R: CryptoRngCore>(rng: &mut R) -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::random(rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    (signing_key, verifying_key)
}

/// Signs a message with the given signing key. The message is hashed internally with SHA-256
/// (per RFC6979 deterministic ECDSA) before being signed.
pub fn sign(signing_key: &SigningKey, msg: &[u8]) -> Signature { signing_key.sign(msg) }

/// Verifies a message signature against a verifying (public) key. Returns `true` iff valid.
pub fn verify(verifying_key: &VerifyingKey, msg: &[u8], sig: &Signature) -> bool {
    verifying_key.verify(msg, sig).is_ok()
}

/// Performs an ephemeral ECDH key exchange against a counterparty's public key, returning our
/// ephemeral public key (to be sent to the counterparty) and the resulting shared secret.
pub fn ecdh_ephemeral<R: CryptoRngCore>(
    rng: &mut R,
    their_public: &PublicKey,
) -> (PublicKey, SharedSecret) {
    let our_secret = EphemeralSecret::random(rng);
    let our_public = PublicKey::from(&our_secret);
    let shared = our_secret.diffie_hellman(their_public);
    (our_public, shared)
}
