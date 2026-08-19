//! PIN-based encryption of the wallet's BIP-32 seed at rest.
//!
//! This wallet doesn't implement a wrong-PIN attempt counter/lockout (there's no display to
//! show a countdown, and Dabao's serial console makes any such state easy to reset by simply
//! power-cycling the on-chip counter store if it were separate from the ciphertext itself).
//! Instead, resistance to brute-forcing is achieved purely through *computational cost*: the
//! PIN is run through a deliberately expensive KDF ([`PBKDF2_ITERATIONS`] rounds of
//! PBKDF2-HMAC-SHA256) to derive the actual encryption key, so each guess -- whether typed at
//! the console or replayed against an extracted copy of the locked blob -- costs real CPU
//! time. This is a "one-time" PIN in the sense that it is fixed at wallet provisioning time
//! ([`Wallet::provision`]) and cannot be changed afterward; the wallet must be explicitly
//! [`Wallet::unlock`]ed with it again every session (e.g. after a reboot).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 64;
const TAG_LEN: usize = 16;
/// Total serialized size of a [`LockedSeed`]: `salt || nonce || (seed + AEAD tag)`.
pub const LOCKED_SEED_LEN: usize = SALT_LEN + NONCE_LEN + SEED_LEN + TAG_LEN;

/// Number of PBKDF2-HMAC-SHA256 rounds used to stretch the PIN into an encryption key.
/// Deliberately large: this is the *only* brute-force defense this scheme relies on, since
/// there is no attempt counter -- each unlock attempt (typed at the console, or replayed
/// offline against an extracted copy of the locked blob) must pay this cost.
///
/// This is a plain software CPU-bound cost, so it scales directly with whatever clock
/// speed/core count is doing the guessing. `100_000` rounds is calibrated to take roughly
/// 1-2 seconds on Dabao's `bao1x` core (a single RV32IMAC core in the few-hundred-MHz
/// range) -- noticeable but tolerable for a legitimate user unlocking once per session,
/// while still being expensive to brute-force at scale. This hasn't been measured on real
/// silicon in this change, so it's worth re-calibrating (by timing `LockedSeed::unlock` on
/// an actual device) and adjusting this constant if the tradeoff feels off in practice.
pub const PBKDF2_ITERATIONS: u32 = 100_000;

#[derive(Debug, PartialEq, Eq)]
pub enum PinError {
    /// AEAD authentication failed -- either the PIN was wrong, or the locked blob is corrupt.
    WrongPinOrCorrupt,
    /// The locked blob wasn't exactly [`LOCKED_SEED_LEN`] bytes.
    Malformed,
}

fn derive_key(pin: &str, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(pin.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key)
        .expect("HMAC can be initialized with any key length");
    key
}

/// A BIP-32 seed encrypted at rest under a PIN-derived key (see the module docs).
pub struct LockedSeed {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    /// `SEED_LEN` bytes of ciphertext followed by the 16-byte Poly1305 tag.
    ciphertext: Vec<u8>,
}

impl LockedSeed {
    /// Encrypts `seed` under a key derived from `pin`, using a fresh random salt and nonce
    /// from `rng`.
    pub fn lock<R: RngCore + CryptoRng>(seed: &[u8; SEED_LEN], pin: &str, rng: &mut R) -> Self {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);

        let mut key = derive_key(pin, &salt);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), seed.as_slice())
            .expect("encryption with a fixed-size key/nonce/plaintext cannot fail");
        key.zeroize();

        LockedSeed { salt, nonce: nonce_bytes, ciphertext }
    }

    /// Attempts to decrypt the seed with `pin`. Returns [`PinError::WrongPinOrCorrupt`] if
    /// `pin` doesn't match (the AEAD tag won't verify).
    pub fn unlock(&self, pin: &str) -> Result<[u8; SEED_LEN], PinError> {
        let mut key = derive_key(pin, &self.salt);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let result = cipher.decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_slice());
        key.zeroize();
        let plaintext = result.map_err(|_| PinError::WrongPinOrCorrupt)?;
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(&plaintext);
        Ok(seed)
    }

    /// Serializes to a fixed-size `[salt || nonce || ciphertext]` byte string, suitable for
    /// storing in e.g. `keystore` app-key slots.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LOCKED_SEED_LEN);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses the format produced by [`Self::to_bytes`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, PinError> {
        if data.len() != LOCKED_SEED_LEN {
            return Err(PinError::Malformed);
        }
        let salt: [u8; SALT_LEN] = data[..SALT_LEN].try_into().unwrap();
        let nonce: [u8; NONCE_LEN] = data[SALT_LEN..SALT_LEN + NONCE_LEN].try_into().unwrap();
        let ciphertext = data[SALT_LEN + NONCE_LEN..].to_vec();
        Ok(LockedSeed { salt, nonce, ciphertext })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeRng(u64);
    impl RngCore for FakeRng {
        fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for FakeRng {}

    #[test]
    fn lock_unlock_roundtrip() {
        let mut rng = FakeRng(1);
        let seed = [0x42u8; SEED_LEN];
        let locked = LockedSeed::lock(&seed, "1234", &mut rng);
        assert_eq!(locked.unlock("1234").unwrap(), seed);
    }

    #[test]
    fn wrong_pin_is_rejected() {
        let mut rng = FakeRng(2);
        let seed = [0x99u8; SEED_LEN];
        let locked = LockedSeed::lock(&seed, "correct horse", &mut rng);
        assert_eq!(locked.unlock("wrong pin"), Err(PinError::WrongPinOrCorrupt));
    }

    #[test]
    fn bytes_roundtrip_and_length() {
        let mut rng = FakeRng(3);
        let seed = [0x01u8; SEED_LEN];
        let locked = LockedSeed::lock(&seed, "0000", &mut rng);
        let bytes = locked.to_bytes();
        assert_eq!(bytes.len(), LOCKED_SEED_LEN);
        let reparsed = LockedSeed::from_bytes(&bytes).unwrap();
        assert_eq!(reparsed.unlock("0000").unwrap(), seed);
    }

    #[test]
    fn malformed_bytes_rejected() {
        match LockedSeed::from_bytes(&[0u8; 10]) {
            Err(PinError::Malformed) => {}
            other => panic!("expected Malformed, got {:?}", other.map(|_| ())),
        }
    }
}
