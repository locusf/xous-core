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

/// Minimum PIN length enforced at provisioning time by [`check_pin_strength`].
///
/// Because this scheme deliberately has no wrong-PIN attempt counter/lockout (see the module
/// docs above), the *only* thing standing between an attacker who has extracted a copy of the
/// locked-seed blob (e.g. by dumping the underlying storage directly, bypassing whatever
/// process-level access control the host OS would normally enforce) and the plaintext seed is
/// how long it takes to brute-force the PIN *offline*, at [`PBKDF2_ITERATIONS`] rounds of
/// PBKDF2-HMAC-SHA256 per guess. Unlike a memory-hard KDF (Argon2/scrypt), plain PBKDF2-SHA256
/// is cheap to parallelize on GPUs/FPGAs/ASICs, so a short numeric PIN's *entire* keyspace
/// (e.g. a 6-digit PIN is only 1,000,000 possibilities) can be exhausted in well under an hour
/// on commodity hardware, no matter how expensive each individual guess is made. Requiring a
/// longer PIN is the only lever this design has left to keep that offline keyspace large
/// enough to matter.
pub const MIN_PIN_LEN: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum PinError {
    /// AEAD authentication failed -- either the PIN was wrong, or the locked blob is corrupt.
    WrongPinOrCorrupt,
    /// The locked blob wasn't exactly [`LOCKED_SEED_LEN`] bytes.
    Malformed,
    /// The PIN didn't pass [`check_pin_strength`] -- see that function's docs for why this is
    /// enforced (this scheme has no lockout, so PIN entropy is the only real defense left
    /// against an attacker who has extracted a copy of the locked-seed blob).
    TooWeak,
}

/// Rejects PINs that would leave an extracted locked-seed blob too cheap to brute-force
/// offline, given this scheme's no-lockout design (see [`MIN_PIN_LEN`]'s docs). Specifically
/// rejects:
///   - PINs shorter than [`MIN_PIN_LEN`] characters,
///   - PINs made of a single repeated character (e.g. `"11111111"`), and
///   - purely ascending or descending runs (e.g. `"12345678"` / `"87654321"`),
///
/// since all three are exactly the patterns a real-world attacker's guess list would try
/// first, effectively for free, regardless of the raw keyspace size implied by the length
/// alone. This is a floor, not a full strength meter -- a longer, non-numeric PIN is always
/// better, but this catches the most common trivially-weak choices without requiring a
/// specific character-class mix (this is typed at a plain serial console with no display to
/// show a strength meter).
pub fn check_pin_strength(pin: &str) -> Result<(), PinError> {
    let bytes = pin.as_bytes();
    if bytes.len() < MIN_PIN_LEN {
        return Err(PinError::TooWeak);
    }
    if bytes.iter().all(|&b| b == bytes[0]) {
        return Err(PinError::TooWeak);
    }
    let is_monotonic_run = bytes.windows(2).all(|w| w[1] as i32 - w[0] as i32 == 1)
        || bytes.windows(2).all(|w| w[0] as i32 - w[1] as i32 == 1);
    if is_monotonic_run {
        return Err(PinError::TooWeak);
    }
    Ok(())
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

    #[test]
    fn short_pins_are_too_weak() {
        assert_eq!(check_pin_strength("1234"), Err(PinError::TooWeak));
        assert_eq!(check_pin_strength("1234567"), Err(PinError::TooWeak)); // one short of MIN_PIN_LEN
        assert_eq!(check_pin_strength(""), Err(PinError::TooWeak));
    }

    #[test]
    fn repeated_char_pins_are_too_weak() {
        assert_eq!(check_pin_strength("11111111"), Err(PinError::TooWeak));
        assert_eq!(check_pin_strength("aaaaaaaaaaaa"), Err(PinError::TooWeak));
    }

    #[test]
    fn monotonic_run_pins_are_too_weak() {
        assert_eq!(check_pin_strength("12345678"), Err(PinError::TooWeak));
        assert_eq!(check_pin_strength("87654321"), Err(PinError::TooWeak));
        assert_eq!(check_pin_strength("abcdefgh"), Err(PinError::TooWeak));
    }

    #[test]
    fn adequate_pins_are_accepted() {
        assert_eq!(check_pin_strength("13975108"), Ok(())); // 8 digits, not monotonic/repeated
        assert_eq!(check_pin_strength("correct horse battery staple"), Ok(()));
        assert_eq!(check_pin_strength(&("9".repeat(MIN_PIN_LEN - 1) + "0")), Ok(())); // exactly MIN_PIN_LEN, not all-repeated
    }
}
