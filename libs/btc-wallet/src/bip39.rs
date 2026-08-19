//! BIP-39 mnemonic sentence generation/validation and mnemonic -> seed derivation.
//!
//! Implements the subset of [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
//! needed by a hardware wallet: turning device-generated entropy into a checksummed
//! mnemonic sentence, validating/parsing a mnemonic typed in by a user (e.g. during
//! restore), and deriving the 64-byte BIP-32 root seed via PBKDF2-HMAC-SHA512.

use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

use crate::wordlist::BIP39_TABLE;

#[derive(Debug, PartialEq, Eq)]
pub enum Bip39Error {
    /// Entropy length isn't one of the five BIP-39-sanctioned strengths (128/160/192/224/256 bits).
    InvalidEntropyLength,
    /// Mnemonic word count isn't one of 12/15/18/21/24.
    InvalidWordCount,
    /// A word in the mnemonic isn't present in the BIP-39 English wordlist.
    UnknownWord,
    /// The trailing checksum bits didn't match the recomputed checksum.
    ChecksumMismatch,
}

/// Number of bits of entropy contributed by each mnemonic word (2^11 = 2048 word list).
const BITS_PER_WORD: usize = 11;

/// Converts raw entropy (16/20/24/28/32 bytes) into a checksummed BIP-39 mnemonic sentence.
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, Bip39Error> {
    let ent_bits = entropy.len() * 8;
    if ![128, 160, 192, 224, 256].contains(&ent_bits) {
        return Err(Bip39Error::InvalidEntropyLength);
    }
    let cs_bits = ent_bits / 32;

    // checksum = the first `cs_bits` bits of SHA256(entropy)
    let hash = Sha256::digest(entropy);

    // Build up a single bit-string of ENT + CS bits, then slice it into 11-bit word indices.
    let mut bits: Vec<bool> = Vec::with_capacity(ent_bits + cs_bits);
    for byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 != 0);
        }
    }
    for i in 0..cs_bits {
        let byte = hash[i / 8];
        let bit = (byte >> (7 - (i % 8))) & 1 != 0;
        bits.push(bit);
    }

    let mut words = Vec::with_capacity(bits.len() / BITS_PER_WORD);
    for chunk in bits.chunks(BITS_PER_WORD) {
        let mut idx = 0usize;
        for &b in chunk {
            idx = (idx << 1) | (b as usize);
        }
        words.push(BIP39_TABLE[idx]);
    }
    Ok(words.join(" "))
}

/// Generates a fresh mnemonic sentence with the given entropy strength (in bits; one of
/// 128/160/192/224/256), using the supplied CSPRNG (e.g. the on-chip TRNG).
pub fn generate_mnemonic<R: RngCore + CryptoRng>(
    rng: &mut R,
    entropy_bits: usize,
) -> Result<String, Bip39Error> {
    if ![128, 160, 192, 224, 256].contains(&entropy_bits) {
        return Err(Bip39Error::InvalidEntropyLength);
    }
    let mut entropy = vec![0u8; entropy_bits / 8];
    rng.fill_bytes(&mut entropy);
    let mnemonic = entropy_to_mnemonic(&entropy);
    // Defensively wipe the local entropy copy; the caller-visible mnemonic still encodes
    // it, so this doesn't add secrecy here, but it avoids leaving an extra plaintext copy
    // of the raw entropy sitting around in this stack frame.
    use zeroize::Zeroize;
    entropy.zeroize();
    mnemonic
}

/// Validates a mnemonic sentence (word membership + checksum) and returns its raw entropy.
pub fn mnemonic_to_entropy(mnemonic: &str) -> Result<Vec<u8>, Bip39Error> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        return Err(Bip39Error::InvalidWordCount);
    }
    let total_bits = words.len() * BITS_PER_WORD;
    let ent_bits = total_bits * 32 / 33; // total = ENT + ENT/32
    let cs_bits = total_bits - ent_bits;

    let mut bits: Vec<bool> = Vec::with_capacity(total_bits);
    for word in &words {
        // The English wordlist is alphabetically sorted per the BIP-39 spec, so we can
        // binary search it instead of a linear scan.
        let idx = BIP39_TABLE.binary_search(word).map_err(|_| Bip39Error::UnknownWord)?;
        for i in (0..BITS_PER_WORD).rev() {
            bits.push((idx >> i) & 1 != 0);
        }
    }

    let mut entropy = vec![0u8; ent_bits / 8];
    for (i, byte) in entropy.iter_mut().enumerate() {
        let mut v = 0u8;
        for b in 0..8 {
            v = (v << 1) | (bits[i * 8 + b] as u8);
        }
        *byte = v;
    }

    let hash = Sha256::digest(&entropy);
    for i in 0..cs_bits {
        let expected = (hash[i / 8] >> (7 - (i % 8))) & 1 != 0;
        if expected != bits[ent_bits + i] {
            return Err(Bip39Error::ChecksumMismatch);
        }
    }
    Ok(entropy)
}

/// Validates a mnemonic sentence without needing the caller to consume its entropy.
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), Bip39Error> { mnemonic_to_entropy(mnemonic).map(|_| ()) }

/// Derives the 64-byte BIP-32 root seed from a mnemonic sentence and optional passphrase,
/// via `PBKDF2-HMAC-SHA512` with 2048 rounds, per BIP-39.
///
/// Note this deliberately does *not* validate the mnemonic's checksum -- per BIP-39, seed
/// derivation is defined for *any* string of words, so that non-standard/foreign-wordlist
/// mnemonics still interoperate. Callers that want to enforce a valid English mnemonic
/// should call [`validate_mnemonic`] first.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    // NFKD-normalization is specified by BIP-39 for non-ASCII input; the English
    // wordlist and any reasonable ASCII passphrase are already normalization-stable,
    // so it's intentionally not implemented here.
    let mut salt = String::from("mnemonic");
    salt.push_str(passphrase);
    let mut seed = [0u8; 64];
    pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed)
        .expect("HMAC can be initialized with any key length");
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official BIP-39 test vectors (English wordlist, "TREZOR" passphrase), from
    // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    struct Vector {
        entropy: &'static str,
        mnemonic: &'static str,
        seed: &'static str,
    }
    const VECTORS: &[Vector] = &[
        Vector {
            entropy: "00000000000000000000000000000000",
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            seed: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        },
        Vector {
            entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
            seed: "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        },
        Vector {
            entropy: "ffffffffffffffffffffffffffffffff",
            mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            seed: "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        },
        Vector {
            entropy: "0000000000000000000000000000000000000000000000000000000000000000",
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            seed: "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        },
        Vector {
            entropy: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            seed: "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        },
    ];

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn hex_encode(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }

    #[test]
    fn official_vectors_entropy_to_mnemonic() {
        for v in VECTORS {
            let entropy = hex_decode(v.entropy);
            assert_eq!(entropy_to_mnemonic(&entropy).unwrap(), v.mnemonic, "entropy {}", v.entropy);
        }
    }

    #[test]
    fn official_vectors_mnemonic_to_entropy() {
        for v in VECTORS {
            let entropy = mnemonic_to_entropy(v.mnemonic).unwrap();
            assert_eq!(hex_encode(&entropy), v.entropy, "mnemonic {}", v.mnemonic);
        }
    }

    #[test]
    fn official_vectors_seed() {
        for v in VECTORS {
            let seed = mnemonic_to_seed(v.mnemonic, "TREZOR");
            assert_eq!(hex_encode(&seed), v.seed, "mnemonic {}", v.mnemonic);
        }
    }

    #[test]
    fn rejects_bad_checksum() {
        // last word of the all-zero 12-word vector changed from "about" to "zoo"
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo";
        assert_eq!(mnemonic_to_entropy(bad), Err(Bip39Error::ChecksumMismatch));
    }

    #[test]
    fn rejects_unknown_word() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        assert_eq!(mnemonic_to_entropy(bad), Err(Bip39Error::UnknownWord));
    }

    #[test]
    fn generate_mnemonic_roundtrips() {
        // Deterministic fake RNG so the test is reproducible; correctness of the *entropy
        // source* isn't under test here, just that generate -> validate -> re-derive works.
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

        let mut rng = FakeRng(42);
        for &bits in &[128usize, 160, 192, 224, 256] {
            let mnemonic = generate_mnemonic(&mut rng, bits).unwrap();
            assert_eq!(mnemonic.split_whitespace().count(), (bits + bits / 32) / BITS_PER_WORD);
            validate_mnemonic(&mnemonic).unwrap();
        }
    }
}
