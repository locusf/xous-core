//! BIP-32 hierarchical-deterministic key derivation, restricted to private-key ("CKDpriv")
//! derivation -- a hardware wallet always holds the private seed, so watch-only public-key
//! derivation isn't needed here.
//!
//! See [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

use hmac::{Hmac, Mac};
use k256::Scalar;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::PrimeField;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::base58;
use crate::hash::hash160;

type HmacSha512 = Hmac<Sha512>;

/// Set on a derivation-path component to request hardened derivation (BIP-32 `'`/`h` suffix).
pub const HARDENED_BIT: u32 = 0x8000_0000;

/// BIP-32 extended-public-key version bytes: mainnet, testnet.
const XPUB_VERSION_MAINNET: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const XPUB_VERSION_TESTNET: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];

#[derive(Debug, PartialEq, Eq)]
pub enum Bip32Error {
    /// The 512-bit HMAC output produced an invalid (>= curve order, or exactly zero) child
    /// key. Per BIP-32 this is astronomically unlikely (~1 in 2^127) and the spec's
    /// prescribed recovery is to derive with the next index instead; we simply surface it
    /// to the caller rather than silently doing that, since it should never trigger in practice.
    InvalidChild,
    /// Attempted non-hardened derivation of index >= 2^31, or a malformed path string.
    InvalidPath,
}

#[derive(Clone)]
pub struct ExtendedPrivKey {
    pub private_key: SigningKey,
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
}

impl Drop for ExtendedPrivKey {
    fn drop(&mut self) { self.chain_code.zeroize(); }
}

impl ExtendedPrivKey {
    /// Derives the master extended private key from a BIP-32/39 seed (typically 64 bytes,
    /// as produced by [`crate::bip39::mnemonic_to_seed`], though BIP-32 allows 16-64 bytes).
    pub fn master(seed: &[u8]) -> Result<Self, Bip32Error> {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC accepts any key length");
        mac.update(seed);
        let i = mac.finalize().into_bytes();
        let (il, ir) = i.split_at(32);

        let scalar = scalar_from_bytes(il).ok_or(Bip32Error::InvalidChild)?;
        let private_key = SigningKey::from_bytes(&scalar.to_bytes()).map_err(|_| Bip32Error::InvalidChild)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);
        Ok(ExtendedPrivKey { private_key, chain_code, depth: 0, parent_fingerprint: [0; 4], child_number: 0 })
    }

    /// The compressed SEC1 public key (33 bytes) corresponding to this node's private key.
    pub fn public_key_compressed(&self) -> [u8; 33] {
        let point = self.private_key.verifying_key().to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// The BIP-32 fingerprint of this node (first 4 bytes of `HASH160(compressed pubkey)`),
    /// used as the `parent_fingerprint` of any children it derives.
    pub fn fingerprint(&self) -> [u8; 4] {
        let h = hash160(&self.public_key_compressed());
        [h[0], h[1], h[2], h[3]]
    }

    /// Derives a single child key (`CKDpriv`). Set the high bit of `index` (or add
    /// [`HARDENED_BIT`]) to request hardened derivation.
    pub fn derive_child(&self, index: u32) -> Result<Self, Bip32Error> {
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("HMAC accepts any key length");
        if index & HARDENED_BIT != 0 {
            mac.update(&[0u8]);
            mac.update(&self.private_key.to_bytes());
        } else {
            mac.update(&self.public_key_compressed());
        }
        mac.update(&index.to_be_bytes());
        let i = mac.finalize().into_bytes();
        let (il, ir) = i.split_at(32);

        let il_scalar = scalar_from_bytes(il).ok_or(Bip32Error::InvalidChild)?;
        let parent_scalar = *self.private_key.as_nonzero_scalar().as_ref();
        let child_scalar = il_scalar + parent_scalar;
        if bool::from(k256::elliptic_curve::Field::is_zero(&child_scalar)) {
            return Err(Bip32Error::InvalidChild);
        }
        let private_key =
            SigningKey::from_bytes(&child_scalar.to_bytes()).map_err(|_| Bip32Error::InvalidChild)?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);
        Ok(ExtendedPrivKey {
            private_key,
            chain_code,
            depth: self.depth.wrapping_add(1),
            parent_fingerprint: self.fingerprint(),
            child_number: index,
        })
    }

    /// Derives a full path (e.g. the components of `m/84'/0'/0'/0/0`) starting from this node.
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, Bip32Error> {
        let mut node = self.clone();
        for &index in path {
            node = node.derive_child(index)?;
        }
        Ok(node)
    }

    /// Serializes this node's **public** half as a standard BIP-32 extended public key
    /// (`xpub.../tpub...`): `version || depth || parent_fingerprint || child_number ||
    /// chain_code || compressed_pubkey`, Base58Check-encoded.
    pub fn serialize_xpub(&self, testnet: bool) -> String {
        let mut payload = Vec::with_capacity(78);
        payload.extend_from_slice(if testnet { &XPUB_VERSION_TESTNET } else { &XPUB_VERSION_MAINNET });
        payload.push(self.depth);
        payload.extend_from_slice(&self.parent_fingerprint);
        payload.extend_from_slice(&self.child_number.to_be_bytes());
        payload.extend_from_slice(&self.chain_code);
        payload.extend_from_slice(&self.public_key_compressed());
        base58::encode_check(&payload)
    }
}

fn scalar_from_bytes(bytes: &[u8]) -> Option<Scalar> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Option::from(Scalar::from_repr(arr.into()))
}

/// Parses a BIP-32 derivation path string such as `"m/84'/0'/0'/0/0"` (or with `h` instead of
/// `'` for the hardened marker) into a list of raw (possibly-hardened) index values.
pub fn parse_path(path: &str) -> Result<Vec<u32>, Bip32Error> {
    let mut components = path.split('/');
    let first = components.next().ok_or(Bip32Error::InvalidPath)?;
    if first != "m" && first != "M" {
        return Err(Bip32Error::InvalidPath);
    }
    let mut out = Vec::new();
    for component in components {
        if component.is_empty() {
            return Err(Bip32Error::InvalidPath);
        }
        let (digits, hardened) = match component.strip_suffix(['\'', 'h', 'H']) {
            Some(d) => (d, true),
            None => (component, false),
        };
        let index: u32 = digits.parse().map_err(|_| Bip32Error::InvalidPath)?;
        if index & HARDENED_BIT != 0 {
            return Err(Bip32Error::InvalidPath);
        }
        out.push(if hardened { index | HARDENED_BIT } else { index });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::identity_op)] // "0 | HARDENED_BIT" spells out "index 0, hardened" for clarity
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }

    // BIP-32 official test vector 1, from
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
    // seed = 000102030405060708090a0b0c0d0e0f
    const SEED_1: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn vector1_master() {
        let seed = hex_decode(SEED_1);
        let m = ExtendedPrivKey::master(&seed).unwrap();
        assert_eq!(hex(&m.private_key.to_bytes()), "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        assert_eq!(hex(&m.chain_code), "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
    }

    #[test]
    fn vector1_m_0h() {
        // m/0'
        let seed = hex_decode(SEED_1);
        let m = ExtendedPrivKey::master(&seed).unwrap();
        let child = m.derive_child(0 | HARDENED_BIT).unwrap();
        assert_eq!(hex(&child.private_key.to_bytes()), "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea");
        assert_eq!(hex(&child.chain_code), "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
    }

    #[test]
    fn vector1_m_0h_1() {
        // m/0'/1
        let seed = hex_decode(SEED_1);
        let m = ExtendedPrivKey::master(&seed).unwrap();
        let child = m.derive_path(&[0 | HARDENED_BIT, 1]).unwrap();
        assert_eq!(hex(&child.private_key.to_bytes()), "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368");
        assert_eq!(hex(&child.chain_code), "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19");
    }

    #[test]
    fn vector1_xpub_serialization() {
        // BIP-32 official test vector 1, "ext pub" strings, from
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
        let seed = hex_decode(SEED_1);
        let m = ExtendedPrivKey::master(&seed).unwrap();
        assert_eq!(
            m.serialize_xpub(false),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );
        let child = m.derive_child(0 | HARDENED_BIT).unwrap();
        assert_eq!(
            child.serialize_xpub(false),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        );
    }

    #[test]
    fn parse_path_variants() {
        assert_eq!(
            parse_path("m/84'/0'/0'/0/0").unwrap(),
            vec![84 | HARDENED_BIT, 0 | HARDENED_BIT, 0 | HARDENED_BIT, 0, 0]
        );
        assert_eq!(
            parse_path("m/84h/0h/0h/0/0").unwrap(),
            vec![84 | HARDENED_BIT, 0 | HARDENED_BIT, 0 | HARDENED_BIT, 0, 0]
        );
        assert!(parse_path("m/2147483648").is_err()); // index already has the hardened bit set
        assert!(parse_path("84'/0'").is_err()); // missing leading "m/"
    }
}
