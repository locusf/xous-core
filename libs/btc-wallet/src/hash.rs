//! Small shared hash helpers used throughout the wallet (Bitcoin's `HASH256`/`HASH160`).

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Bitcoin's `HASH256`: double SHA-256.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    second.into()
}

/// Bitcoin's `HASH160`: RIPEMD-160(SHA-256(data)), used for P2PKH/P2WPKH pubkey hashes.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    ripe.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash160_known_vector() {
        // HASH160("") == RIPEMD160(SHA256("")); well-known constant used across the
        // Bitcoin ecosystem (e.g. it's OP_HASH160's output for an empty input).
        let h = hash160(b"");
        assert_eq!(hex(&h), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
    }

    #[test]
    fn sha256d_known_vector() {
        // SHA256d("") is a widely-published constant.
        let h = sha256d(b"");
        assert_eq!(hex(&h), "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
    }

    fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }
}
