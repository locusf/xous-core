//! Bech32 encoding ([BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki))
//! and native SegWit v0 (P2WPKH) address construction.
//!
//! Only plain Bech32 (not Bech32m/BIP-350) is implemented, since this wallet only supports
//! witness version 0 (P2WPKH) addresses.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// Generator polynomial constants from BIP-173's reference `bech32_polymod`.
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
/// XORed into the final checksum polymod; `1` for Bech32 (BIP-173), `0x2bc830a3` for Bech32m
/// (BIP-350, used by Taproot/witness v1+ -- not needed since we only emit witness v0).
const BECH32_CONST: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum Bech32Error {
    InvalidHrp,
    InvalidData,
    /// The witness program length doesn't match a valid P2WPKH program (20 bytes).
    InvalidWitnessProgramLength,
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = (chk & 0x1ff_ffff) << 5 ^ (v as u32);
        for (i, gen) in GENERATOR.iter().enumerate() {
            if (b >> i) & 1 != 0 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        v.push(b >> 5);
    }
    v.push(0);
    for b in hrp.bytes() {
        v.push(b & 31);
    }
    v
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let poly = polymod(&values) ^ BECH32_CONST;
    let mut out = [0u8; 6];
    for (i, o) in out.iter_mut().enumerate() {
        *o = ((poly >> (5 * (5 - i))) & 31) as u8;
    }
    out
}

/// Encodes `hrp` + 5-bit `data` values (not including the checksum) into a Bech32 string.
pub fn encode(hrp: &str, data: &[u8]) -> Result<String, Bech32Error> {
    if hrp.is_empty() || !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(Bech32Error::InvalidHrp);
    }
    if data.iter().any(|&d| d > 31) {
        return Err(Bech32Error::InvalidData);
    }
    let checksum = create_checksum(hrp, data);
    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for &d in data.iter().chain(checksum.iter()) {
        out.push(CHARSET[d as usize] as char);
    }
    Ok(out)
}

/// Regroups a byte slice from `frombits`-wide groups into `tobits`-wide groups (used to
/// convert the 8-bit witness program into Bech32's 5-bit alphabet and back).
fn convert_bits(data: &[u8], frombits: u32, tobits: u32, pad: bool) -> Result<Vec<u8>, Bech32Error> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv: u32 = (1 << tobits) - 1;
    let max_acc: u32 = (1 << (frombits + tobits - 1)) - 1;
    for &value in data {
        if (value as u32) >> frombits != 0 {
            return Err(Bech32Error::InvalidData);
        }
        acc = ((acc << frombits) | value as u32) & max_acc;
        bits += frombits;
        while bits >= tobits {
            bits -= tobits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (tobits - bits)) & maxv) as u8);
        }
    } else if bits >= frombits || ((acc << (tobits - bits)) & maxv) != 0 {
        return Err(Bech32Error::InvalidData);
    }
    Ok(ret)
}

/// Encodes a native SegWit v0 P2WPKH address from a 20-byte `HASH160(compressed pubkey)`
/// witness program.
pub fn encode_p2wpkh(hrp: &str, pubkey_hash: &[u8; 20]) -> Result<String, Bech32Error> {
    let mut data = vec![0u8]; // witness version 0
    data.extend(convert_bits(pubkey_hash, 8, 5, true)?);
    encode(hrp, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash160;

    // From BIP-173's own worked examples: pubkey
    // 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 (compressed G).
    const PUBKEY: &str = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    const MAINNET_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const TESTNET_ADDR: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn bip173_p2wpkh_vectors() {
        let pubkey = hex_decode(PUBKEY);
        let program = hash160(&pubkey);
        assert_eq!(encode_p2wpkh("bc", &program).unwrap(), MAINNET_ADDR);
        assert_eq!(encode_p2wpkh("tb", &program).unwrap(), TESTNET_ADDR);
    }

    #[test]
    fn rejects_bad_hrp() {
        assert_eq!(encode("", &[0]), Err(Bech32Error::InvalidHrp));
    }
}
