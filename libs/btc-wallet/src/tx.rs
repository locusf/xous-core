//! Minimal Bitcoin transaction data model: legacy (non-witness) serialization/parsing (the
//! form used by `PSBT_GLOBAL_UNSIGNED_TX`, per BIP-174), witness-serialization for producing
//! a final broadcastable transaction, and BIP-143 segwit v0 sighash computation.

use k256::ecdsa::SigningKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;

use crate::hash::sha256d;
use crate::varint::{read_varbytes, read_varint, write_varbytes, write_varint};

pub const SIGHASH_ALL: u32 = 0x01;
pub const SIGHASH_NONE: u32 = 0x02;
pub const SIGHASH_SINGLE: u32 = 0x03;
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;

#[derive(Debug, PartialEq, Eq)]
pub enum TxError {
    Truncated,
    TrailingData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutPoint {
    /// Previous transaction id, in the same (internal/little-endian) byte order used by raw
    /// transaction serialization -- *not* the reversed, human-displayed order.
    pub txid: [u8; 32],
    pub vout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

impl Transaction {
    /// Parses a transaction in the legacy (non-segwit) serialization -- the form
    /// `PSBT_GLOBAL_UNSIGNED_TX` is required to use per BIP-174 (empty scriptSigs, no marker/
    /// flag/witness bytes).
    pub fn parse_legacy(data: &[u8]) -> Result<Self, TxError> {
        let mut pos = 0usize;
        let version = i32::from_le_bytes(data.get(0..4).ok_or(TxError::Truncated)?.try_into().unwrap());
        pos += 4;

        let (n_in, c) = read_varint(&data[pos..]).ok_or(TxError::Truncated)?;
        pos += c;
        let mut inputs = Vec::with_capacity(n_in as usize);
        for _ in 0..n_in {
            let txid: [u8; 32] = data.get(pos..pos + 32).ok_or(TxError::Truncated)?.try_into().unwrap();
            pos += 32;
            let vout = u32::from_le_bytes(data.get(pos..pos + 4).ok_or(TxError::Truncated)?.try_into().unwrap());
            pos += 4;
            let (script_sig, c) = read_varbytes(&data[pos..]).ok_or(TxError::Truncated)?;
            let script_sig = script_sig.to_vec();
            pos += c;
            let sequence = u32::from_le_bytes(data.get(pos..pos + 4).ok_or(TxError::Truncated)?.try_into().unwrap());
            pos += 4;
            inputs.push(TxIn { prevout: OutPoint { txid, vout }, script_sig, sequence });
        }

        let (n_out, c) = read_varint(&data[pos..]).ok_or(TxError::Truncated)?;
        pos += c;
        let mut outputs = Vec::with_capacity(n_out as usize);
        for _ in 0..n_out {
            let value = u64::from_le_bytes(data.get(pos..pos + 8).ok_or(TxError::Truncated)?.try_into().unwrap());
            pos += 8;
            let (script_pubkey, c) = read_varbytes(&data[pos..]).ok_or(TxError::Truncated)?;
            let script_pubkey = script_pubkey.to_vec();
            pos += c;
            outputs.push(TxOut { value, script_pubkey });
        }

        let locktime = u32::from_le_bytes(data.get(pos..pos + 4).ok_or(TxError::Truncated)?.try_into().unwrap());
        pos += 4;

        if pos != data.len() {
            return Err(TxError::TrailingData);
        }
        Ok(Transaction { version, inputs, outputs, locktime })
    }

    /// Serializes in the legacy (non-witness) format; this is both what's stored in
    /// `PSBT_GLOBAL_UNSIGNED_TX` and what `txid()` hashes.
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut out, self.inputs.len() as u64);
        for input in &self.inputs {
            out.extend_from_slice(&input.prevout.txid);
            out.extend_from_slice(&input.prevout.vout.to_le_bytes());
            write_varbytes(&mut out, &input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len() as u64);
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            write_varbytes(&mut out, &output.script_pubkey);
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    /// The transaction id: `SHA256d` of the legacy serialization, in internal (little-endian)
    /// byte order.
    pub fn txid(&self) -> [u8; 32] { sha256d(&self.serialize_legacy()) }

    /// Serializes the transaction in the BIP-144 witness format, given one witness stack
    /// (a list of byte-string stack items) per input, in input order. Producing the final,
    /// broadcastable, signed transaction.
    pub fn serialize_with_witness(&self, witnesses: &[Vec<Vec<u8>>]) -> Vec<u8> {
        assert_eq!(witnesses.len(), self.inputs.len(), "one witness stack per input is required");
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(0x00); // segwit marker
        out.push(0x01); // segwit flag
        write_varint(&mut out, self.inputs.len() as u64);
        for input in &self.inputs {
            out.extend_from_slice(&input.prevout.txid);
            out.extend_from_slice(&input.prevout.vout.to_le_bytes());
            write_varbytes(&mut out, &input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len() as u64);
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            write_varbytes(&mut out, &output.script_pubkey);
        }
        for stack in witnesses {
            write_varint(&mut out, stack.len() as u64);
            for item in stack {
                write_varbytes(&mut out, item);
            }
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }
}

/// Builds the BIP-143 `scriptCode` for a P2WPKH input, given the 20-byte pubkey hash from its
/// witness program: `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG` (the same script a
/// legacy P2PKH output would use).
pub fn p2wpkh_script_code(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Computes the [BIP-143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
/// sighash for a version-0 witness program input.
///
/// `script_code` is the raw (not length-prefixed) scriptCode, e.g. from
/// [`p2wpkh_script_code`]; `amount` is the value (in satoshis) of the output being spent.
pub fn bip143_sighash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    amount: u64,
    sighash_type: u32,
) -> [u8; 32] {
    let anyonecanpay = sighash_type & SIGHASH_ANYONECANPAY != 0;
    let base_type = sighash_type & 0x1f;

    let hash_prevouts = if !anyonecanpay {
        let mut buf = Vec::with_capacity(tx.inputs.len() * 36);
        for input in &tx.inputs {
            buf.extend_from_slice(&input.prevout.txid);
            buf.extend_from_slice(&input.prevout.vout.to_le_bytes());
        }
        sha256d(&buf)
    } else {
        [0u8; 32]
    };

    let hash_sequence = if !anyonecanpay && base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        let mut buf = Vec::with_capacity(tx.inputs.len() * 4);
        for input in &tx.inputs {
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }
        sha256d(&buf)
    } else {
        [0u8; 32]
    };

    let hash_outputs = if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        let mut buf = Vec::new();
        for output in &tx.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            write_varbytes(&mut buf, &output.script_pubkey);
        }
        sha256d(&buf)
    } else if base_type == SIGHASH_SINGLE && input_index < tx.outputs.len() {
        let mut buf = Vec::new();
        let output = &tx.outputs[input_index];
        buf.extend_from_slice(&output.value.to_le_bytes());
        write_varbytes(&mut buf, &output.script_pubkey);
        sha256d(&buf)
    } else {
        [0u8; 32]
    };

    let input = &tx.inputs[input_index];
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&input.prevout.txid);
    preimage.extend_from_slice(&input.prevout.vout.to_le_bytes());
    write_varbytes(&mut preimage, script_code);
    preimage.extend_from_slice(&amount.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());
    preimage.extend_from_slice(&sighash_type.to_le_bytes());

    sha256d(&preimage)
}

/// Signs a precomputed BIP-143 sighash directly (no additional hashing) with ECDSA,
/// normalizing to low-S and strict DER encoding per [BIP-62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki)/
/// [BIP-66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki) policy/consensus
/// rules, then appending the 1-byte sighash type -- producing the exact byte string used as
/// a P2WPKH witness signature stack item.
pub fn sign_sighash(private_key: &SigningKey, sighash: &[u8; 32], sighash_type: u32) -> Vec<u8> {
    let sig: k256::ecdsa::Signature =
        private_key.sign_prehash(sighash).expect("prehash signing of a 32-byte digest cannot fail");
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut out = sig.to_der().as_bytes().to_vec();
    out.push(sighash_type as u8);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }

    // BIP-143 "Native P2WPKH" official test vector, from
    // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    const UNSIGNED_TX: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
    const SIGNED_TX: &str = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";

    #[test]
    fn parse_and_reserialize_legacy_roundtrips() {
        let raw = hex_decode(UNSIGNED_TX);
        let tx = Transaction::parse_legacy(&raw).unwrap();
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.serialize_legacy(), raw);
    }

    #[test]
    fn bip143_native_p2wpkh_vector() {
        let raw = hex_decode(UNSIGNED_TX);
        let tx = Transaction::parse_legacy(&raw).unwrap();

        // second input (index 1) spends a native P2WPKH output with this pubkey hash/value
        let pubkey_hash: [u8; 20] = hex_decode("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1").try_into().unwrap();
        let script_code = p2wpkh_script_code(&pubkey_hash);
        assert_eq!(hex(&script_code), "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");

        let amount = 600_000_000u64; // 6 BTC
        let sighash = bip143_sighash(&tx, 1, &script_code, amount, SIGHASH_ALL);
        assert_eq!(hex(&sighash), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
    }

    #[test]
    fn serialize_with_witness_matches_vector() {
        let raw = hex_decode(UNSIGNED_TX);
        let mut tx = Transaction::parse_legacy(&raw).unwrap();
        // first input's scriptSig gets filled in (it's a legacy P2PK input in this vector)
        tx.inputs[0].script_sig = hex_decode("4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01");
        let sig = hex_decode("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01");
        let pubkey = hex_decode("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357");
        let witnesses = vec![vec![], vec![sig, pubkey]];
        assert_eq!(hex(&tx.serialize_with_witness(&witnesses)), SIGNED_TX);
    }

    #[test]
    fn sign_sighash_matches_bip143_vector() {
        let raw = hex_decode(UNSIGNED_TX);
        let tx = Transaction::parse_legacy(&raw).unwrap();
        let pubkey_hash: [u8; 20] = hex_decode("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1").try_into().unwrap();
        let script_code = p2wpkh_script_code(&pubkey_hash);
        let sighash = bip143_sighash(&tx, 1, &script_code, 600_000_000, SIGHASH_ALL);

        let privkey_bytes = hex_decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
        let signing_key = SigningKey::from_slice(&privkey_bytes).unwrap();
        let sig_with_type = sign_sighash(&signing_key, &sighash, SIGHASH_ALL);
        assert_eq!(
            hex(&sig_with_type),
            "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
        );
    }
}
