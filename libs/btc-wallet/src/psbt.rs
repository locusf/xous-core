//! Minimal [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) (PSBTv0)
//! parser/serializer and a P2WPKH-only signer/finalizer/extractor.
//!
//! Only the fields needed to sign and finalize single-signature native SegWit v0 (P2WPKH)
//! inputs are interpreted; everything else (redeem/witness scripts, non-witness UTXOs,
//! global xpubs, proprietary fields, ...) is preserved verbatim as opaque key/value pairs so
//! round-tripping an unrelated/partially-signed PSBT doesn't lose data.

use crate::bip32::{ExtendedPrivKey, HARDENED_BIT};
use crate::hash::hash160;
use crate::tx::{self, Transaction, TxOut};
use crate::varint::{read_varbytes, read_varint, write_varbytes, write_varint};

const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

// Global key types
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
// Input key types
const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;

#[derive(Debug, PartialEq, Eq)]
pub enum PsbtError {
    BadMagic,
    Truncated,
    TrailingData,
    /// The unsigned tx's input/output count didn't match the number of per-input/output maps.
    MapCountMismatch,
    /// No input in the PSBT could be signed with this wallet's key (either none carried a
    /// `PSBT_IN_BIP32_DERIVATION` matching our master fingerprint, or the derived key didn't
    /// match the input's claimed scriptPubKey).
    NothingToSign,
    /// An input's BIP-32 derivation path claims a pubkey that doesn't match what that path
    /// actually derives to, or doesn't match the scriptPubKey being spent -- signing was
    /// refused to avoid signing for an address the user didn't actually intend.
    DerivationMismatch,
    /// An input we're asked to sign is missing `PSBT_IN_WITNESS_UTXO`, or that UTXO's
    /// scriptPubKey isn't a v0 P2WPKH program (`OP_0 <20-byte-hash>`) -- the only script type
    /// this wallet supports.
    UnsupportedInput,
    /// Not every input has a final witness -- extraction requires a fully-signed PSBT.
    IncompleteForExtraction,
}

/// A raw, not-further-interpreted PSBT key/value pair (used to preserve fields this signer
/// doesn't understand or doesn't need, so they round-trip unmodified).
pub type KeyValue = (Vec<u8>, Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip32Derivation {
    /// SEC1 (usually compressed, 33-byte) public key this derivation info applies to.
    pub pubkey: Vec<u8>,
    pub master_fingerprint: [u8; 4],
    pub path: Vec<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct PsbtInput {
    pub non_witness_utxo: Option<Transaction>,
    pub witness_utxo: Option<TxOut>,
    pub partial_sigs: Vec<KeyValue>,
    pub sighash_type: Option<u32>,
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub final_script_sig: Option<Vec<u8>>,
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    pub unknown: Vec<KeyValue>,
}

#[derive(Clone, Debug, Default)]
pub struct PsbtOutput {
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub unknown: Vec<KeyValue>,
}

#[derive(Clone, Debug)]
pub struct Psbt {
    pub unsigned_tx: Transaction,
    pub global_unknown: Vec<KeyValue>,
    pub inputs: Vec<PsbtInput>,
    pub outputs: Vec<PsbtOutput>,
}

/// Reads one key/value map (as found in each PSBT global/input/output section), terminated by
/// a zero-length key, returning `(pairs, bytes_consumed)`.
fn read_map(data: &[u8]) -> Result<(Vec<KeyValue>, usize), PsbtError> {
    let mut pos = 0;
    let mut pairs = Vec::new();
    loop {
        let (keylen, c) = read_varint(&data[pos..]).ok_or(PsbtError::Truncated)?;
        pos += c;
        if keylen == 0 {
            break;
        }
        let key = data.get(pos..pos + keylen as usize).ok_or(PsbtError::Truncated)?.to_vec();
        pos += keylen as usize;
        let (value, c) = read_varbytes(&data[pos..]).ok_or(PsbtError::Truncated)?;
        let value = value.to_vec();
        pos += c;
        pairs.push((key, value));
    }
    Ok((pairs, pos))
}

fn write_map(out: &mut Vec<u8>, pairs: &[KeyValue]) {
    for (key, value) in pairs {
        write_varbytes(out, key);
        write_varbytes(out, value);
    }
    out.push(0x00); // map terminator (zero-length key)
}

fn parse_bip32_derivation(key_data: &[u8], value: &[u8]) -> Option<Bip32Derivation> {
    if value.len() < 4 || !value.len().is_multiple_of(4) {
        return None;
    }
    let master_fingerprint = value[0..4].try_into().ok()?;
    let path = value[4..].chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    Some(Bip32Derivation { pubkey: key_data.to_vec(), master_fingerprint, path })
}

impl Psbt {
    pub fn parse(data: &[u8]) -> Result<Self, PsbtError> {
        if data.len() < 5 || data[0..5] != PSBT_MAGIC {
            return Err(PsbtError::BadMagic);
        }
        let mut pos = 5;

        let (global_pairs, c) = read_map(&data[pos..])?;
        pos += c;
        let mut unsigned_tx = None;
        let mut global_unknown = Vec::new();
        for (key, value) in global_pairs {
            match key.first() {
                Some(&PSBT_GLOBAL_UNSIGNED_TX) if key.len() == 1 => {
                    unsigned_tx = Some(Transaction::parse_legacy(&value).map_err(|_| PsbtError::Truncated)?);
                }
                _ => global_unknown.push((key, value)),
            }
        }
        let unsigned_tx = unsigned_tx.ok_or(PsbtError::Truncated)?;

        let mut inputs = Vec::with_capacity(unsigned_tx.inputs.len());
        for _ in 0..unsigned_tx.inputs.len() {
            let (pairs, c) = read_map(&data[pos..])?;
            pos += c;
            let mut input = PsbtInput::default();
            for (key, value) in pairs {
                let (ty, key_data) = (key.first().copied(), &key[key.len().min(1)..]);
                match ty {
                    Some(PSBT_IN_NON_WITNESS_UTXO) => {
                        input.non_witness_utxo =
                            Some(Transaction::parse_legacy(&value).map_err(|_| PsbtError::Truncated)?);
                    }
                    Some(PSBT_IN_WITNESS_UTXO) => {
                        let value_bytes = value.len();
                        let mut p = 0usize;
                        let val = u64::from_le_bytes(
                            value.get(0..8).ok_or(PsbtError::Truncated)?.try_into().unwrap(),
                        );
                        p += 8;
                        let (script_pubkey, c) = read_varbytes(&value[p..]).ok_or(PsbtError::Truncated)?;
                        p += c;
                        if p != value_bytes {
                            return Err(PsbtError::TrailingData);
                        }
                        input.witness_utxo = Some(TxOut { value: val, script_pubkey: script_pubkey.to_vec() });
                    }
                    Some(PSBT_IN_PARTIAL_SIG) => input.partial_sigs.push((key_data.to_vec(), value)),
                    Some(PSBT_IN_SIGHASH_TYPE) => {
                        input.sighash_type = Some(u32::from_le_bytes(
                            value.get(0..4).ok_or(PsbtError::Truncated)?.try_into().unwrap(),
                        ));
                    }
                    Some(PSBT_IN_BIP32_DERIVATION) => {
                        if let Some(d) = parse_bip32_derivation(key_data, &value) {
                            input.bip32_derivation.push(d);
                        }
                    }
                    Some(PSBT_IN_FINAL_SCRIPTSIG) => input.final_script_sig = Some(value),
                    Some(PSBT_IN_FINAL_SCRIPTWITNESS) => {
                        let (n, mut p) = read_varint(&value).ok_or(PsbtError::Truncated)?;
                        let mut items = Vec::with_capacity(n as usize);
                        for _ in 0..n {
                            let (item, c) = read_varbytes(&value[p..]).ok_or(PsbtError::Truncated)?;
                            items.push(item.to_vec());
                            p += c;
                        }
                        input.final_script_witness = Some(items);
                    }
                    _ => input.unknown.push((key, value)),
                }
            }
            inputs.push(input);
        }

        let mut outputs = Vec::with_capacity(unsigned_tx.outputs.len());
        for _ in 0..unsigned_tx.outputs.len() {
            let (pairs, c) = read_map(&data[pos..])?;
            pos += c;
            let mut output = PsbtOutput::default();
            for (key, value) in pairs {
                let (ty, key_data) = (key.first().copied(), &key[key.len().min(1)..]);
                match ty {
                    Some(0x02) => {
                        if let Some(d) = parse_bip32_derivation(key_data, &value) {
                            output.bip32_derivation.push(d);
                        }
                    }
                    _ => output.unknown.push((key, value)),
                }
            }
            outputs.push(output);
        }

        if pos != data.len() {
            return Err(PsbtError::TrailingData);
        }
        if inputs.len() != unsigned_tx.inputs.len() || outputs.len() != unsigned_tx.outputs.len() {
            return Err(PsbtError::MapCountMismatch);
        }

        Ok(Psbt { unsigned_tx, global_unknown, inputs, outputs })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PSBT_MAGIC);

        let mut global_pairs = vec![(vec![PSBT_GLOBAL_UNSIGNED_TX], self.unsigned_tx.serialize_legacy())];
        global_pairs.extend(self.global_unknown.iter().cloned());
        write_map(&mut out, &global_pairs);

        for input in &self.inputs {
            let mut pairs = Vec::new();
            if let Some(tx) = &input.non_witness_utxo {
                pairs.push((vec![PSBT_IN_NON_WITNESS_UTXO], tx.serialize_legacy()));
            }
            if let Some(utxo) = &input.witness_utxo {
                let mut value = Vec::new();
                value.extend_from_slice(&utxo.value.to_le_bytes());
                write_varbytes(&mut value, &utxo.script_pubkey);
                pairs.push((vec![PSBT_IN_WITNESS_UTXO], value));
            }
            for (pubkey, sig) in &input.partial_sigs {
                let mut key = vec![PSBT_IN_PARTIAL_SIG];
                key.extend_from_slice(pubkey);
                pairs.push((key, sig.clone()));
            }
            if let Some(sighash_type) = input.sighash_type {
                pairs.push((vec![PSBT_IN_SIGHASH_TYPE], sighash_type.to_le_bytes().to_vec()));
            }
            for d in &input.bip32_derivation {
                let mut key = vec![PSBT_IN_BIP32_DERIVATION];
                key.extend_from_slice(&d.pubkey);
                let mut value = Vec::new();
                value.extend_from_slice(&d.master_fingerprint);
                for step in &d.path {
                    value.extend_from_slice(&step.to_le_bytes());
                }
                pairs.push((key, value));
            }
            if let Some(script_sig) = &input.final_script_sig {
                pairs.push((vec![PSBT_IN_FINAL_SCRIPTSIG], script_sig.clone()));
            }
            if let Some(witness) = &input.final_script_witness {
                let mut value = Vec::new();
                write_varint(&mut value, witness.len() as u64);
                for item in witness {
                    write_varbytes(&mut value, item);
                }
                pairs.push((vec![PSBT_IN_FINAL_SCRIPTWITNESS], value));
            }
            pairs.extend(input.unknown.iter().cloned());
            write_map(&mut out, &pairs);
        }

        for output in &self.outputs {
            let mut pairs = Vec::new();
            for d in &output.bip32_derivation {
                let mut key = vec![0x02u8];
                key.extend_from_slice(&d.pubkey);
                let mut value = Vec::new();
                value.extend_from_slice(&d.master_fingerprint);
                for step in &d.path {
                    value.extend_from_slice(&step.to_le_bytes());
                }
                pairs.push((key, value));
            }
            pairs.extend(output.unknown.iter().cloned());
            write_map(&mut out, &pairs);
        }

        out
    }

    /// Signs and immediately finalizes every input this `master` key (identified by
    /// `master_fingerprint`, the first 4 bytes of `HASH160` of its public key -- see
    /// [`ExtendedPrivKey::fingerprint`]) can sign, restricted to native P2WPKH inputs.
    ///
    /// For each candidate input, the derived key is checked against the input's actual
    /// `witness_utxo` scriptPubKey *before* signing (see [`PsbtError::DerivationMismatch`]):
    /// this stops a malicious host from asking the device to sign with an unexpected
    /// derivation path for an input whose address doesn't actually match.
    ///
    /// Returns the number of inputs signed, or [`PsbtError::NothingToSign`] if none matched.
    pub fn sign_p2wpkh(
        &mut self,
        master: &ExtendedPrivKey,
        master_fingerprint: [u8; 4],
    ) -> Result<usize, PsbtError> {
        let mut signed = 0usize;
        for i in 0..self.inputs.len() {
            let Some(derivation) = self.inputs[i]
                .bip32_derivation
                .iter()
                .find(|d| d.master_fingerprint == master_fingerprint)
                .cloned()
            else {
                continue;
            };
            // Reject unreasonably deep/foreign paths defensively; BIP-84 paths are 5 levels.
            if derivation.path.iter().any(|&c| c & HARDENED_BIT != 0 && derivation.path.len() > 16) {
                return Err(PsbtError::DerivationMismatch);
            }
            let child = master.derive_path(&derivation.path).map_err(|_| PsbtError::DerivationMismatch)?;
            let pubkey = child.public_key_compressed();
            if pubkey.as_slice() != derivation.pubkey.as_slice() {
                return Err(PsbtError::DerivationMismatch);
            }

            let Some(utxo) = self.inputs[i].witness_utxo.clone() else {
                return Err(PsbtError::UnsupportedInput);
            };
            let pubkey_hash = hash160(&pubkey);
            let expected_script_pubkey = p2wpkh_script_pubkey(&pubkey_hash);
            if utxo.script_pubkey != expected_script_pubkey {
                // The path derives a key that doesn't match what's actually being spent --
                // refuse rather than sign for the wrong address.
                return Err(PsbtError::DerivationMismatch);
            }

            let sighash_type = self.inputs[i].sighash_type.unwrap_or(tx::SIGHASH_ALL);
            let script_code = tx::p2wpkh_script_code(&pubkey_hash);
            let sighash = tx::bip143_sighash(&self.unsigned_tx, i, &script_code, utxo.value, sighash_type);
            let sig = tx::sign_sighash(&child.private_key, &sighash, sighash_type);

            self.inputs[i].final_script_sig = Some(Vec::new());
            self.inputs[i].final_script_witness = Some(vec![sig, pubkey.to_vec()]);
            // Clean up now-redundant fields once finalized, per BIP-174's finalizer guidance.
            self.inputs[i].partial_sigs.clear();
            self.inputs[i].bip32_derivation.clear();
            self.inputs[i].sighash_type = None;
            signed += 1;
        }
        if signed == 0 {
            return Err(PsbtError::NothingToSign);
        }
        Ok(signed)
    }

    /// Assembles the final, broadcastable transaction from a fully-finalized PSBT (i.e. every
    /// input has `PSBT_IN_FINAL_SCRIPTWITNESS`, as produced by [`Self::sign_p2wpkh`]).
    pub fn extract_transaction(&self) -> Result<Vec<u8>, PsbtError> {
        let mut tx = self.unsigned_tx.clone();
        let mut witnesses = Vec::with_capacity(self.inputs.len());
        for (input, psbt_in) in tx.inputs.iter_mut().zip(&self.inputs) {
            input.script_sig = psbt_in.final_script_sig.clone().ok_or(PsbtError::IncompleteForExtraction)?;
            witnesses.push(psbt_in.final_script_witness.clone().ok_or(PsbtError::IncompleteForExtraction)?);
        }
        Ok(tx.serialize_with_witness(&witnesses))
    }
}

/// Builds a native SegWit v0 P2WPKH `scriptPubKey` (`OP_0 <20-byte-hash>`) from a pubkey hash.
pub fn p2wpkh_script_pubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.push(0x00); // OP_0 (witness version 0)
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip32::ExtendedPrivKey;

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{:02x}", b)).collect() }

    /// Hand-builds a single-input, single-output PSBT spending a P2WPKH output derived from
    /// `m/84'/1'/0'/0/0` of the BIP-32 test vector 1 seed, and checks that `sign_p2wpkh` +
    /// `extract_transaction` produce a validly-signed transaction (independently re-verified
    /// with the same `bip143_sighash`/ECDSA-verify machinery this crate already trusts).
    #[test]
    fn build_sign_and_extract_p2wpkh_psbt() {
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedPrivKey::master(&seed).unwrap();
        let master_fp = master.fingerprint();
        let path = crate::bip32::parse_path("m/84'/1'/0'/0/0").unwrap();
        let child = master.derive_path(&path).unwrap();
        let pubkey = child.public_key_compressed();
        let pubkey_hash = hash160(&pubkey);

        // a fictitious previous output of 1 BTC paying our derived P2WPKH address
        let prev_txid = [0x11u8; 32];
        let unsigned_tx = Transaction {
            version: 2,
            inputs: vec![tx::TxIn {
                prevout: tx::OutPoint { txid: prev_txid, vout: 0 },
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOut {
                value: 99_900_000, // 1 BTC minus a small fee
                script_pubkey: p2wpkh_script_pubkey(&hash160(b"someone else's pubkey!!")),
            }],
            locktime: 0,
        };

        let mut psbt = Psbt {
            unsigned_tx: unsigned_tx.clone(),
            global_unknown: Vec::new(),
            inputs: vec![PsbtInput {
                witness_utxo: Some(TxOut {
                    value: 100_000_000,
                    script_pubkey: p2wpkh_script_pubkey(&pubkey_hash),
                }),
                bip32_derivation: vec![Bip32Derivation {
                    pubkey: pubkey.to_vec(),
                    master_fingerprint: master_fp,
                    path: path.clone(),
                }],
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };

        // round-trip through (de)serialization before signing, exercising the parser too
        let reparsed = Psbt::parse(&psbt.serialize()).unwrap();
        psbt = reparsed;

        let signed_count = psbt.sign_p2wpkh(&master, master_fp).unwrap();
        assert_eq!(signed_count, 1);

        let final_tx_bytes = psbt.extract_transaction().unwrap();

        let witness = psbt.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 2);
        let sig_with_type = &witness[0];
        let witness_pubkey = &witness[1];
        assert_eq!(witness_pubkey.as_slice(), pubkey.as_slice());

        let script_code = tx::p2wpkh_script_code(&pubkey_hash);
        let sighash = tx::bip143_sighash(&unsigned_tx, 0, &script_code, 100_000_000, tx::SIGHASH_ALL);
        let der_sig = &sig_with_type[..sig_with_type.len() - 1];
        assert_eq!(*sig_with_type.last().unwrap(), tx::SIGHASH_ALL as u8);

        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let sig = k256::ecdsa::Signature::from_der(der_sig).unwrap();
        child.private_key.verifying_key().verify_prehash(&sighash, &sig).expect("signature must verify against the sighash");

        // sanity: the final tx bytes parse back with the expected marker/flag and script_sig
        assert_eq!(&final_tx_bytes[4..6], &[0x00, 0x01]);
        assert_eq!(hex(&final_tx_bytes[..4]), "02000000");
    }

    #[test]
    fn refuses_to_sign_when_derivation_does_not_match_scriptpubkey() {
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f");
        let master = ExtendedPrivKey::master(&seed).unwrap();
        let master_fp = master.fingerprint();
        let path = crate::bip32::parse_path("m/84'/1'/0'/0/0").unwrap();
        let child = master.derive_path(&path).unwrap();
        let pubkey = child.public_key_compressed();

        let unsigned_tx = Transaction {
            version: 2,
            inputs: vec![tx::TxIn {
                prevout: tx::OutPoint { txid: [0x22; 32], vout: 0 },
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOut { value: 1000, script_pubkey: vec![0x6a] }],
            locktime: 0,
        };
        let mut psbt = Psbt {
            unsigned_tx,
            global_unknown: Vec::new(),
            inputs: vec![PsbtInput {
                // scriptPubKey deliberately doesn't match what m/84'/1'/0'/0/0 actually derives to
                witness_utxo: Some(TxOut {
                    value: 100_000,
                    script_pubkey: p2wpkh_script_pubkey(&hash160(b"not our key")),
                }),
                bip32_derivation: vec![Bip32Derivation { pubkey: pubkey.to_vec(), master_fingerprint: master_fp, path }],
                ..Default::default()
            }],
            outputs: vec![PsbtOutput::default()],
        };

        assert_eq!(psbt.sign_p2wpkh(&master, master_fp), Err(PsbtError::DerivationMismatch));
    }
}
