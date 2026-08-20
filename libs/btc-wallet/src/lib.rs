//! Pure-logic core of a BIP-32/39/174 Bitcoin hardware wallet for the dabao-console
//! USB-serial shell: mnemonics, HD key derivation, Bech32/P2WPKH addresses, and Bitcoin
//! transaction/PSBT (de)serialization + signing.
//!
//! This crate has no `xous`/hardware dependency, so its logic can be exercised with
//! `cargo test -p btc-wallet` on the host, independent of the actual on-device build. It is
//! surfaced on-device purely through dabao-console's existing serial-console shell commands
//! (`apps-dabao/dabao-console/src/cmds/btc_cmd.rs`) -- there's no separate encrypted USB HID
//! transport, since the console already runs over a serial link.

pub mod base58;
pub mod bech32;
pub mod bip32;
pub mod bip39;
pub mod hash;
pub mod pin;
pub mod psbt;
pub mod tx;
mod varint;
mod wordlist;

use bip32::ExtendedPrivKey;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

#[derive(Debug, PartialEq, Eq)]
pub enum WalletError {
    Bip39(bip39::Bip39Error),
    Bip32(bip32::Bip32Error),
    Bech32(bech32::Bech32Error),
    Psbt(psbt::PsbtError),
    Pin(pin::PinError),
    /// The P2WPKH witness program at this path isn't exactly 20 bytes -- can't happen for
    /// this wallet's own derivation but guards a malformed/foreign scriptPubKey passed in.
    InvalidWitnessProgram,
}
impl From<bip39::Bip39Error> for WalletError {
    fn from(e: bip39::Bip39Error) -> Self { WalletError::Bip39(e) }
}
impl From<bip32::Bip32Error> for WalletError {
    fn from(e: bip32::Bip32Error) -> Self { WalletError::Bip32(e) }
}
impl From<bech32::Bech32Error> for WalletError {
    fn from(e: bech32::Bech32Error) -> Self { WalletError::Bech32(e) }
}
impl From<psbt::PsbtError> for WalletError {
    fn from(e: psbt::PsbtError) -> Self { WalletError::Psbt(e) }
}
impl From<pin::PinError> for WalletError {
    fn from(e: pin::PinError) -> Self { WalletError::Pin(e) }
}

/// High-level, single-seed P2WPKH ("native SegWit") hardware wallet: wraps BIP-32/39 key
/// derivation, Bech32 address encoding, and PSBT signing behind a small path-string-based API
/// suitable for driving from a text console.
pub struct Wallet {
    master: ExtendedPrivKey,
    master_fingerprint: [u8; 4],
    testnet: bool,
    /// Bech32 human-readable part: `"bc"` for mainnet, `"tb"` for testnet.
    hrp: &'static str,
}

impl Wallet {
    /// Builds a wallet directly from a BIP-32 seed (e.g. the output of
    /// [`bip39::mnemonic_to_seed`]).
    pub fn from_seed(seed: &[u8], testnet: bool) -> Result<Self, WalletError> {
        let master = ExtendedPrivKey::master(seed)?;
        let master_fingerprint = master.fingerprint();
        Ok(Wallet { master, master_fingerprint, testnet, hrp: if testnet { "tb" } else { "bc" } })
    }

    /// Builds a wallet from a mnemonic sentence (validated) and optional BIP-39 passphrase.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str, testnet: bool) -> Result<Self, WalletError> {
        bip39::validate_mnemonic(mnemonic)?;
        let seed = bip39::mnemonic_to_seed(mnemonic, passphrase);
        let wallet = Self::from_seed(&seed, testnet);
        // `seed` was only ever needed transiently to build the master key; wipe our copy of it.
        let mut seed = seed;
        seed.zeroize();
        wallet
    }

    /// Generates a brand new mnemonic sentence (does *not* build a wallet from it -- the
    /// caller should show it to the user for backup before calling [`Self::from_mnemonic`]).
    pub fn generate_mnemonic<R: RngCore + CryptoRng>(
        rng: &mut R,
        entropy_bits: usize,
    ) -> Result<String, WalletError> {
        Ok(bip39::generate_mnemonic(rng, entropy_bits)?)
    }

    /// Provisions a wallet from a mnemonic sentence, locking its seed at rest under `pin` --
    /// this is the "one-time" PIN set: it's fixed from here on, and must be supplied again to
    /// [`Self::unlock`] every subsequent session (there is no "change PIN" operation).
    ///
    /// Returns the ready-to-use in-memory `Wallet` alongside the encrypted seed blob (see
    /// [`pin::LockedSeed::to_bytes`]) that the caller is responsible for persisting (e.g. in
    /// `keystore` app-key slots) -- this crate has no storage of its own.
    ///
    /// Rejects `pin_code` outright (before ever touching `mnemonic`/`rng`) if it fails
    /// [`pin::check_pin_strength`] -- see that function's docs for why this matters given
    /// this scheme's deliberate lack of a wrong-PIN lockout.
    pub fn provision<R: RngCore + CryptoRng>(
        mnemonic: &str,
        passphrase: &str,
        pin_code: &str,
        testnet: bool,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>), WalletError> {
        bip39::validate_mnemonic(mnemonic)?;
        pin::check_pin_strength(pin_code)?;
        let mut seed = bip39::mnemonic_to_seed(mnemonic, passphrase);
        let wallet = Self::from_seed(&seed, testnet);
        let locked = pin::LockedSeed::lock(&seed, pin_code, rng).to_bytes();
        seed.zeroize();
        Ok((wallet?, locked))
    }

    /// Decrypts `locked_blob` (as produced by [`Self::provision`]) with `pin_code` and builds
    /// a `Wallet` from the recovered seed. Returns [`WalletError::Pin`] if the PIN is wrong.
    pub fn unlock(locked_blob: &[u8], pin_code: &str, testnet: bool) -> Result<Self, WalletError> {
        let locked = pin::LockedSeed::from_bytes(locked_blob)?;
        let mut seed = locked.unlock(pin_code)?;
        let wallet = Self::from_seed(&seed, testnet);
        seed.zeroize();
        wallet
    }

    /// The wallet's BIP-32 master key fingerprint (first 4 bytes of `HASH160` of the master
    /// public key), used to identify which `PSBT_IN_BIP32_DERIVATION` entries are ours.
    pub fn master_fingerprint(&self) -> [u8; 4] { self.master_fingerprint }

    fn derive(&self, path: &str) -> Result<ExtendedPrivKey, WalletError> {
        let components = bip32::parse_path(path)?;
        Ok(self.master.derive_path(&components)?)
    }

    /// The compressed SEC1 public key at `path` (e.g. `"m/84'/0'/0'/0/0"`).
    pub fn pubkey(&self, path: &str) -> Result<[u8; 33], WalletError> {
        Ok(self.derive(path)?.public_key_compressed())
    }

    /// The standard BIP-32 extended public key (`xpub.../tpub...`) at `path` -- e.g. the
    /// account-level key (`"m/84'/0'/0'"`) that watch-only desktop wallet software (Sparrow,
    /// Electrum, ...) would import to derive and watch every receive/change address itself,
    /// without ever seeing this wallet's private keys.
    pub fn xpub(&self, path: &str) -> Result<String, WalletError> {
        Ok(self.derive(path)?.serialize_xpub(self.testnet))
    }

    /// The native SegWit v0 (P2WPKH) Bech32 address at `path`.
    pub fn address_p2wpkh(&self, path: &str) -> Result<String, WalletError> {
        let pubkey = self.pubkey(path)?;
        let pubkey_hash = hash::hash160(&pubkey);
        Ok(bech32::encode_p2wpkh(self.hrp, &pubkey_hash)?)
    }

    /// Signs every P2WPKH input of `psbt_bytes` (a serialized PSBTv0) that this wallet's key
    /// can sign, per [`psbt::Psbt::sign_p2wpkh`]'s "verify the derivation before signing"
    /// policy, and returns the updated (finalized, for the inputs it signed) PSBT bytes.
    pub fn sign_psbt(&self, psbt_bytes: &[u8]) -> Result<Vec<u8>, WalletError> {
        let mut psbt = psbt::Psbt::parse(psbt_bytes).map_err(WalletError::Psbt)?;
        psbt.sign_p2wpkh(&self.master, self.master_fingerprint)?;
        Ok(psbt.serialize())
    }

    /// Signs `psbt_bytes` like [`Self::sign_psbt`], then immediately extracts and returns the
    /// final, broadcastable raw transaction bytes. Only useful when this wallet is the sole
    /// signer needed for every input (true for a simple single-sig P2WPKH wallet).
    pub fn sign_and_extract(&self, psbt_bytes: &[u8]) -> Result<Vec<u8>, WalletError> {
        let mut psbt = psbt::Psbt::parse(psbt_bytes).map_err(WalletError::Psbt)?;
        psbt.sign_p2wpkh(&self.master, self.master_fingerprint)?;
        Ok(psbt.extract_transaction()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_mnemonic_to_address_to_signed_tx() {
        // Official BIP-39 test vector 1's mnemonic/passphrase, feeding a wallet that then
        // derives a receive address and signs a PSBT spending into it -- exercising the
        // whole mnemonic -> seed -> HD derive -> address -> PSBT sign -> extract pipeline.
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, "TREZOR", false).unwrap();

        let path = "m/84'/0'/0'/0/0";
        let address = wallet.address_p2wpkh(path).unwrap();
        assert!(address.starts_with("bc1q"));

        let pubkey = wallet.pubkey(path).unwrap();
        let pubkey_hash = hash::hash160(&pubkey);

        let unsigned_tx = tx::Transaction {
            version: 2,
            inputs: vec![tx::TxIn {
                prevout: tx::OutPoint { txid: [0x33; 32], vout: 0 },
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
            }],
            outputs: vec![tx::TxOut {
                value: 50_000,
                script_pubkey: psbt::p2wpkh_script_pubkey(&hash::hash160(b"payee")),
            }],
            locktime: 0,
        };
        let p = psbt::Psbt {
            unsigned_tx,
            global_unknown: Vec::new(),
            inputs: vec![psbt::PsbtInput {
                witness_utxo: Some(tx::TxOut {
                    value: 100_000,
                    script_pubkey: psbt::p2wpkh_script_pubkey(&pubkey_hash),
                }),
                bip32_derivation: vec![psbt::Bip32Derivation {
                    pubkey: pubkey.to_vec(),
                    master_fingerprint: wallet.master_fingerprint(),
                    path: bip32::parse_path(path).unwrap(),
                }],
                ..Default::default()
            }],
            outputs: vec![psbt::PsbtOutput::default()],
        };

        let final_tx = wallet.sign_and_extract(&p.serialize()).unwrap();
        // marker+flag present => a witness (segwit) transaction was produced
        assert_eq!(&final_tx[4..6], &[0x00, 0x01]);

        // signing again from scratch (parse -> sign -> extract) must be deterministic
        let final_tx_again = wallet.sign_and_extract(&p.serialize()).unwrap();
        assert_eq!(final_tx, final_tx_again);
    }

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
    fn provision_and_unlock_with_pin() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut rng = FakeRng(7);
        let (wallet, locked_blob) =
            Wallet::provision(mnemonic, "TREZOR", "1359702468", false, &mut rng).unwrap();
        assert_eq!(locked_blob.len(), pin::LOCKED_SEED_LEN);

        let path = "m/84'/0'/0'/0/0";
        let expected_address = wallet.address_p2wpkh(path).unwrap();

        // simulate a reboot: the in-memory wallet is gone, only the locked blob (as would be
        // read back from `keystore`) and the PIN remain.
        let reopened = Wallet::unlock(&locked_blob, "1359702468", false).unwrap();
        assert_eq!(reopened.address_p2wpkh(path).unwrap(), expected_address);
        assert_eq!(reopened.master_fingerprint(), wallet.master_fingerprint());

        // wrong PIN must not unlock, and must not silently produce a differently-derived
        // (but still "valid looking") wallet -- it must fail outright.
        match Wallet::unlock(&locked_blob, "0000000000", false) {
            Err(WalletError::Pin(pin::PinError::WrongPinOrCorrupt)) => {}
            other => panic!("expected wrong-PIN rejection, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn provision_rejects_weak_pin() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut rng = FakeRng(11);
        match Wallet::provision(mnemonic, "", "1234", false, &mut rng) {
            Err(WalletError::Pin(pin::PinError::TooWeak)) => {}
            other => panic!("expected weak-PIN rejection, got {:?}", other.map(|_| ())),
        }
    }
}
