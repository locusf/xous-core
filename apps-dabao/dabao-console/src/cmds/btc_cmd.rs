use core::fmt::Write;

use btc_wallet::Wallet;
use keystore::Keystore;

use crate::{CommonEnv, ShellCmdApi};

/// The `keystore` "application key" slot range used to persist the wallet's PIN-encrypted
/// seed blob (`btc_wallet::pin::LockedSeed`) in on-chip RRAM. Dabao has no external SPI
/// flash/PDDB, so this hardware-backed app-key storage (see `services/keystore`) is the only
/// persistent option available on this board.
const SEED_KEY_BASE: usize = 100;
const SEED_KEY_SLOTS: usize = (btc_wallet::pin::LOCKED_SEED_LEN + 31) / 32; // ceil(108/32) = 4

fn to_hex(bytes: &[u8], out: &mut String) {
    for b in bytes {
        write!(out, "{:02x}", b).ok();
    }
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Console command for a PIN-protected BIP-32/39/174 native-SegWit (P2WPKH) Bitcoin hardware
/// wallet.
///
/// Unlike a BitBox02/Trezor-style device, this doesn't run over a dedicated encrypted USB HID
/// channel -- it's driven entirely through dabao-console's existing USB-serial shell, with
/// binary data (PSBTs, transactions, public keys) passed as hex strings, the same convention
/// the `secp256k1` command uses.
///
/// The wallet's seed is locked at rest under a PIN set once at provisioning time (`newseed`/
/// `restore`) -- see `btc_wallet::pin` for the "protection via KDF cost, not attempt-lockout"
/// rationale. The PIN can't be changed; it must be supplied again via `unlock` every session
/// (the decrypted wallet only ever lives in this process's memory, never in `keystore`).
pub struct BtcCmd {
    keystore: Keystore,
    wallet: Option<Wallet>,
    testnet: bool,
}
impl BtcCmd {
    pub fn new() -> Self {
        let xns = xous_names::XousNames::new().unwrap();
        BtcCmd { keystore: Keystore::new(&xns), wallet: None, testnet: false }
    }

    fn require_unlocked(&self) -> Result<&Wallet, &'static str> {
        self.wallet.as_ref().ok_or("wallet is locked -- run 'btc unlock <pin>' first")
    }

    /// Reads the persisted locked-seed blob back from `keystore`, if this device has ever
    /// been provisioned (all-zero across every slot is the "never provisioned" sentinel).
    fn load_locked(&self) -> Option<Vec<u8>> {
        let mut blob = Vec::with_capacity(SEED_KEY_SLOTS * 32);
        for i in 0..SEED_KEY_SLOTS {
            blob.extend_from_slice(&self.keystore.read_app_key(SEED_KEY_BASE + i).ok()?);
        }
        blob.truncate(btc_wallet::pin::LOCKED_SEED_LEN);
        if blob.iter().all(|&b| b == 0) { None } else { Some(blob) }
    }

    fn store_locked(&self, blob: &[u8]) -> Result<(), xous::Error> {
        if blob.len() != btc_wallet::pin::LOCKED_SEED_LEN {
            return Err(xous::Error::InvalidArgument);
        }
        for i in 0..SEED_KEY_SLOTS {
            let mut chunk = [0u8; 32];
            let start = i * 32;
            let end = (start + 32).min(blob.len());
            chunk[..end - start].copy_from_slice(&blob[start..end]);
            self.keystore.write_app_key(SEED_KEY_BASE + i, &chunk)?;
        }
        Ok(())
    }

    fn wipe_locked(&self) -> bool {
        let zero = [0u8; 32];
        (0..SEED_KEY_SLOTS).all(|i| self.keystore.write_app_key(SEED_KEY_BASE + i, &zero).is_ok())
    }
}

/// Prints `s` broken into short lines instead of one long `println!`.
///
/// This works around a known, pre-existing, unresolved limitation in the board's low-level
/// USB CDC-ACM serial driver (see the "I'm still not sure why we seem to miss some IN ACKs"
/// comment on `get_app_buf_ptr` in `libs/bao1x-hal/src/usb/driver.rs`): a single print longer
/// than roughly one USB packet reliably gets truncated on the wire, no matter how the
/// higher-level retry/backoff logic in `usb-bao1x`'s `LogString` handler is tuned, because the
/// hardware's own transfer-completion tracking for this endpoint doesn't reliably signal that
/// it's ready for more data. Short lines have consistently transmitted correctly in testing, so
/// long output is deliberately broken up here rather than risk silent truncation -- which would
/// be especially bad for e.g. a signed transaction's hex.
fn print_chunked(s: &str) {
    const SAFE_CHUNK: usize = 48;
    let tt = ticktimer::Ticktimer::new().unwrap();
    for chunk in s.as_bytes().chunks(SAFE_CHUNK) {
        // Safety: every string this command ever builds is plain ASCII (hex digits, bech32/
        // base58 addresses, and literal help/status text), so any byte offset is also a valid
        // UTF-8 char boundary.
        println!("{}", unsafe { core::str::from_utf8_unchecked(chunk) });
        // A few ms of pacing between chunks. Without it, a burst of output generated right
        // after a fast/bulk serial input (e.g. a pasted PSBT hex line, as opposed to one typed
        // key at a time) can trigger the same underlying Corigine USB controller flakiness that
        // causes truncation (see the `get_app_buf_ptr` "missed IN ACKs" comment in
        // bao1x-hal's usb/driver.rs) in its other failure mode: a chunk gets sent twice instead
        // of dropped. Reproduced and confirmed fixed on real hardware across repeated bursts.
        tt.sleep_ms(5).ok();
    }
}

const HELP: &str = "btc [newseed <pin> [12|15|18|21|24]] [restore <pin> <mnemonic...>] [unlock <pin>] [fingerprint] [address <path>] [pubkey <path>] [xpub <path>] [sign-psbt <hex>] [extract-psbt <hex>] [wipe]";

impl<'a> ShellCmdApi<'a> for BtcCmd {
    cmd_api!(btc);

    fn process(&mut self, args: String, env: &mut CommonEnv) -> Result<Option<String>, xous::Error> {
        let mut ret = String::new();
        let mut tokens = args.split(' ');
        let Some(sub_cmd) = tokens.next() else {
            print_chunked(HELP);
            return Ok(None);
        };

        match sub_cmd {
            "newseed" | "restore" => {
                if self.load_locked().is_some() {
                    print_chunked(
                        "a wallet is already provisioned on this device -- run 'btc wipe' first if you really want to replace it",
                    );
                    return Ok(None);
                }
                let Some(pin) = tokens.next() else {
                    write!(ret, "usage: {}", HELP).ok();
                    print_chunked(&ret);
                    return Ok(None);
                };
                let pin = pin.to_string();

                let mnemonic = if sub_cmd == "newseed" {
                    let words: usize = tokens.next().and_then(|s| s.parse().ok()).unwrap_or(24);
                    let bits = match words {
                        12 => 128,
                        15 => 160,
                        18 => 192,
                        21 => 224,
                        24 => 256,
                        _ => {
                            print_chunked("word count must be one of 12/15/18/21/24");
                            return Ok(None);
                        }
                    };
                    match Wallet::generate_mnemonic(&mut env.trng, bits) {
                        Ok(m) => m,
                        Err(e) => {
                            write!(ret, "failed to generate mnemonic: {:?}", e).ok();
                            print_chunked(&ret);
                            return Ok(None);
                        }
                    }
                } else {
                    tokens.collect::<Vec<&str>>().join(" ")
                };

                match Wallet::provision(&mnemonic, "", &pin, self.testnet, &mut env.trng) {
                    Ok((wallet, locked_blob)) => match self.store_locked(&locked_blob) {
                        Ok(()) => {
                            self.wallet = Some(wallet);
                            if sub_cmd == "newseed" {
                                write!(
                                    ret,
                                    "NEW WALLET, PIN SET -- write this mnemonic down, it will not be shown again:\n{}",
                                    mnemonic
                                )
                                .ok();
                            } else {
                                ret.push_str("wallet restored, PIN set, and persisted");
                            }
                        }
                        Err(e) => {
                            write!(ret, "provisioned in memory but failed to persist: {:?}", e).ok();
                        }
                    },
                    Err(e) => {
                        write!(ret, "failed to provision wallet: {:?}", e).ok();
                    }
                }
            }
            "unlock" => {
                let Some(pin) = tokens.next() else {
                    print_chunked("usage: btc unlock <pin>");
                    return Ok(None);
                };
                match self.load_locked() {
                    None => ret.push_str("no wallet provisioned -- run 'btc newseed <pin>' or 'btc restore <pin> <mnemonic...>' first"),
                    Some(blob) => match Wallet::unlock(&blob, pin, self.testnet) {
                        Ok(wallet) => {
                            self.wallet = Some(wallet);
                            ret.push_str("unlocked");
                        }
                        Err(btc_wallet::WalletError::Pin(_)) => ret.push_str("wrong PIN"),
                        Err(e) => {
                            write!(ret, "failed to unlock: {:?}", e).ok();
                        }
                    },
                }
            }
            "fingerprint" => match self.require_unlocked() {
                Ok(wallet) => to_hex(&wallet.master_fingerprint(), &mut ret),
                Err(e) => ret.push_str(e),
            },
            "address" => {
                let path = tokens.next().unwrap_or("").to_string();
                match self.require_unlocked() {
                    Ok(wallet) => match wallet.address_p2wpkh(&path) {
                        Ok(addr) => ret.push_str(&addr),
                        Err(e) => {
                            write!(ret, "derivation error: {:?}", e).ok();
                        }
                    },
                    Err(e) => ret.push_str(e),
                }
            }
            "pubkey" => {
                let path = tokens.next().unwrap_or("").to_string();
                match self.require_unlocked() {
                    Ok(wallet) => match wallet.pubkey(&path) {
                        Ok(pk) => to_hex(&pk, &mut ret),
                        Err(e) => {
                            write!(ret, "derivation error: {:?}", e).ok();
                        }
                    },
                    Err(e) => ret.push_str(e),
                }
            }
            "xpub" => {
                let path = tokens.next().unwrap_or("").to_string();
                match self.require_unlocked() {
                    Ok(wallet) => match wallet.xpub(&path) {
                        Ok(xpub) => ret.push_str(&xpub),
                        Err(e) => {
                            write!(ret, "derivation error: {:?}", e).ok();
                        }
                    },
                    Err(e) => ret.push_str(e),
                }
            }
            "sign-psbt" => {
                let hex_arg = tokens.next().unwrap_or("");
                match from_hex(hex_arg) {
                    Some(psbt_bytes) => match self.require_unlocked() {
                        Ok(wallet) => match wallet.sign_psbt(&psbt_bytes) {
                            Ok(signed) => to_hex(&signed, &mut ret),
                            Err(e) => {
                                write!(ret, "signing failed: {:?}", e).ok();
                            }
                        },
                        Err(e) => ret.push_str(e),
                    },
                    None => ret.push_str("expected a hex-encoded PSBT"),
                }
            }
            "extract-psbt" => {
                let hex_arg = tokens.next().unwrap_or("");
                match from_hex(hex_arg) {
                    Some(psbt_bytes) => match self.require_unlocked() {
                        Ok(wallet) => match wallet.sign_and_extract(&psbt_bytes) {
                            Ok(final_tx) => to_hex(&final_tx, &mut ret),
                            Err(e) => {
                                write!(ret, "signing failed: {:?}", e).ok();
                            }
                        },
                        Err(e) => ret.push_str(e),
                    },
                    None => ret.push_str("expected a hex-encoded PSBT"),
                }
            }
            "wipe" => {
                self.wallet = None;
                if self.wipe_locked() {
                    ret.push_str("wallet wiped (seed and PIN erased)");
                } else {
                    ret.push_str("failed to fully wipe seed");
                }
            }
            _ => {
                print_chunked(HELP);
                return Ok(None);
            }
        }
        print_chunked(&ret);
        Ok(None)
    }
}
