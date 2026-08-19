//! Base58 / Base58Check encoding, used for BIP-32 extended public/private key serialization
//! (`xpub`/`tpub`/... strings). Not used for addresses (this wallet only produces Bech32
//! native SegWit addresses), so only the pieces BIP-32 needs are implemented.

use crate::hash::sha256d;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Plain Base58 encoding (no checksum) of arbitrary bytes.
pub fn encode(data: &[u8]) -> String {
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Repeatedly divide the big-endian number `data` by 58, in base 256, collecting
    // remainders; this is the standard "convert arbitrary base" long-division algorithm.
    let mut digits: Vec<u8> = Vec::new();
    let mut input = data.to_vec();
    let mut start = leading_zeros;
    while start < input.len() {
        let mut remainder: u32 = 0;
        for byte in input.iter_mut().skip(start) {
            let acc = remainder * 256 + *byte as u32;
            *byte = (acc / 58) as u8;
            remainder = acc % 58;
        }
        digits.push(remainder as u8);
        // skip over any new leading zero(es) produced by the division to keep it fast
        while start < input.len() && input[start] == 0 {
            start += 1;
        }
    }

    let mut out = String::with_capacity(leading_zeros + digits.len());
    out.extend(std::iter::repeat_n('1', leading_zeros));
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

/// Base58Check: appends a 4-byte `SHA256d` checksum to `payload`, then Base58-encodes it.
pub fn encode_check(payload: &[u8]) -> String {
    let checksum = sha256d(payload);
    let mut data = payload.to_vec();
    data.extend_from_slice(&checksum[..4]);
    encode(&data)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Base58Error {
    InvalidCharacter,
    ChecksumMismatch,
    TooShort,
}

/// Decodes plain Base58 (no checksum) back to bytes.
pub fn decode(s: &str) -> Result<Vec<u8>, Base58Error> {
    let leading_ones = s.bytes().take_while(|&b| b == b'1').count();

    let mut out: Vec<u8> = vec![0];
    for ch in s.bytes().skip(leading_ones) {
        let digit =
            ALPHABET.iter().position(|&c| c == ch).ok_or(Base58Error::InvalidCharacter)? as u32;
        let mut carry = digit;
        for byte in out.iter_mut().rev() {
            let acc = *byte as u32 * 58 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // trim any leading zero bytes produced by the big-number math itself (not real data)
    let first_nonzero = out.iter().position(|&b| b != 0).unwrap_or(out.len());
    let mut result = vec![0u8; leading_ones];
    result.extend_from_slice(&out[first_nonzero..]);
    Ok(result)
}

/// Decodes a Base58Check string, verifying and stripping the trailing 4-byte checksum.
pub fn decode_check(s: &str) -> Result<Vec<u8>, Base58Error> {
    let data = decode(s)?;
    if data.len() < 4 {
        return Err(Base58Error::TooShort);
    }
    let (payload, checksum) = data.split_at(data.len() - 4);
    if sha256d(payload)[..4] != *checksum {
        return Err(Base58Error::ChecksumMismatch);
    }
    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_known_vectors() {
        // widely-published Base58 (no checksum) test vectors
        assert_eq!(encode(b""), "");
        assert_eq!(encode(&[0]), "1");
        assert_eq!(encode(&[0, 0, 0]), "111");
        assert_eq!(encode(b"hello world"), "StV1DL6CwTryKyV");
    }

    #[test]
    fn decode_is_inverse_of_encode() {
        for data in [
            &b""[..],
            &[0][..],
            &[0, 0, 1, 2, 3][..],
            &[0xff; 32][..],
            b"the quick brown fox jumps over the lazy dog",
        ] {
            assert_eq!(decode(&encode(data)).unwrap(), data);
        }
    }

    #[test]
    fn check_roundtrip_and_tamper_detection() {
        let payload = b"some extended key payload bytes";
        let s = encode_check(payload);
        assert_eq!(decode_check(&s).unwrap(), payload);

        // flip a character; the checksum must catch it
        let mut tampered: Vec<char> = s.chars().collect();
        let mid = tampered.len() / 2;
        tampered[mid] = if tampered[mid] == '1' { '2' } else { '1' };
        let tampered: String = tampered.into_iter().collect();
        assert!(matches!(
            decode_check(&tampered),
            Err(Base58Error::ChecksumMismatch) | Err(Base58Error::InvalidCharacter)
        ));
    }
}
