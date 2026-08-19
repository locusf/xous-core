//! Bitcoin's variable-length integer ("CompactSize"/"VarInt") encoding, used throughout raw
//! transaction and PSBT serialization.

/// Reads a CompactSize-encoded integer from the front of `data`, returning `(value,
/// bytes_consumed)`.
pub fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    match first {
        0..=0xfc => Some((first as u64, 1)),
        0xfd => {
            let b = data.get(1..3)?;
            Some((u16::from_le_bytes(b.try_into().ok()?) as u64, 3))
        }
        0xfe => {
            let b = data.get(1..5)?;
            Some((u32::from_le_bytes(b.try_into().ok()?) as u64, 5))
        }
        0xff => {
            let b = data.get(1..9)?;
            Some((u64::from_le_bytes(b.try_into().ok()?), 9))
        }
    }
}

/// Encodes `value` as a CompactSize integer, appending it to `out`.
pub fn write_varint(out: &mut Vec<u8>, value: u64) {
    if value <= 0xfc {
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Reads a CompactSize-prefixed length, then that many following bytes, as a single field.
pub fn read_varbytes(data: &[u8]) -> Option<(&[u8], usize)> {
    let (len, consumed) = read_varint(data)?;
    let len = len as usize;
    let bytes = data.get(consumed..consumed + len)?;
    Some((bytes, consumed + len))
}

/// Encodes `bytes` as a CompactSize length prefix followed by the bytes themselves.
pub fn write_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_varint() {
        for v in [0u64, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let (parsed, consumed) = read_varint(&buf).unwrap();
            assert_eq!(parsed, v);
            assert_eq!(consumed, buf.len());
        }
    }
}
