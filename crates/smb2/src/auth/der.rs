//! Shared ASN.1/DER encoding and decoding primitives.
//!
//! These low-level helpers are used by both `spnego.rs` and `kerberos/messages.rs`
//! to build and parse DER-encoded structures. Only the core TLV operations live
//! here; type-specific helpers (INTEGER, GeneralString, etc.) stay in their
//! respective modules.

use crate::Error;

/// Encode a DER length field.
///
/// - Lengths < 128 are encoded as a single byte.
/// - Lengths < 256 are encoded as `0x81` followed by one byte.
/// - Lengths < 65536 are encoded as `0x82` followed by two bytes (big-endian).
pub(crate) fn der_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

/// Wrap data in a DER TLV (tag-length-value).
pub(crate) fn der_tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_length(data.len()));
    out.extend_from_slice(data);
    out
}

/// Parse a DER length field, returning `(length, bytes_consumed)`.
pub(crate) fn parse_der_length(data: &[u8]) -> Result<(usize, usize), Error> {
    if data.is_empty() {
        return Err(Error::invalid_data("DER: truncated length"));
    }
    let first = data[0];
    if first < 128 {
        Ok((first as usize, 1))
    } else if first == 0x81 {
        if data.len() < 2 {
            return Err(Error::invalid_data("DER: truncated length (0x81)"));
        }
        Ok((data[1] as usize, 2))
    } else if first == 0x82 {
        if data.len() < 3 {
            return Err(Error::invalid_data("DER: truncated length (0x82)"));
        }
        let len = ((data[1] as usize) << 8) | (data[2] as usize);
        Ok((len, 3))
    } else if first == 0x83 {
        if data.len() < 4 {
            return Err(Error::invalid_data("DER: truncated length (0x83)"));
        }
        let len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
        Ok((len, 4))
    } else {
        Err(Error::invalid_data(format!(
            "DER: unsupported length encoding: 0x{first:02x}"
        )))
    }
}

/// Parse a DER TLV, returning `(tag, value_slice, total_bytes_consumed)`.
pub(crate) fn parse_der_tlv(data: &[u8]) -> Result<(u8, &[u8], usize), Error> {
    if data.is_empty() {
        return Err(Error::invalid_data("DER: truncated TLV"));
    }
    let tag = data[0];
    let (len, len_bytes) = parse_der_length(&data[1..])?;
    let header_len = 1 + len_bytes;
    let total = header_len + len;
    if data.len() < total {
        return Err(Error::invalid_data(format!(
            "DER: TLV truncated: need {total} bytes, have {}",
            data.len()
        )));
    }
    Ok((tag, &data[header_len..total], total))
}

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // DER length encoding
    // =======================================================================

    #[test]
    fn length_single_byte() {
        assert_eq!(der_length(0), vec![0x00]);
        assert_eq!(der_length(1), vec![0x01]);
        assert_eq!(der_length(127), vec![0x7f]);
    }

    #[test]
    fn length_two_byte() {
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(255), vec![0x81, 0xff]);
    }

    #[test]
    fn length_three_byte() {
        assert_eq!(der_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(der_length(65535), vec![0x82, 0xff, 0xff]);
        assert_eq!(der_length(1000), vec![0x82, 0x03, 0xe8]);
    }

    // =======================================================================
    // DER TLV encoding
    // =======================================================================

    #[test]
    fn tlv_simple() {
        let result = der_tlv(0x04, &[0x01, 0x02]);
        assert_eq!(result, vec![0x04, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn tlv_empty() {
        let result = der_tlv(0x30, &[]);
        assert_eq!(result, vec![0x30, 0x00]);
    }

    #[test]
    fn tlv_long_content() {
        let data = vec![0xaa; 200];
        let result = der_tlv(0x04, &data);
        assert_eq!(result[0], 0x04);
        assert_eq!(result[1], 0x81);
        assert_eq!(result[2], 200);
        assert_eq!(result.len(), 3 + 200);
    }

    // =======================================================================
    // DER length parsing
    // =======================================================================

    #[test]
    fn parse_length_single_byte() {
        let (len, consumed) = parse_der_length(&[0x05]).unwrap();
        assert_eq!(len, 5);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn parse_length_two_byte() {
        let (len, consumed) = parse_der_length(&[0x81, 0x80]).unwrap();
        assert_eq!(len, 128);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn parse_length_three_byte() {
        let (len, consumed) = parse_der_length(&[0x82, 0x01, 0x00]).unwrap();
        assert_eq!(len, 256);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn parse_length_four_byte() {
        let (len, consumed) = parse_der_length(&[0x83, 0x01, 0x00, 0x00]).unwrap();
        assert_eq!(len, 65536);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn parse_length_truncated() {
        assert!(parse_der_length(&[]).is_err());
        assert!(parse_der_length(&[0x81]).is_err());
        assert!(parse_der_length(&[0x82, 0x01]).is_err());
        assert!(parse_der_length(&[0x83, 0x01, 0x00]).is_err());
    }

    // =======================================================================
    // DER TLV parsing
    // =======================================================================

    #[test]
    fn parse_tlv_roundtrip() {
        let original = der_tlv(0x04, &[0xde, 0xad, 0xbe, 0xef]);
        let (tag, value, total) = parse_der_tlv(&original).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(value, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(total, original.len());
    }

    #[test]
    fn parse_tlv_truncated() {
        assert!(parse_der_tlv(&[]).is_err());
        // Tag present, length says 10 bytes but only 2 available
        assert!(parse_der_tlv(&[0x04, 0x0a, 0x01, 0x02]).is_err());
    }
}
