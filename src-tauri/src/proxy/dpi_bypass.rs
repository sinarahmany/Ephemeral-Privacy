use rand::RngExt;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Builds TLS record-split frames for a valid TLS ClientHello without changing handshake transcript bytes.
/// Because TLS Transcript-Hash only hashes the inner Handshake payload and ignores outer 5-byte TLSPlaintext
/// record headers, splitting into multiple `0x16` records is RFC 8446 compliant and blinds single-record
/// SNI & JA3 passive inspection probes.
pub fn split_client_hello_records(buf: &[u8]) -> Option<Vec<Vec<u8>>> {
    if buf.len() < 55 || buf[0] != 0x16 || buf[5] != 0x01 {
        return None;
    }

    let ver_hi = buf[1];
    let ver_lo = buf[2];
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if rec_len < 48 || 5 + rec_len > buf.len() {
        return None;
    }

    let payload = &buf[5..5 + rec_len];
    let trailing = &buf[5 + rec_len..];

    let mut rng = rand::rng();
    // Choose 2 split boundaries inside `payload`
    let first_split = rng.random_range(12..28.min(payload.len() - 10));
    let second_split = if let Some((sni_off, sni_len)) = find_sni_offset(buf) {
        let rel_sni = sni_off.saturating_sub(5) + (sni_len / 2).max(1);
        if rel_sni > first_split + 4 && rel_sni < payload.len() - 2 {
            rel_sni
        } else {
            (first_split + (payload.len() - first_split) / 2).min(payload.len() - 1)
        }
    } else {
        (first_split + (payload.len() - first_split) / 2).min(payload.len() - 1)
    };

    if first_split >= second_split || second_split >= payload.len() {
        return None;
    }

    let slices = [
        &payload[..first_split],
        &payload[first_split..second_split],
        &payload[second_split..],
    ];

    let mut records = Vec::with_capacity(4);
    for chunk in slices {
        let mut rec = Vec::with_capacity(5 + chunk.len());
        rec.push(0x16);
        rec.push(ver_hi);
        rec.push(ver_lo);
        rec.push((chunk.len() >> 8) as u8);
        rec.push((chunk.len() & 0xff) as u8);
        rec.extend_from_slice(chunk);
        records.push(rec);
    }

    if !trailing.is_empty() {
        records.push(trailing.to_vec());
    }

    Some(records)
}

/// Sends an obfuscated ClientHello using RFC-safe TLS Record Splitting and/or TCP SNI fragmentation.
pub async fn send_obfuscated_client_hello<W>(
    writer: &mut W,
    buf: &[u8],
    split_records: bool,
    fragment_sni: bool,
) -> std::io::Result<(bool, bool)>
where
    W: AsyncWrite + Unpin,
{
    if split_records {
        if let Some(records) = split_client_hello_records(buf) {
            let mut delays_us = [700u64, 1400u64, 900u64];
            {
                let mut rng = rand::rng();
                for d in &mut delays_us {
                    *d = rng.random_range(400..2200);
                }
            }

            for (i, rec) in records.iter().enumerate() {
                writer.write_all(rec).await?;
                writer.flush().await?;
                if i + 1 < records.len() {
                    let delay = delays_us[i % delays_us.len()];
                    tokio::time::sleep(std::time::Duration::from_micros(delay)).await;
                }
            }
            return Ok((true, true));
        }
    }

    if fragment_sni {
        let did_frag = send_fragmented_client_hello(writer, buf).await?;
        return Ok((did_frag, false));
    }

    writer.write_all(buf).await?;
    writer.flush().await?;
    Ok((false, false))
}

/// Attempts to locate the Server Name Indication (SNI) extension inside a TLS ClientHello packet.
/// Returns the byte offset within `buf` where the SNI hostname resides, and its length.
pub fn find_sni_offset(buf: &[u8]) -> Option<(usize, usize)> {
    // Basic validation of TLS Handshake Record
    if buf.len() < 43 || buf[0] != 0x16 || buf[5] != 0x01 {
        return None;
    }

    let mut cursor = 43; // Past record header (5), handshake header (4), version (2), random (32)

    // Skip Session ID
    if cursor >= buf.len() {
        return None;
    }
    let session_id_len = buf[cursor] as usize;
    cursor += 1 + session_id_len;

    // Skip Cipher Suites
    if cursor + 2 > buf.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) as usize;
    cursor += 2 + cipher_suites_len;

    // Skip Compression Methods
    if cursor >= buf.len() {
        return None;
    }
    let compression_len = buf[cursor] as usize;
    cursor += 1 + compression_len;

    // Extensions block
    if cursor + 2 > buf.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) as usize;
    cursor += 2;

    let extensions_end = (cursor + extensions_len).min(buf.len());

    // Iterate through extensions to find server_name (0x0000)
    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        let ext_len = u16::from_be_bytes([buf[cursor + 2], buf[cursor + 3]]) as usize;
        cursor += 4;

        if ext_type == 0x0000 {
            // SNI Extension found!
            // SNI structure: list_len (2 bytes), type (1 byte, 0 = host_name), name_len (2 bytes), name
            if cursor + 5 <= extensions_end {
                let name_len = u16::from_be_bytes([buf[cursor + 3], buf[cursor + 4]]) as usize;
                let name_offset = cursor + 5;
                if name_offset + name_len <= extensions_end {
                    return Some((name_offset, name_len));
                }
            }
            return None;
        }

        cursor += ext_len;
    }

    None
}

/// Slices the TLS ClientHello TCP packet through the middle of the SNI domain name.
/// This prevents ISP Deep Packet Inspection (DPI) boxes from reading the destination domain.
pub async fn send_fragmented_client_hello<W>(writer: &mut W, buf: &[u8]) -> std::io::Result<bool>
where
    W: AsyncWrite + Unpin,
{
    if let Some((offset, len)) = find_sni_offset(buf) {
        if len > 2 {
            // Split right in the middle of the domain name string (e.g. "exam" and "ple.com")
            let split_point = offset + (len / 2);

            // Send chunk 1
            writer.write_all(&buf[..split_point]).await?;
            writer.flush().await?;

            // Subtle micro-delay to ensure TCP segment fragmentation across network buffers
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;

            // Send chunk 2
            writer.write_all(&buf[split_point..]).await?;
            writer.flush().await?;

            return Ok(true); // Successfully fragmented SNI
        }
    }

    // Fallback: send whole buffer if not ClientHello or SNI not found
    writer.write_all(buf).await?;
    writer.flush().await?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_offset_detection() {
        // Construct a minimal synthetic ClientHello packet with SNI "example.com"
        let hostname = b"example.com";
        let mut packet = vec![
            0x16, 0x03, 0x01, 0x00, 0x00, // Record header (length patched later)
            0x01, 0x00, 0x00, 0x00,       // Handshake ClientHello header
            0x03, 0x03,                   // Version
        ];
        // 32 bytes random
        packet.extend_from_slice(&[0xaa; 32]);
        // Session ID len 0
        packet.push(0x00);
        // Cipher suites: len 2, 0x1301 (TLS_AES_128_GCM_SHA256)
        packet.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // Compression: len 1, 0x00
        packet.extend_from_slice(&[0x01, 0x00]);

        // Extensions
        let sni_ext_len = 2 + 1 + 2 + hostname.len() as u16;
        let mut ext_block = vec![
            0x00, 0x00, // ext_type = server_name
            (sni_ext_len >> 8) as u8, (sni_ext_len & 0xff) as u8,
            0x00, (1 + 2 + hostname.len()) as u8, // list_len
            0x00, // name_type = host_name
            (hostname.len() >> 8) as u8, (hostname.len() & 0xff) as u8,
        ];
        ext_block.extend_from_slice(hostname);

        let total_ext_len = ext_block.len() as u16;
        packet.extend_from_slice(&[(total_ext_len >> 8) as u8, (total_ext_len & 0xff) as u8]);
        packet.extend_from_slice(&ext_block);

        let found = find_sni_offset(&packet);
        assert!(found.is_some());
        let (offset, len) = found.unwrap();
        assert_eq!(&packet[offset..offset + len], hostname);
    }

    #[test]
    fn test_record_layer_splitting_preserves_handshake_bytes() {
        let hostname = b"privacy-audit-test.example.org";
        let mut packet = vec![
            0x16, 0x03, 0x01, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x03, 0x03,
        ];
        packet.extend_from_slice(&[0xbb; 32]);
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
        packet.extend_from_slice(&[0x01, 0x00]);
        let sni_ext_len = 2 + 1 + 2 + hostname.len() as u16;
        let mut ext_block = vec![
            0x00, 0x00,
            (sni_ext_len >> 8) as u8, (sni_ext_len & 0xff) as u8,
            0x00, (1 + 2 + hostname.len()) as u8,
            0x00,
            (hostname.len() >> 8) as u8, (hostname.len() & 0xff) as u8,
        ];
        ext_block.extend_from_slice(hostname);
        let total_ext_len = ext_block.len() as u16;
        packet.extend_from_slice(&[(total_ext_len >> 8) as u8, (total_ext_len & 0xff) as u8]);
        packet.extend_from_slice(&ext_block);

        let payload_len = (packet.len() - 5) as u16;
        packet[3] = (payload_len >> 8) as u8;
        packet[4] = (payload_len & 0xff) as u8;

        let records = split_client_hello_records(&packet).expect("should split valid ClientHello");
        assert_eq!(records.len(), 3);

        let mut reconstructed = Vec::new();
        for rec in &records {
            assert_eq!(rec[0], 0x16);
            assert_eq!(rec[1], 0x03);
            assert_eq!(rec[2], 0x01);
            let rlen = u16::from_be_bytes([rec[3], rec[4]]) as usize;
            assert_eq!(rec.len(), 5 + rlen);
            reconstructed.extend_from_slice(&rec[5..]);
        }

        assert_eq!(reconstructed, &packet[5..]);
    }
}
