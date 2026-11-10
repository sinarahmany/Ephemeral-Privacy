use tokio::io::{AsyncWrite, AsyncWriteExt};

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
}
