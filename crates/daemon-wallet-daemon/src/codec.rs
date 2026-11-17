//! The Chrome Native Messaging framing codec.
//!
//! The wire is a 4-byte little-endian `u32` length prefix followed by exactly
//! that many bytes of UTF-8 JSON. This module is the *pure* half of the daemon:
//! it reads and writes frames over any [`Read`]/[`Write`] and knows nothing
//! about wallets, approval, or terminals. That split is what lets the framing be
//! unit-tested against in-memory buffers (see the tests below) with no Chrome and
//! no stdio involved.

use std::io::{self, Read, Write};

/// Upper bound on a single frame, as a defence against a hostile or corrupt
/// length prefix forcing a huge allocation. Chrome itself caps a message from the
/// extension at 1 MiB; this ceiling is generous above that.
pub const MAX_MESSAGE_LEN: u32 = 64 * 1024 * 1024;

/// Read one length-prefixed frame from `reader`.
///
/// Returns:
/// - `Ok(Some(bytes))` for a complete frame,
/// - `Ok(None)` on a *clean* end of stream at a frame boundary (the peer closed
///   the pipe between messages), and
/// - `Err(..)` for an I/O failure or a *truncated* frame — a partial length
///   prefix or a body shorter than its declared length is reported as
///   [`io::ErrorKind::UnexpectedEof`], not silently treated as a clean close.
pub fn read_message<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    // Read the first byte on its own so a clean EOF at a frame boundary (zero
    // bytes available) is distinguishable from a truncated length prefix (one to
    // three bytes then EOF).
    let mut first = [0u8; 1];
    if reader.read(&mut first)? == 0 {
        return Ok(None);
    }

    let mut rest = [0u8; 3];
    reader.read_exact(&mut rest)?;
    let len = u32::from_le_bytes([first[0], rest[0], rest[1], rest[2]]);

    if len > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds maximum {MAX_MESSAGE_LEN}"),
        ));
    }

    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Write `body` to `writer` as one length-prefixed frame and flush.
///
/// Fails with [`io::ErrorKind::InvalidInput`] if `body` is longer than a `u32`
/// can address.
pub fn write_message<W: Write>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame body exceeds u32 length limit",
        )
    })?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trips_a_frame() {
        let payload = br#"{"id":"1","method":"wallet_status","params":[]}"#;
        let mut buf: Vec<u8> = Vec::new();
        write_message(&mut buf, payload).expect("write");

        // The length prefix is the body length, little-endian.
        assert_eq!(&buf[0..4], (payload.len() as u32).to_le_bytes());

        let mut cursor = Cursor::new(buf);
        let read = read_message(&mut cursor).expect("read").expect("some");
        assert_eq!(read, payload);
    }

    #[test]
    fn round_trips_several_frames_back_to_back() {
        let a = b"first";
        let b = b"second message";
        let mut buf: Vec<u8> = Vec::new();
        write_message(&mut buf, a).unwrap();
        write_message(&mut buf, b).unwrap();

        let mut cursor = Cursor::new(buf);
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), a);
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), b);
        // A clean boundary EOF yields None, not an error.
        assert!(read_message(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn clean_eof_at_boundary_is_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert!(read_message(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn partial_length_prefix_is_an_error() {
        // Only two of the four length bytes are present: a truncated prefix must
        // surface as an error rather than masquerade as a clean close.
        let mut cursor = Cursor::new(vec![0x05u8, 0x00]);
        let err = read_message(&mut cursor).expect_err("partial prefix must error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn truncated_body_is_an_error() {
        // Declares a 5-byte body but only supplies 3.
        let mut buf: Vec<u8> = 5u32.to_le_bytes().to_vec();
        buf.extend_from_slice(b"abc");
        let mut cursor = Cursor::new(buf);
        let err = read_message(&mut cursor).expect_err("short body must error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
