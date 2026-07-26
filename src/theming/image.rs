//! Detect the true image type by magic bytes; the client-declared type is never trusted.

/// Ceiling for any uploaded logo blob (org branding, OAuth client).
pub const MAX_LOGO_BYTES: usize = 256 * 1024;

/// Size + true-type gate shared by every logo upload path. The error is the
/// operator-facing message.
pub fn validate_logo(bytes: &[u8]) -> Result<&'static str, &'static str> {
    if bytes.len() > MAX_LOGO_BYTES {
        return Err("logo file exceeds 256 KB");
    }
    detect(bytes).ok_or("unsupported image type")
}

pub fn detect(b: &[u8]) -> Option<&'static str> {
    if b.len() >= 8 && b[0..8] == [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'] {
        return Some("image/png");
    }
    if b.len() >= 3 && b[0..3] == [0xff, 0xd8, 0xff] {
        return Some("image/jpeg");
    }
    if b.len() >= 16
        && &b[0..4] == b"RIFF"
        && &b[8..12] == b"WEBP"
        && matches!(&b[12..16], b"VP8 " | b"VP8L" | b"VP8X")
    {
        return Some("image/webp");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_png_jpeg_webp() {
        assert_eq!(detect(b"\x89PNG\r\n\x1a\n....."), Some("image/png"));
        assert_eq!(detect(b"\xff\xd8\xff\xe0rest"), Some("image/jpeg"));
        let mut webp = b"RIFF\x00\x00\x00\x00WEBPVP8 ".to_vec();
        webp.extend_from_slice(b"rest");
        assert_eq!(detect(&webp), Some("image/webp"));
    }
    #[test]
    fn validate_logo_accepts_small_png() {
        let mut png = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        png.extend_from_slice(&[0u8; 32]);
        assert_eq!(validate_logo(&png), Ok("image/png"));
    }

    #[test]
    fn validate_logo_rejects_oversize() {
        let mut png = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        png.resize(8 + MAX_LOGO_BYTES + 1, 0);
        let err = validate_logo(&png).unwrap_err();
        assert_eq!(err, "logo file exceeds 256 KB");
    }

    #[test]
    fn validate_logo_rejects_non_image() {
        let err = validate_logo(b"<svg xmlns=...>").unwrap_err();
        assert_eq!(err, "unsupported image type");
    }

    #[test]
    fn rejects_svg_short_and_riff_non_webp() {
        assert_eq!(detect(b"<svg xmlns=..."), None);
        assert_eq!(detect(b"RIF"), None); // short, must not panic
        assert_eq!(detect(b""), None);
        assert_eq!(detect(b"RIFF\x00\x00\x00\x00WAVEfmt "), None); // RIFF but not WEBP
        assert_eq!(detect(b"RIFF\x00\x00\x00\x00WEBPXXXX"), None); // WEBP but bad fourCC
    }
}
