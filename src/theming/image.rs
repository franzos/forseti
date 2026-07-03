//! Detect the true image type by magic bytes; the client-declared type is never trusted.

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
    fn rejects_svg_short_and_riff_non_webp() {
        assert_eq!(detect(b"<svg xmlns=..."), None);
        assert_eq!(detect(b"RIF"), None); // short, must not panic
        assert_eq!(detect(b""), None);
        assert_eq!(detect(b"RIFF\x00\x00\x00\x00WAVEfmt "), None); // RIFF but not WEBP
        assert_eq!(detect(b"RIFF\x00\x00\x00\x00WEBPXXXX"), None); // WEBP but bad fourCC
    }
}
