//! Deterministic SVG identicon — no external crate, no upload pipeline.
//!
//! Hash the identity_id with SHA-256, use the first byte trio as an HSL
//! colour (fixed saturation/lightness for readability), and the next
//! few bytes as a 5x5 mirrored cell pattern. Output is a compact SVG
//! that templates inline via `{{ identicon }}|safe`.

use sha2::{Digest, Sha256};

/// Render a 64x64 SVG identicon for `seed`. The fixed viewBox lets the
/// caller scale via CSS (e.g. width: 96px on the profile page, 32px in
/// the roster).
pub fn render(seed: &str) -> String {
    let hash = Sha256::digest(seed.as_bytes());
    // First three bytes pick the foreground hue; saturation/lightness
    // pinned to values that read well on both light and dark cards.
    // u32 to dodge overflow: 255 * 360 = 91 800 > u16::MAX.
    let hue = u32::from(hash[0]) * 360 / 255;
    let fg = format!("hsl({hue}, 65%, 55%)");
    let bg = "hsl(0, 0%, 96%)";

    // 5x5 grid mirrored across the vertical axis — only the 3 leftmost
    // cells per row are randomised (columns 3-4 mirror columns 1-0).
    // 5 rows × 3 cells = 15 bits, well inside the next two hash bytes.
    let bits = u16::from(hash[1]) | (u16::from(hash[2]) << 8);

    let mut cells = String::with_capacity(512);
    for row in 0..5 {
        for col in 0..3 {
            let bit_idx = row * 3 + col;
            if bits & (1 << bit_idx) != 0 {
                let x = col * 12 + 2;
                let y = row * 12 + 2;
                cells.push_str(&format!(
                    r#"<rect x="{x}" y="{y}" width="12" height="12" fill="{fg}"/>"#
                ));
                // Mirror onto the right side unless we're on the middle column.
                if col < 2 {
                    let mirror_x = (4 - col) * 12 + 2;
                    cells.push_str(&format!(
                        r#"<rect x="{mirror_x}" y="{y}" width="12" height="12" fill="{fg}"/>"#
                    ));
                }
            }
        }
    }

    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="Identicon">
<rect width="64" height="64" rx="6" fill="{bg}"/>
{cells}
</svg>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_is_deterministic() {
        let a = render("00000000-1111-2222-3333-444444444444");
        let b = render("00000000-1111-2222-3333-444444444444");
        assert_eq!(a, b);
    }

    #[test]
    fn render_differs_per_seed() {
        let a = render("aaa");
        let b = render("bbb");
        assert_ne!(a, b);
    }
}
