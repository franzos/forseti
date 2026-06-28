//! Deterministic SVG identicon: SHA-256 of the seed picks an HSL hue and a 5x5
//! mirrored cell pattern. Templates inline the SVG via `{{ identicon }}|safe`.

use sha2::{Digest, Sha256};

/// Render a 64x64 SVG identicon for `seed`; the fixed viewBox lets callers
/// scale via CSS.
pub fn render(seed: &str) -> String {
    let hash = Sha256::digest(seed.as_bytes());
    // u32 to dodge overflow: 255 * 360 = 91 800 > u16::MAX.
    let hue = u32::from(hash[0]) * 360 / 255;
    let fg = format!("hsl({hue}, 65%, 55%)");
    let bg = "hsl(0, 0%, 96%)";

    // 5x5 grid mirrored across the vertical axis: 5 rows x 3 left cells = 15
    // bits, taken from the next two hash bytes.
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
