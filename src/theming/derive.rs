use crate::theming::color::{parse_color, Color};

const DARK_SURFACE: (u8, u8, u8) = (0x13, 0x13, 0x14);
const DARK_ON_LIGHT: (u8, u8, u8) = (0x1b, 0x1b, 0x1d);
const LIGHT_ON_DARK: (u8, u8, u8) = (0xe6, 0xe1, 0xe5);
const AA: f64 = 4.5;

fn pairable(rgb: (u8, u8, u8)) -> bool {
    contrast_ratio(rgb, DARK_ON_LIGHT) >= AA || contrast_ratio(rgb, LIGHT_ON_DARK) >= AA
}

pub fn to_rgb(c: &Color) -> Option<(u8, u8, u8)> {
    let s = c.as_str();
    if let Some(hex) = s.strip_prefix('#') {
        return match hex.len() {
            3 | 4 => {
                let d = |i: usize| u8::from_str_radix(&hex[i..=i], 16).ok().map(|v| v * 17);
                Some((d(0)?, d(1)?, d(2)?))
            }
            6 | 8 => {
                let d = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
                Some((d(0)?, d(2)?, d(4)?))
            }
            _ => None,
        };
    }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("rgb(") || lower.starts_with("rgba(") {
        let inner = s[s.find('(')? + 1..s.rfind(')')?].trim();
        let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
        if parts.len() >= 3 {
            let p = |x: &str| {
                if let Some(pct) = x.strip_suffix('%') {
                    pct.parse::<f64>().ok().map(|v| v * 255.0 / 100.0)
                } else {
                    x.parse::<f64>().ok()
                }
            };
            return Some((
                clamp8(p(parts[0])?),
                clamp8(p(parts[1])?),
                clamp8(p(parts[2])?),
            ));
        }
    }
    None
}

fn clamp8(v: f64) -> u8 {
    v.round().clamp(0.0, 255.0) as u8
}

fn channel_lum(c: u8) -> f64 {
    let s = f64::from(c) / 255.0;
    if s <= 0.03928 {
        s / 12.92
    } else {
        ((s + 0.055) / 1.055).powf(2.4)
    }
}

fn relative_luminance((r, g, b): (u8, u8, u8)) -> f64 {
    0.2126 * channel_lum(r) + 0.7152 * channel_lum(g) + 0.0722 * channel_lum(b)
}

pub fn contrast_ratio(a: (u8, u8, u8), b: (u8, u8, u8)) -> f64 {
    let (la, lb) = (relative_luminance(a), relative_luminance(b));
    let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

pub fn derive_dark_variant(primary: &Color) -> Option<Color> {
    let rgb = to_rgb(primary)?;
    if contrast_ratio(rgb, DARK_SURFACE) >= AA && pairable(rgb) {
        return Some(primary.clone());
    }
    let (r, g, b) = rgb;
    for step in 1..=10 {
        let t = f64::from(step) / 10.0;
        let mix = |ch: u8| clamp8(f64::from(ch) + (255.0 - f64::from(ch)) * t);
        let cand = (mix(r), mix(g), mix(b));
        if contrast_ratio(cand, DARK_SURFACE) >= AA && pairable(cand) {
            return parse_color(&format!("#{:02x}{:02x}{:02x}", cand.0, cand.1, cand.2));
        }
    }
    parse_color("#e6e1e5")
}

/// Near-black or near-white, whichever best contrasts `bg` for dark-mode button text.
pub fn derive_on_color(bg: &Color) -> Color {
    let rgb = to_rgb(bg).unwrap_or((0, 0, 0));
    if contrast_ratio(rgb, LIGHT_ON_DARK) >= contrast_ratio(rgb, DARK_ON_LIGHT) {
        parse_color("#e6e1e5").expect("valid hex")
    } else {
        parse_color("#1b1b1d").expect("valid hex")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theming::color::parse_color;

    fn c(s: &str) -> crate::theming::color::Color {
        parse_color(s).unwrap()
    }

    #[test]
    fn to_rgb_parses_hex_forms() {
        assert_eq!(to_rgb(&c("#ffffff")), Some((255, 255, 255)));
        assert_eq!(to_rgb(&c("#000")), Some((0, 0, 0)));
        assert_eq!(to_rgb(&c("#12ab34")), Some((0x12, 0xab, 0x34)));
        assert_eq!(to_rgb(&c("rgb(1,2,3)")), Some((1, 2, 3)));
    }

    #[test]
    fn to_rgb_scales_rgb_percentages() {
        assert_eq!(to_rgb(&c("rgb(100%,0%,0%)")), Some((255, 0, 0)));
        assert_eq!(to_rgb(&c("rgb(50%,50%,50%)")), Some((128, 128, 128)));
    }

    #[test]
    fn contrast_white_on_black_is_max() {
        let r = contrast_ratio((255, 255, 255), (0, 0, 0));
        assert!((r - 21.0).abs() < 0.1, "got {r}");
    }

    #[test]
    fn dark_variant_of_dark_primary_is_lightened_and_legible() {
        let derived = derive_dark_variant(&c("#000000")).unwrap();
        let dark_surface = (0x13, 0x13, 0x14);
        assert!(contrast_ratio(to_rgb(&derived).unwrap(), dark_surface) >= 4.5);
    }

    #[test]
    fn already_legible_primary_survives() {
        let derived = derive_dark_variant(&c("#ff2e97")).unwrap();
        assert_eq!(derived.as_str(), "#ff2e97");
    }
}
