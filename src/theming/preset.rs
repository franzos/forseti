use crate::theming::color::{parse_color, Color};

pub struct Preset {
    // Only used by tests to identify which preset a lookup returned.
    #[allow(dead_code)]
    pub name: &'static str,
    pub primary: Color,
    pub on_primary: Color,
    pub secondary: Color,
}

pub const ALL: &[&str] = &["default", "midnight", "cyberpunk"];

fn c(s: &str) -> Color {
    parse_color(s).expect("built-in preset colors are valid by construction")
}

pub fn lookup(name: &str) -> Preset {
    match name {
        "midnight" => Preset {
            name: "midnight",
            primary: c("#3b4a6b"),
            on_primary: c("#ffffff"),
            secondary: c("#8892b0"),
        },
        "cyberpunk" => Preset {
            name: "cyberpunk",
            primary: c("#ff2e97"),
            on_primary: c("#0a0a12"),
            secondary: c("#00f0ff"),
        },
        _ => Preset {
            name: "default",
            primary: c("#000000"),
            on_primary: c("#ffffff"),
            secondary: c("#555f73"),
        },
    }
}
