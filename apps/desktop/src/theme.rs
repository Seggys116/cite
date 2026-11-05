use gpui::{Rgba, rgb};

pub const BG: u32 = 0x0d1117;
pub const SURFACE: u32 = 0x161b22;
pub const SURFACE_HI: u32 = 0x1c232c;
pub const BORDER: u32 = 0x30363d;
pub const TEXT: u32 = 0xe6edf3;
pub const DIM: u32 = 0x8b949e;
pub const ACCENT: u32 = 0xce422b;
pub const YELLOW: u32 = 0xffd23f;
pub const BLUE: u32 = 0x3b82f6;
pub const GREEN: u32 = 0x22c55e;

#[cfg(target_os = "macos")]
pub const MONO: &str = "Menlo";
#[cfg(not(target_os = "macos"))]
pub const MONO: &str = "DejaVu Sans Mono";

pub fn c(hex: u32) -> Rgba {
    rgb(hex)
}

// Translucent tint of a palette colour for pill and notice backgrounds.
pub fn tint(hex: u32, alpha: f32) -> Rgba {
    let mut color = rgb(hex);
    color.a = alpha;
    color
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Ok,
    Bad,
    Warn,
    Info,
    Blue,
    Green,
    Muted,
}

impl Tone {
    pub fn color(self) -> u32 {
        match self {
            Self::Ok | Self::Green => GREEN,
            Self::Bad => ACCENT,
            Self::Warn => YELLOW,
            Self::Info | Self::Blue => BLUE,
            Self::Muted => DIM,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tones_map_to_palette_colours() {
        assert_eq!(Tone::Ok.color(), GREEN);
        assert_eq!(Tone::Bad.color(), ACCENT);
        assert_eq!(Tone::Blue.color(), BLUE);
    }

    #[test]
    fn tint_keeps_hue_and_sets_alpha() {
        let t = tint(ACCENT, 0.2);
        assert!((t.a - 0.2).abs() < f32::EPSILON);
        assert!((t.r - c(ACCENT).r).abs() < f32::EPSILON);
    }
}
