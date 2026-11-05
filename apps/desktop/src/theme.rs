use gpui::{Rgba, rgb};

pub const BG: u32 = 0x0b0b0c;
pub const SIDEBAR: u32 = 0x0e0e10;
pub const TOPBAR: u32 = 0x1b1b1f;
pub const INPUT: u32 = 0x111113;
pub const SURFACE: u32 = 0x141418;
pub const SURFACE_HI: u32 = 0x1e1e23;
pub const BORDER: u32 = 0x2a2a2e;
pub const DIVIDER: u32 = 0x1c1c20;
pub const TEXT: u32 = 0xdcdcdc;
pub const DIM: u32 = 0x8a8a8c;
pub const ACCENT: u32 = 0xce422b;
pub const YELLOW: u32 = 0xd7ba7d;
pub const BLUE: u32 = 0x61afef;
pub const GREEN: u32 = 0x8cd973;
pub const TOOL: u32 = 0xc678dd;
pub const RED: u32 = 0xf26b78;

// Metrics shared by the chrome: card radius and the row and pill corner radii.
pub const CARD_RADIUS: f32 = 10.0;
pub const ROW_RADIUS: f32 = 8.0;
pub const CHIP_RADIUS: f32 = 7.0;

#[cfg(target_os = "macos")]
pub const MONO: &str = "Menlo";
#[cfg(not(target_os = "macos"))]
pub const MONO: &str = "DejaVu Sans Mono";

pub fn c(hex: u32) -> Rgba {
    rgb(hex)
}

// The selected-row and chip fill: white at 8 percent.
pub fn chip_fill() -> Rgba {
    tint(0xffffff, 0.08)
}

// The chip outline: white at 12 percent.
pub fn chip_stroke() -> Rgba {
    tint(0xffffff, 0.12)
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
            Self::Bad => RED,
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
        assert_eq!(Tone::Bad.color(), RED);
        assert_eq!(Tone::Blue.color(), BLUE);
    }

    #[test]
    fn selection_fill_is_white_at_eight_percent() {
        let fill = chip_fill();
        assert!((fill.a - 0.08).abs() < f32::EPSILON);
        assert!((fill.r - 1.0).abs() < f32::EPSILON);
        assert!((chip_stroke().a - 0.12).abs() < f32::EPSILON);
    }

    #[test]
    fn brand_red_is_not_a_status_colour() {
        for tone in [
            Tone::Ok,
            Tone::Bad,
            Tone::Warn,
            Tone::Info,
            Tone::Blue,
            Tone::Green,
            Tone::Muted,
        ] {
            assert_ne!(tone.color(), ACCENT);
        }
    }

    #[test]
    fn tint_keeps_hue_and_sets_alpha() {
        let t = tint(ACCENT, 0.2);
        assert!((t.a - 0.2).abs() < f32::EPSILON);
        assert!((t.r - c(ACCENT).r).abs() < f32::EPSILON);
    }
}
