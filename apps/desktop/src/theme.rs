use gpui::{Rgba, rgb};

pub const BG: u32 = 0x0b0b0c;
pub const SIDEBAR: u32 = 0x0e0e10;
pub const TOPBAR: u32 = 0x1b1b1f;
// The window behind the inset panels; Term paints its chrome in the top bar colour.
pub const WINDOW: u32 = TOPBAR;
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
pub const PANEL_RADIUS: f32 = CARD_RADIUS;

// The one spacing scale: every gap and padding in the shared helpers comes from here.
pub mod space {
    pub const XXS: f32 = 2.0;
    pub const XS: f32 = 4.0;
    pub const SM: f32 = 8.0;
    pub const MD: f32 = 12.0;
    pub const LG: f32 = 16.0;
    pub const XL: f32 = 24.0;
    pub const XXL: f32 = 32.0;
}

pub mod font {
    pub const XS: f32 = 11.0;
    pub const SM: f32 = 12.0;
    pub const BASE: f32 = 13.0;
    pub const MD: f32 = 14.0;
    pub const LG: f32 = 16.0;
    pub const XL: f32 = 22.0;
}

// Shell geometry, matching Term's chrome metrics.
pub mod layout {
    pub const WINDOW_INSET: f32 = 8.0;
    pub const SIDEBAR_W: f32 = 240.0;
    pub const TOP_ROW_H: f32 = 36.0;
    pub const TRAFFIC_LIGHTS_W: f32 = 76.0;
    pub const CONTENT_MAX_W: f32 = 1100.0;
    pub const CONTROL_H: f32 = 28.0;
    pub const ROW_H: f32 = 32.0;
    pub const INPUT_MIN_W: f32 = 96.0;
    pub const FIELD_MIN_W: f32 = 96.0;
    pub const COLUMN_MIN_W: f32 = 260.0;
    pub const WINDOW_MIN_W: f32 = 720.0;
    pub const WINDOW_MIN_H: f32 = 480.0;
    pub const WINDOW_DEFAULT_W: f32 = 1280.0;
    pub const WINDOW_DEFAULT_H: f32 = 820.0;

    // Side padding of the page column: scales with the content width between 16 and 40.
    pub fn page_padding(content_width: f32) -> f32 {
        (content_width * 0.04).clamp(super::space::LG, 40.0)
    }
}

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
    fn page_padding_scales_between_its_bounds() {
        assert_eq!(layout::page_padding(200.0), space::LG);
        assert!((layout::page_padding(600.0) - 24.0).abs() < 0.01);
        assert_eq!(layout::page_padding(4000.0), 40.0);
    }

    #[test]
    fn tint_keeps_hue_and_sets_alpha() {
        let t = tint(ACCENT, 0.2);
        assert!((t.a - 0.2).abs() < f32::EPSILON);
        assert!((t.r - c(ACCENT).r).abs() < f32::EPSILON);
    }
}
