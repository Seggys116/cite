use gpui::{Rgba, rgb};

// The ink palette: neutral greys with one accent, depth from layered shadows and hairlines.
pub const BG: u32 = 0x0b0c0e;
pub const SIDEBAR: u32 = 0x0e0f12;
pub const TOPBAR: u32 = 0x101114;
// The window behind the inset panels; Term paints its chrome in the top bar colour.
pub const WINDOW: u32 = TOPBAR;
pub const INPUT: u32 = 0x131417;
pub const SURFACE: u32 = 0x141518;
pub const SURFACE_HI: u32 = 0x202126;
pub const BORDER: u32 = 0x2e2f36;
pub const DIVIDER: u32 = 0x1d1e22;
pub const TEXT: u32 = 0xf2f2f3;
pub const DIM: u32 = 0xaaabb2;
// The quietest text that still reads at 4.5:1 on SURFACE and SURFACE_HI.
pub const FAINT: u32 = 0x888991;
pub const ACCENT: u32 = 0xee6a52;
// Label colour on an ACCENT fill.
pub const ON_ACCENT: u32 = 0x0b0c0e;
pub const YELLOW: u32 = 0xe3b95c;
pub const BLUE: u32 = 0x7fb0ff;
pub const GREEN: u32 = 0x6fd08c;
pub const TOOL: u32 = 0xc678dd;
pub const RED: u32 = 0xff8a80;

// Metrics shared by the chrome: card radius and the row and pill corner radii.
pub const CARD_RADIUS: f32 = 18.0;
pub const ROW_RADIUS: f32 = 12.0;
pub const CHIP_RADIUS: f32 = 12.0;
// Pills and pill controls are fully rounded.
pub const PILL_RADIUS: f32 = 999.0;
// The panels sit WINDOW_INSET inside the window frame, so this stays equal to CARD_RADIUS.
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

    // WCAG relative luminance and contrast ratio.
    fn luminance(color: Rgba) -> f32 {
        let lin = |v: f32| {
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(color.r) + 0.7152 * lin(color.g) + 0.0722 * lin(color.b)
    }

    fn contrast(fg: Rgba, bg: Rgba) -> f32 {
        let (a, b) = (luminance(fg), luminance(bg));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    // Straight alpha blend in sRGB, which is how the renderer composites a tint.
    fn over(fg: Rgba, bg: Rgba) -> Rgba {
        let mix = |f: f32, b: f32| b + (f - b) * fg.a;
        Rgba {
            r: mix(fg.r, bg.r),
            g: mix(fg.g, bg.g),
            b: mix(fg.b, bg.b),
            a: 1.0,
        }
    }

    #[test]
    fn text_colours_reach_aa_on_every_surface_they_sit_on() {
        let surfaces = [BG, SIDEBAR, TOPBAR, INPUT, SURFACE, SURFACE_HI];
        for surface in surfaces {
            for text in [TEXT, DIM, FAINT] {
                let ratio = contrast(c(text), c(surface));
                assert!(
                    ratio >= 4.5,
                    "{text:06x} on {surface:06x} is only {ratio:.2}:1"
                );
            }
        }
    }

    #[test]
    fn labels_on_accent_and_tinted_pills_reach_aa() {
        assert!(contrast(c(ON_ACCENT), c(ACCENT)) >= 4.5);
        for hex in [GREEN, YELLOW, RED, BLUE, TOOL] {
            let bg = over(tint(hex, 0.12), c(SURFACE));
            let ratio = contrast(c(hex), bg);
            assert!(ratio >= 4.5, "{hex:06x} pill is only {ratio:.2}:1");
        }
    }

    #[test]
    fn pills_are_fully_rounded_and_the_panel_matches_the_card() {
        const { assert!(PILL_RADIUS >= 500.0) };
        assert_eq!(PANEL_RADIUS, CARD_RADIUS);
    }

    #[test]
    fn tint_keeps_hue_and_sets_alpha() {
        let t = tint(ACCENT, 0.2);
        assert!((t.a - 0.2).abs() < f32::EPSILON);
        assert!((t.r - c(ACCENT).r).abs() < f32::EPSILON);
    }
}
