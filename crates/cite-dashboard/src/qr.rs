use qrcode::QrCode;
use qrcode::render::{svg, unicode};

const SVG_MIN_SIZE: u32 = 220;

pub fn svg(data: &str) -> Result<String, String> {
    let code = QrCode::new(data.as_bytes()).map_err(|e| format!("cannot encode qr code: {e}"))?;
    let image = code
        .render::<svg::Color>()
        .min_dimensions(SVG_MIN_SIZE, SVG_MIN_SIZE)
        .quiet_zone(true)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    // The xml prolog is dropped so the markup can be parsed as an inline svg fragment.
    match image.find("<svg") {
        Some(start) => Ok(image[start..].to_string()),
        None => Ok(image),
    }
}

pub fn terminal(data: &str) -> Result<String, String> {
    let code = QrCode::new(data.as_bytes()).map_err(|e| format!("cannot encode qr code: {e}"))?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_output_is_an_svg_fragment() {
        let out = svg("otpauth://totp/Cite:admin?secret=ABC").expect("svg");
        assert!(out.starts_with("<svg"));
        assert!(out.contains("</svg>"));
        assert!(!out.contains("<?xml"));
    }

    #[test]
    fn terminal_output_has_block_characters() {
        let out = terminal("otpauth://totp/Cite:admin?secret=ABC").expect("terminal");
        assert!(out.lines().count() > 10);
        assert!(out.contains('\u{2588}') || out.contains('\u{2580}') || out.contains('\u{2584}'));
    }
}
