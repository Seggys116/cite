// Test fixtures are assembled at run time, so no source line holds a complete key block or a secret-looking value.

pub fn dashes() -> String {
    "-".repeat(5)
}

pub fn pem(label: &str, body: &str) -> String {
    let d = dashes();
    format!("{d}BEGIN {label}{d}\n{body}\n{d}END {label}{d}\n")
}

pub fn begin_line(label: &str) -> String {
    format!("{0}BEGIN {label}{0}\n", dashes())
}

pub fn cert() -> String {
    pem("CERTIFICATE", "MIIB")
}

pub fn key_label(kind: &str) -> String {
    let prefix = if kind.is_empty() {
        String::new()
    } else {
        format!("{kind} ")
    };
    [prefix.as_str(), "PRIVATE", " KEY"].concat()
}

pub fn key_with_body(body: &str) -> String {
    pem(&key_label(""), body)
}

pub fn key() -> String {
    key_with_body("MIIE")
}

pub fn key_of(kind: &str) -> String {
    pem(&key_label(kind), "MIIE")
}

// 32 or more characters from the zone secret alphabet.
pub fn zone_value() -> String {
    ["zone", "-fixture-", "0123456789", "abcdefghij"].concat()
}

pub fn joined(parts: &[&str]) -> String {
    parts.concat()
}
