use std::net::IpAddr;

use crate::bot::{BotInputs, classify};
use crate::model::LogEvent;
use crate::validate::is_valid_id;

// Fixed-size fields come first and the capped, url_enc'd variable-size ones last, so a line that loses its tail keeps the verdict.
pub const LOG_FORMAT: &str = concat!(
    "%Ts%ms %ci %b %s %[method,bytes(0,16),url_enc] %ST %B %U %Tt %[var(txn.qlen)] ",
    "%[var(txn.blocked),url_enc] %[var(txn.site),url_enc] ",
    "%HV %[ssl_fc_protocol,bytes(0,16),url_enc] %Tr ",
    "%[var(txn.host),bytes(0,255),url_enc] %[var(txn.path),bytes(0,1024),url_enc] ",
    "%[var(txn.ua),bytes(0,512),url_enc] %[var(txn.ref),bytes(0,512),url_enc] ",
    "%[var(txn.ct),bytes(0,128),url_enc] ",
    "%[var(txn.accept),bytes(0,128),url_enc] %[var(txn.alang),bytes(0,64),url_enc] ",
    "%[var(txn.aenc),bytes(0,64),url_enc] %[var(txn.sfs),bytes(0,24),url_enc] ",
    "%[var(txn.sfm),bytes(0,24),url_enc] %[var(txn.sfd),bytes(0,24),url_enc] ",
    "%[var(txn.chua),bytes(0,128),url_enc]"
);

const FIELD_COUNT: usize = 27;
const HTTP_VERSION: usize = 12;
const TLS_VERSION: usize = 13;
const RESP_MS: usize = 14;
const FIRST_VARIABLE: usize = 15;
const MAX_DATAGRAM: usize = 8192;
const MAX_LINE: usize = 65536;
const MAX_FUTURE_MS: i64 = 300_000;
const MIN_FIELDS: usize = FIRST_VARIABLE;
const MAX_PATH: usize = 2048;
const MAX_UA: usize = 512;
const MAX_REFERER: usize = 1024;
const MAX_HOST: usize = 255;
const MAX_CTYPE: usize = 128;
const MAX_NAME: usize = 128;
const MAX_METHOD: usize = 16;
const MAX_RULE: usize = 64;
const MAX_VERSION: usize = 16;
const MAX_ACCEPT: usize = 128;
const MAX_LANG: usize = 64;
const MAX_ENCODING: usize = 64;
const MAX_FETCH: usize = 24;
const MAX_CH_UA: usize = 128;

pub fn parse_datagram(buf: &[u8], now_ms: i64) -> Option<LogEvent> {
    if buf.is_empty() || buf.len() > MAX_DATAGRAM {
        return None;
    }
    parse_line(&String::from_utf8_lossy(buf), now_ms)
}

pub fn parse_line(line: &str, now_ms: i64) -> Option<LogEvent> {
    if line.len() > MAX_LINE {
        return None;
    }
    let msg = message(line)?;
    let mut f = [""; FIELD_COUNT];
    let mut n = 0;
    for (slot, part) in f.iter_mut().zip(msg.split(' ')) {
        *slot = part;
        n += 1;
    }
    if n < MIN_FIELDS {
        return None;
    }
    // the previous 17-field format has the host here, which would shift every later field into the wrong column
    let http_version = f[HTTP_VERSION];
    if !(http_version.is_empty()
        || http_version.starts_with("HTTP/")
        || http_version.starts_with('<'))
    {
        return None;
    }
    let get = |i: usize| f.get(i).copied().unwrap_or("");
    // a short line was cut by the log target, so its last variable field may be partial and is dropped
    let cut = n < FIELD_COUNT || line.len() + 1 >= MAX_DATAGRAM;
    let tail = |i: usize| {
        if cut && i + 1 >= n { "" } else { get(i) }
    };
    let ts: i64 = get(0).parse().ok()?;
    // an unusable clock on the sender must not push events outside the retention window
    let ts_ms = if ts <= 0 || ts > now_ms.saturating_add(MAX_FUTURE_MS) {
        now_ms
    } else {
        ts
    };
    let client_ip = get(1);
    client_ip.parse::<IpAddr>().ok()?;
    let backend = sanitise(get(2), MAX_NAME);
    let status: i32 = get(5).parse().ok()?;
    let bytes_out: i64 = get(6).parse().ok()?;
    let bytes_in: i64 = get(7).parse().ok()?;
    let total: i64 = get(8).parse().ok()?;
    // HAProxy leaves the variable empty when no firewall rule matched
    let blocked = decode(get(10), MAX_RULE);
    let blocked = if blocked.is_empty() || blocked == "-" {
        None
    } else {
        Some(blocked)
    };
    // blocked requests and maintenance pages never reach a site backend, so the frontend names the site
    let mut site = site_of(&backend);
    if site.is_empty() {
        let named = decode(get(11), MAX_NAME);
        if is_valid_id(&named) {
            site = named;
        }
    }
    // HAProxy prints "-" for a sample that has no value
    let value = |raw: &str, max: usize| match decode(raw, max) {
        v if v == "-" => String::new(),
        v => v,
    };
    let mut event = LogEvent {
        ts_ms,
        client_ip: client_ip.to_string(),
        host: value(tail(FIRST_VARIABLE), MAX_HOST),
        method: decode(get(4), MAX_METHOD),
        path: decode(tail(FIRST_VARIABLE + 1), MAX_PATH),
        query_len: get(9)
            .parse::<u64>()
            .map_or(0, |v| v.min(u32::MAX as u64) as u32),
        status: status.clamp(0, 999) as u16,
        bytes_in: bytes_in.max(0) as u64,
        bytes_out: bytes_out.max(0) as u64,
        total_ms: total.clamp(0, u32::MAX as i64) as u32,
        user_agent: value(tail(FIRST_VARIABLE + 2), MAX_UA),
        referer: value(tail(FIRST_VARIABLE + 3), MAX_REFERER),
        content_type: value(tail(FIRST_VARIABLE + 4), MAX_CTYPE),
        site,
        backend,
        server: sanitise(get(3), MAX_NAME),
        blocked,
        http_version: value(http_version, MAX_VERSION),
        tls_version: value(get(TLS_VERSION), MAX_VERSION),
        resp_ms: get(RESP_MS)
            .parse::<i64>()
            .map_or(0, |v| v.clamp(0, u32::MAX as i64) as u32),
        accept: value(tail(FIRST_VARIABLE + 5), MAX_ACCEPT),
        accept_language: value(tail(FIRST_VARIABLE + 6), MAX_LANG),
        accept_encoding: value(tail(FIRST_VARIABLE + 7), MAX_ENCODING),
        sec_fetch_site: value(tail(FIRST_VARIABLE + 8), MAX_FETCH),
        sec_fetch_mode: value(tail(FIRST_VARIABLE + 9), MAX_FETCH),
        sec_fetch_dest: value(tail(FIRST_VARIABLE + 10), MAX_FETCH),
        sec_ch_ua: value(tail(FIRST_VARIABLE + 11), MAX_CH_UA),
        ..LogEvent::default()
    };
    // a cut line is missing request headers and stays unclassified, since scoring that absence would label real visitors as bots
    if !cut {
        score_bot(&mut event);
    }
    Some(event)
}

fn score_bot(ev: &mut LogEvent) {
    let verdict = classify(&BotInputs {
        user_agent: &ev.user_agent,
        accept: &ev.accept,
        accept_language: &ev.accept_language,
        accept_encoding: &ev.accept_encoding,
        sec_fetch_site: &ev.sec_fetch_site,
        sec_fetch_mode: &ev.sec_fetch_mode,
        sec_fetch_dest: &ev.sec_fetch_dest,
        sec_ch_ua: &ev.sec_ch_ua,
        http_version: &ev.http_version,
        referer: &ev.referer,
        method: &ev.method,
        tls_version: &ev.tls_version,
        path: &ev.path,
    });
    ev.bot_score = verdict.score;
    ev.bot_class = verdict.class.as_str().to_string();
    ev.bot_signals = verdict.signals.join(",");
}

fn site_of(backend: &str) -> String {
    backend
        .strip_prefix("be_")
        .and_then(|r| r.strip_suffix("_blue").or_else(|| r.strip_suffix("_green")))
        .unwrap_or("")
        .to_string()
}

// Returns the payload after the syslog header; accepts RFC 5424, RFC 3164 and a bare payload.
fn message(line: &str) -> Option<&str> {
    let line = line.trim_end_matches(['\n', '\r', '\0']);
    let mut rest = line;
    let mut had_pri = false;
    if let Some(r) = rest.strip_prefix('<')
        && let Some(end) = r.find('>')
    {
        let pri = &r[..end];
        if (1..=3).contains(&pri.len()) && pri.bytes().all(|b| b.is_ascii_digit()) {
            rest = &r[end + 1..];
            had_pri = true;
        }
    }
    let msg = if had_pri && is_rfc5424(rest) {
        rfc5424_payload(rest)?
    } else if is_bare_payload(rest) {
        rest
    } else {
        let idx = rest.find(": ")?;
        if idx > 256 {
            return None;
        }
        &rest[idx + 2..]
    };
    let msg = msg.trim_start_matches('\u{feff}');
    if msg.is_empty() { None } else { Some(msg) }
}

fn is_rfc5424(rest: &str) -> bool {
    match rest.split_once(' ') {
        Some((ver, _)) => (1..=2).contains(&ver.len()) && ver.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

fn rfc5424_payload(rest: &str) -> Option<&str> {
    let mut after = rest;
    // version, timestamp, hostname, app-name, procid, msgid
    for _ in 0..6 {
        after = after.split_once(' ')?.1;
    }
    if let Some(r) = after.strip_prefix('-') {
        return r.strip_prefix(' ');
    }
    if after.starts_with('[') {
        let end = after.find("] ")?;
        return Some(&after[end + 2..]);
    }
    None
}

fn is_bare_payload(rest: &str) -> bool {
    let first = rest.split(' ').next().unwrap_or("");
    first.len() >= 9 && first.bytes().all(|b| b.is_ascii_digit())
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode(s: &str, max: usize) -> String {
    if !s.bytes().any(|c| c == b'+' || c == b'%') {
        return sanitise(s, max);
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = b.get(i + 1).copied().and_then(hex);
                let lo = b.get(i + 2).copied().and_then(hex);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            _ => out.push(c),
        }
        i += 1;
    }
    match String::from_utf8(out) {
        Ok(owned) if owned.len() <= max && !owned.chars().any(char::is_control) => owned,
        Ok(owned) => sanitise(&owned, max),
        Err(e) => sanitise(&String::from_utf8_lossy(e.as_bytes()), max),
    }
}

fn sanitise(s: &str, max: usize) -> String {
    if s.len() <= max && !s.chars().any(char::is_control) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len().min(max));
    for c in s.chars() {
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(if c.is_control() { ' ' } else { c });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const NOW: i64 = 1_730_721_600_500;

    fn fields() -> Vec<String> {
        [
            "1730721600123",
            "203.0.113.9",
            "be_shop_blue",
            "app1",
            "GET",
            "200",
            "5120",
            "311",
            "12",
            "7",
            "",
            "shop",
            "HTTP/2.0",
            "TLSv1.3",
            "9",
            "shop.example.com",
            "/a%20b%2Fc",
            "Mozilla%2F5.0+%28X11%29",
            "https%3A%2F%2Fexample.org%2F",
            "text%2Fhtml%3B+charset%3Dutf-8",
            "text%2Fhtml%2Capplication%2Fxhtml%2Bxml",
            "en-US%2Cen%3Bq%3D0.9",
            "gzip%2C+deflate%2C+br",
            "none",
            "navigate",
            "document",
            "%22Chromium%22%3Bv%3D%22124%22",
        ]
        .map(String::from)
        .to_vec()
    }

    fn enc(s: &str) -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    const CHROME_CH: &str =
        "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"";

    fn chrome_fields() -> Vec<String> {
        let mut f = fields();
        f[FIRST_VARIABLE + 2] = enc(CHROME_UA);
        f[FIRST_VARIABLE + 5] = enc("text/html,application/xhtml+xml,*/*;q=0.8");
        f[FIRST_VARIABLE + 11] = enc(CHROME_CH);
        f
    }

    fn body() -> String {
        fields().join(" ")
    }

    #[test]
    fn parses_rfc3164_line() {
        let line = format!("<134>Nov  4 12:00:00 edge haproxy[812]: {}", body());
        let ev = parse_line(&line, NOW).expect("parsed");
        assert_eq!(ev.ts_ms, 1_730_721_600_123);
        assert_eq!(ev.client_ip, "203.0.113.9");
        assert_eq!(ev.backend, "be_shop_blue");
        assert_eq!(ev.server, "app1");
        assert_eq!(ev.site, "shop");
        assert_eq!(ev.host, "shop.example.com");
        assert_eq!(ev.method, "GET");
        assert_eq!(ev.path, "/a b/c");
        assert_eq!(ev.query_len, 7);
        assert_eq!(ev.status, 200);
        assert_eq!(ev.bytes_out, 5120);
        assert_eq!(ev.bytes_in, 311);
        assert_eq!(ev.total_ms, 12);
        assert_eq!(ev.user_agent, "Mozilla/5.0 (X11)");
        assert_eq!(ev.referer, "https://example.org/");
        assert_eq!(ev.content_type, "text/html; charset=utf-8");
        assert_eq!(ev.blocked, None);
    }

    #[test]
    fn parses_rfc5424_line() {
        let line = format!(
            "<134>1 2026-11-04T12:00:00.123Z edge haproxy 812 - - {}",
            body()
        );
        let ev = parse_line(&line, NOW).expect("parsed");
        assert_eq!(ev.path, "/a b/c");
        assert_eq!(ev.status, 200);
        let head = "<134>1 2026-11-04T12:00:00Z edge haproxy 812 - [a@1 k=\"v\"]";
        let sd = format!("{head} {}", body());
        assert_eq!(parse_line(&sd, NOW).expect("parsed").status, 200);
    }

    #[test]
    fn parses_headerless_line() {
        let ev = parse_line(&body(), NOW).expect("parsed");
        assert_eq!(ev.client_ip, "203.0.113.9");
        let tagged = format!("haproxy[1]: {}", body());
        assert_eq!(parse_line(&tagged, NOW).expect("parsed").method, "GET");
    }

    #[test]
    fn parses_ipv6_and_trailing_newline() {
        let line = format!("{}\n", body().replace("203.0.113.9", "2001:db8::1"));
        let ev = parse_line(&line, NOW).expect("parsed");
        assert_eq!(ev.client_ip, "2001:db8::1");
    }

    #[test]
    fn rejects_garbage() {
        for line in [
            "",
            "hello world",
            "<134>",
            "<134>Nov 4 x: y",
            ": : :",
            "\0\0\0",
        ] {
            assert!(parse_line(line, NOW).is_none(), "accepted {line:?}");
        }
    }

    #[test]
    fn rejects_truncated_line() {
        let full = format!("<134>Nov  4 12:00:00 edge haproxy[812]: {}", body());
        let payload = full.split_once(": ").map(|p| p.1).unwrap_or("");
        let cut = payload
            .split(' ')
            .take(MIN_FIELDS - 1)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(parse_line(&cut, NOW).is_none());
    }

    #[test]
    fn rejects_bad_numbers_and_ip() {
        assert!(parse_line(&body().replace("203.0.113.9", "not-an-ip"), NOW).is_none());
        assert!(parse_line(&body().replace(" 200 ", " abc "), NOW).is_none());
        assert!(parse_line(&body().replace("1730721600123", "xyz"), NOW).is_none());
    }

    #[test]
    fn tolerates_trimmed_trailing_fields() {
        let short = "1730721600123 203.0.113.9 be_shop_green app1 GET 404 10 20 3 0  shop HTTP/1.1 - 5 h /x";
        let ev = parse_line(short, NOW).expect("parsed");
        assert_eq!(ev.status, 404);
        assert_eq!(ev.site, "shop");
        assert_eq!(ev.host, "h");
        assert_eq!(ev.path, "");
        assert_eq!(ev.user_agent, "");
        assert_eq!(ev.blocked, None);
        assert_eq!(ev.http_version, "HTTP/1.1");
        assert_eq!(ev.resp_ms, 5);
    }

    #[test]
    fn line_cut_in_the_variable_tail_keeps_the_blocked_verdict() {
        let mut f = fields();
        f[2] = "fe_main".into();
        f[10] = "preset-scanners-1".into();
        for keep in FIRST_VARIABLE..FIELD_COUNT {
            let line = f[..keep].join(" ");
            let ev = parse_line(&line, NOW).expect("kept");
            assert_eq!(ev.blocked.as_deref(), Some("preset-scanners-1"), "{keep}");
            assert_eq!(ev.site, "shop");
            assert_eq!(ev.status, 200);
        }
        let ev = parse_line(&f[..FIRST_VARIABLE + 2].join(" "), NOW).expect("kept");
        assert_eq!(ev.host, "shop.example.com");
        assert_eq!(ev.path, "");
    }

    #[test]
    fn a_dash_user_agent_is_empty_and_scored_as_missing() {
        let mut f = fields();
        f[FIRST_VARIABLE + 2] = "-".into();
        f[FIRST_VARIABLE + 3] = "-".into();
        let ev = parse_line(&f.join(" "), NOW).expect("parsed");
        assert_eq!((ev.user_agent.as_str(), ev.referer.as_str()), ("", ""));
        assert!(
            ev.bot_signals.split(',').any(|s| s == "empty_ua"),
            "{}",
            ev.bot_signals
        );
    }

    #[test]
    fn a_line_at_the_datagram_limit_stays_unclassified() {
        let mut f = fields();
        f[FIRST_VARIABLE + 1] = "a".repeat(8200);
        let ev = parse_line(&f.join(" "), NOW).expect("parsed");
        assert_eq!((ev.bot_score, ev.bot_class.as_str()), (0, ""));
    }

    #[test]
    fn cut_lines_are_not_scored_as_bots() {
        let cut = chrome_fields()[..FIRST_VARIABLE + 4].join(" ");
        let ev = parse_line(&cut, NOW).expect("kept");
        assert_eq!(ev.user_agent, CHROME_UA);
        assert_eq!((ev.bot_score, ev.bot_class.as_str()), (0, ""));
        assert_eq!(ev.bot_signals, "");
        assert_eq!(ev.accept, "");
    }

    #[test]
    fn full_line_fills_every_new_field() {
        let ev = parse_line(&body(), NOW).expect("parsed");
        assert_eq!(ev.http_version, "HTTP/2.0");
        assert_eq!(ev.tls_version, "TLSv1.3");
        assert_eq!(ev.resp_ms, 9);
        assert_eq!(ev.accept, "text/html,application/xhtml+xml");
        assert_eq!(ev.accept_language, "en-US,en;q=0.9");
        assert_eq!(ev.accept_encoding, "gzip, deflate, br");
        assert_eq!(ev.sec_fetch_site, "none");
        assert_eq!(ev.sec_fetch_mode, "navigate");
        assert_eq!(ev.sec_fetch_dest, "document");
        assert_eq!(ev.sec_ch_ua, "\"Chromium\";v=\"124\"");
        assert_eq!(ev.host, "shop.example.com");
        assert_eq!(ev.content_type, "text/html; charset=utf-8");
    }

    #[test]
    fn real_chrome_line_scores_human_and_curl_scores_tool() {
        let line = format!(
            "<134>Nov  4 12:00:00 edge haproxy[812]: {}",
            chrome_fields().join(" ")
        );
        let ev = parse_line(&line, NOW).expect("parsed");
        assert_eq!(ev.user_agent, CHROME_UA);
        assert_eq!(ev.sec_ch_ua, CHROME_CH);
        assert_eq!(ev.bot_score, 0, "{}", ev.bot_signals);
        assert_eq!(ev.bot_class, "human");
        assert_eq!(ev.bot_signals, "");

        let mut f = fields();
        f[HTTP_VERSION] = "HTTP/1.1".into();
        f[TLS_VERSION] = String::new();
        f[FIRST_VARIABLE + 2] = enc("curl/8.5.0");
        f[FIRST_VARIABLE + 3] = String::new();
        f[FIRST_VARIABLE + 5] = enc("*/*");
        for v in &mut f[FIRST_VARIABLE + 6..] {
            v.clear();
        }
        let ev = parse_line(&f.join(" "), NOW).expect("parsed");
        assert_eq!(ev.tls_version, "");
        assert_eq!(ev.bot_class, "tool");
        assert!(ev.bot_score >= 70);
        assert!(ev.bot_signals.ends_with("ua_curl"), "{}", ev.bot_signals);
        assert!(ev.bot_signals.starts_with("missing_accept_language"));
    }

    #[test]
    fn dash_samples_become_empty() {
        let mut f = fields();
        f[TLS_VERSION] = "-".into();
        f[FIRST_VARIABLE + 5] = "-".into();
        let ev = parse_line(&f.join(" "), NOW).expect("parsed");
        assert_eq!((ev.tls_version.as_str(), ev.accept.as_str()), ("", ""));
    }

    #[test]
    fn old_format_lines_are_rejected() {
        let mut f = fields();
        f.drain(HTTP_VERSION..FIRST_VARIABLE);
        f.truncate(17);
        assert_eq!(f.len(), 17);
        assert!(parse_line(&f.join(" "), NOW).is_none());
        assert!(parse_line(&f[..13].join(" "), NOW).is_none());
    }

    #[test]
    fn hostile_headers_cannot_add_fields_or_control_characters() {
        let hostile = [
            "a b\r\n\0 injected 200 5120 311 12".to_string(),
            "\u{202e}\u{feff}\u{e9}\u{1F600}\x1b[31m".to_string(),
            "%00%0d%0a %zz %".to_string(),
            "x".repeat(5_000),
        ];
        let base = parse_line(&body(), NOW).expect("parsed");
        for h in hostile {
            let mut f = fields();
            for v in &mut f[FIRST_VARIABLE + 5..] {
                *v = enc(&h);
            }
            let line = f.join(" ");
            assert_eq!(line.split(' ').count(), FIELD_COUNT);
            let ev = parse_line(&line, NOW).expect("parsed");
            assert_eq!(ev.status, base.status);
            assert_eq!(ev.host, base.host);
            assert_eq!(ev.path, base.path);
            assert_eq!(ev.user_agent, base.user_agent);
            assert_eq!(ev.resp_ms, base.resp_ms);
            for v in [
                &ev.accept,
                &ev.accept_language,
                &ev.accept_encoding,
                &ev.sec_fetch_site,
                &ev.sec_fetch_mode,
                &ev.sec_fetch_dest,
                &ev.sec_ch_ua,
            ] {
                assert!(!v.chars().any(char::is_control), "{v:?}");
            }
            assert!(ev.accept.len() <= MAX_ACCEPT);
            assert!(ev.accept_language.len() <= MAX_LANG);
            assert!(ev.sec_fetch_mode.len() <= MAX_FETCH);
            assert!(ev.sec_ch_ua.len() <= MAX_CH_UA);
            assert!(ev.bot_score <= 100);
        }
    }

    #[test]
    fn site_label_is_used_when_the_backend_has_none() {
        let mut f = fields();
        f[2] = "fe_main".into();
        assert_eq!(parse_line(&f.join(" "), NOW).expect("parsed").site, "shop");
        f[11] = "Bad!Site".into();
        assert_eq!(parse_line(&f.join(" "), NOW).expect("parsed").site, "");
        f[11] = String::new();
        assert_eq!(parse_line(&f.join(" "), NOW).expect("parsed").site, "");
        let mut g = fields();
        g[11] = "other".into();
        assert_eq!(parse_line(&g.join(" "), NOW).expect("parsed").site, "shop");
    }

    #[test]
    fn sanitises_control_characters() {
        let b = body().replace("Mozilla%2F5.0+%28X11%29", "a%00b%0Ac%1Bd%7F");
        let ev = parse_line(&b, NOW).expect("parsed");
        assert_eq!(ev.user_agent, "a b c d ");
        assert!(!ev.user_agent.chars().any(|c| c.is_control()));
    }

    #[test]
    fn invalid_utf8_and_bad_escapes_do_not_fail() {
        let b = body().replace("/a%20b%2Fc", "/%FF%fe%zz%4");
        let ev = parse_line(&b, NOW).expect("parsed");
        assert!(ev.path.starts_with('/'));
        assert!(ev.path.ends_with("%zz%4"));
    }

    #[test]
    fn truncates_long_fields() {
        let long = "a".repeat(5000);
        let b = body()
            .replace("/a%20b%2Fc", &format!("/{long}"))
            .replace("Mozilla%2F5.0+%28X11%29", &long)
            .replace("https%3A%2F%2Fexample.org%2F", &long);
        let ev = parse_line(&b, NOW).expect("parsed");
        assert_eq!(ev.path.len(), 2048);
        assert_eq!(ev.user_agent.len(), 512);
        assert_eq!(ev.referer.len(), 1024);
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let enc = "%C3%A9".repeat(2000);
        let ev = parse_line(&body().replace("/a%20b%2Fc", &enc), NOW).expect("parsed");
        assert_eq!(ev.path.len(), 2048);
        assert!(ev.path.chars().all(|c| c == '\u{e9}'));
    }

    #[test]
    fn blocked_rule_is_extracted_and_dash_is_none() {
        let mut f = fields();
        f[10] = "fw_deny_bots".into();
        let ev = parse_line(&f.join(" "), NOW).expect("parsed");
        assert_eq!(ev.blocked.as_deref(), Some("fw_deny_bots"));
        assert_eq!(ev.path, "/a b/c");
        f[10] = "-".into();
        assert_eq!(parse_line(&f.join(" "), NOW).expect("parsed").blocked, None);
    }

    #[test]
    fn site_is_derived_from_backend_name() {
        let ev = parse_line(&body().replace("be_shop_blue", "be_my_site_green"), NOW);
        assert_eq!(ev.expect("parsed").site, "my_site");
        let bare = body().replace(" shop ", "  ");
        let ev = parse_line(&bare.replace("be_shop_blue", "be_maintenance"), NOW);
        assert_eq!(ev.expect("parsed").site, "");
        let ev = parse_line(&bare.replace("be_shop_blue", "other"), NOW);
        assert_eq!(ev.expect("parsed").site, "");
    }

    #[test]
    fn timestamps_outside_sane_range_fall_back_to_now() {
        let future = body().replace("1730721600123", "9999999999999");
        assert_eq!(parse_line(&future, NOW).expect("parsed").ts_ms, NOW);
        let zero = body().replace("1730721600123", "0000000000000");
        assert_eq!(parse_line(&zero, NOW).expect("parsed").ts_ms, NOW);
    }

    #[test]
    fn negative_values_are_clamped() {
        let b = body().replace(" 200 5120 311 12 ", " -1 -1 -1 -1 ");
        let ev = parse_line(&b, NOW).expect("parsed");
        assert_eq!(
            (ev.status, ev.bytes_out, ev.bytes_in, ev.total_ms),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn datagram_wrapper_limits_size_and_decodes_lossy() {
        let line = format!("<134>Nov  4 12:00:00 edge haproxy[812]: {}", body());
        assert!(parse_datagram(line.as_bytes(), NOW).is_some());
        assert!(parse_datagram(&[], NOW).is_none());
        assert!(parse_datagram(&vec![b'a'; 8193], NOW).is_none());
        let mut bytes = line.into_bytes();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        assert!(parse_datagram(&bytes, NOW).is_some());
    }

    #[test]
    fn log_format_is_single_line_without_quotes() {
        assert!(!LOG_FORMAT.contains('\n'));
        assert!(!LOG_FORMAT.contains('"'));
        assert_eq!(LOG_FORMAT.split(' ').count(), FIELD_COUNT);
        let fixed: Vec<&str> = LOG_FORMAT.split(' ').take(FIRST_VARIABLE).collect();
        assert!(
            fixed
                .iter()
                .all(|f| !f.contains("txn.path") && !f.contains("txn.ua"))
        );
        let tail: Vec<&str> = LOG_FORMAT.split(' ').skip(FIRST_VARIABLE).collect();
        assert!(tail.iter().all(|f| f.contains("bytes(0,")), "{tail:?}");
        let at = |i: usize| LOG_FORMAT.split(' ').nth(i).unwrap_or("");
        assert_eq!(at(HTTP_VERSION), "%HV");
        assert!(at(TLS_VERSION).contains("ssl_fc_protocol"));
        assert_eq!(at(RESP_MS), "%Tr");
        let order = ["host", "path", "ua", "ref", "ct", "accept", "alang"];
        let rest = ["aenc", "sfs", "sfm", "sfd", "chua"];
        for (k, name) in order.iter().chain(rest.iter()).enumerate() {
            assert!(
                at(FIRST_VARIABLE + k).contains(&format!("var(txn.{name})")),
                "{name}"
            );
        }
    }

    proptest! {
        #[test]
        fn datagram_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..3000)) {
            let _ = parse_datagram(&bytes, NOW);
        }

        #[test]
        fn line_never_panics(line in ".*") {
            let _ = parse_line(&line, NOW);
        }

        #[test]
        fn mangled_valid_line_never_panics(cut in 0usize..200, ch in any::<char>()) {
            let mut s = format!("<134>Nov  4 12:00:00 edge haproxy[812]: {}", body());
            let at = cut.min(s.len());
            if s.is_char_boundary(at) {
                s.insert(at, ch);
            }
            let _ = parse_line(&s, NOW);
        }
    }
}
