use serde::{Deserialize, Serialize};

use crate::analytics::TopItem;

// Scores run 0 (human) to 100 (bot); weights add up and the sum is clamped, so one strong signal never needs a second to matter.
pub const SUSPECT_THRESHOLD: u8 = 40;
pub const BOT_THRESHOLD: u8 = 70;
const MAX_SCORE: u32 = 100;
// Major versions from which a browser over TLS is expected to send Sec-Fetch-* (and Sec-CH-UA for Chromium).
const MODERN_CHROMIUM: u32 = 90;
const MODERN_FIREFOX: u32 = 90;
const MODERN_SAFARI: u32 = 17;
const W_EMPTY_UA: u32 = 40;
const W_NO_LANG_BROWSER: u32 = 40;
const W_NO_LANG: u32 = 10;
const W_NO_ACCEPT_BROWSER: u32 = 35;
const W_NO_ACCEPT: u32 = 15;
const W_WILDCARD_BROWSER: u32 = 30;
const W_WILDCARD: u32 = 8;
const W_NO_ENCODING_BROWSER: u32 = 30;
const W_NO_ENCODING: u32 = 10;
const W_NO_SEC_FETCH: u32 = 30;
const W_SEC_FETCH_PARTIAL: u32 = 20;
const W_SEC_FETCH_INCONSISTENT: u32 = 30;
const W_NO_SEC_CH_UA: u32 = 30;
const W_CH_UA_MISMATCH: u32 = 40;
const W_HTTP_1_0: u32 = 20;
const W_HTTP1_MODERN: u32 = 25;
const W_OLD_TLS: u32 = 10;
const W_POST_NO_REFERER_BROWSER: u32 = 20;
const W_POST_NO_REFERER: u32 = 10;
const W_UA_CRAWLER: u32 = 70;
const W_UA_TOOL: u32 = 70;
const W_UA_AUTOMATION: u32 = 85;
const W_UA_GENERIC: u32 = 60;

const MAX_FIELD: usize = 1024;
const MAX_PATH: usize = 2048;
const MAX_TOKEN: usize = 24;

pub const SCORE_BUCKETS: [&str; 5] = ["0-19", "20-39", "40-59", "60-79", "80-100"];

const CRAWLER_TOKENS: &[(&str, &str)] = &[
    ("googlebot", "ua_googlebot"),
    ("adsbot-google", "ua_adsbot_google"),
    ("google-inspectiontool", "ua_google_inspection"),
    ("bingbot", "ua_bingbot"),
    ("bingpreview", "ua_bingpreview"),
    ("duckduckbot", "ua_duckduckbot"),
    ("baiduspider", "ua_baiduspider"),
    ("yandexbot", "ua_yandexbot"),
    ("applebot", "ua_applebot"),
    ("facebookexternalhit", "ua_facebookexternalhit"),
    ("slackbot", "ua_slackbot"),
    ("twitterbot", "ua_twitterbot"),
    ("linkedinbot", "ua_linkedinbot"),
    ("discordbot", "ua_discordbot"),
    ("telegrambot", "ua_telegrambot"),
    ("pinterest", "ua_pinterest"),
    ("ahrefsbot", "ua_ahrefsbot"),
    ("semrushbot", "ua_semrushbot"),
    ("mj12bot", "ua_mj12bot"),
    ("dotbot", "ua_dotbot"),
    ("petalbot", "ua_petalbot"),
    ("bytespider", "ua_bytespider"),
    ("gptbot", "ua_gptbot"),
    ("claudebot", "ua_claudebot"),
    ("ccbot", "ua_ccbot"),
    ("amazonbot", "ua_amazonbot"),
    ("sogou", "ua_sogou"),
    ("exabot", "ua_exabot"),
    ("seznambot", "ua_seznambot"),
    ("uptimerobot", "ua_uptimerobot"),
    ("ia_archiver", "ua_ia_archiver"),
    ("archive.org_bot", "ua_archive_org"),
];

const AUTOMATION_TOKENS: &[(&str, &str)] = &[
    ("headlesschrome", "ua_headlesschrome"),
    ("phantomjs", "ua_phantomjs"),
    ("selenium", "ua_selenium"),
    ("puppeteer", "ua_puppeteer"),
    ("playwright", "ua_playwright"),
];

const TOOL_TOKENS: &[(&str, &str)] = &[
    ("curl/", "ua_curl"),
    ("wget", "ua_wget"),
    ("python-requests", "ua_python_requests"),
    ("python-urllib", "ua_python_urllib"),
    ("python-httpx", "ua_httpx"),
    ("httpx", "ua_httpx"),
    ("aiohttp", "ua_aiohttp"),
    ("go-http-client", "ua_go_http_client"),
    ("okhttp", "ua_okhttp"),
    ("java/", "ua_java"),
    ("apache-httpclient", "ua_apache_httpclient"),
    ("libwww-perl", "ua_libwww_perl"),
    ("node-fetch", "ua_node_fetch"),
    ("undici", "ua_undici"),
    ("axios", "ua_axios"),
    ("scrapy", "ua_scrapy"),
    ("guzzlehttp", "ua_guzzle"),
    ("postmanruntime", "ua_postman"),
    ("httpie", "ua_httpie"),
    ("mechanize", "ua_mechanize"),
    // Last so the specific python-* names above win; the first match in list order is reported.
    ("python", "ua_python"),
];

const GENERIC_CRAWLER_TOKENS: &[(&str, &str)] = &[
    ("bot/", "ua_generic_bot"),
    ("+http", "ua_generic_bot"),
    ("spider", "ua_generic_spider"),
    ("crawl", "ua_generic_crawler"),
];

const GENERIC_SCRAPER_TOKENS: &[(&str, &str)] = &[("scrape", "ua_generic_scraper")];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BotClass {
    #[default]
    Human,
    Suspect,
    Crawler,
    Tool,
    Bot,
}

impl BotClass {
    pub fn as_str(self) -> &'static str {
        match self {
            BotClass::Human => "human",
            BotClass::Suspect => "suspect",
            BotClass::Crawler => "crawler",
            BotClass::Tool => "tool",
            BotClass::Bot => "bot",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BotInputs<'a> {
    pub user_agent: &'a str,
    pub accept: &'a str,
    pub accept_language: &'a str,
    pub accept_encoding: &'a str,
    pub sec_fetch_site: &'a str,
    pub sec_fetch_mode: &'a str,
    pub sec_fetch_dest: &'a str,
    pub sec_ch_ua: &'a str,
    pub http_version: &'a str,
    pub referer: &'a str,
    pub method: &'a str,
    pub tls_version: &'a str,
    pub path: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BotVerdict {
    pub score: u8,
    pub class: BotClass,
    pub signals: Vec<&'static str>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BotSummary {
    pub total_requests: u64,
    pub bot_requests: u64,
    pub bot_share_pct: f64,
    pub classes: Vec<TopItem>,
    pub signals: Vec<TopItem>,
    pub agents: Vec<TopItem>,
    pub score_buckets: Vec<TopItem>,
}

pub fn score_bucket(score: u8) -> &'static str {
    SCORE_BUCKETS[usize::from(score.min(100) / 20).min(SCORE_BUCKETS.len() - 1)]
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Engine {
    NotBrowser,
    Other,
    Chromium(u32),
    Firefox(u32),
    Safari(u32),
}

struct Tally {
    score: u32,
    signals: Vec<&'static str>,
}

impl Tally {
    fn add(&mut self, name: &'static str, weight: u32) {
        self.score += weight;
        self.signals.push(name);
    }
}

// Header values are client-controlled, so every scan runs on a bounded prefix.
fn cap(s: &str, max: usize) -> &[u8] {
    let b = s.as_bytes();
    b.get(..max).unwrap_or(b)
}

fn find_ci(hay: &[u8], needle: &str) -> Option<usize> {
    let n = needle.as_bytes();
    if n.is_empty() || hay.len() < n.len() {
        return None;
    }
    hay.windows(n.len()).position(|w| w.eq_ignore_ascii_case(n))
}

fn contains_ci(hay: &[u8], needle: &str) -> bool {
    find_ci(hay, needle).is_some()
}

fn starts_with_ci(hay: &[u8], prefix: &str) -> bool {
    hay.get(..prefix.len())
        .is_some_and(|h| h.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn one_of(v: &[u8], set: &[&str]) -> bool {
    set.iter().any(|s| v.eq_ignore_ascii_case(s.as_bytes()))
}

fn version_after(hay: &[u8], needle: &str) -> Option<u32> {
    let at = find_ci(hay, needle)? + needle.len();
    let mut v: u32 = 0;
    let mut seen = false;
    // At most 5 digits, so a hostile version string cannot overflow u32.
    for &c in hay.get(at..)?.iter().take(5) {
        if !c.is_ascii_digit() {
            break;
        }
        v = v * 10 + u32::from(c - b'0');
        seen = true;
    }
    seen.then_some(v)
}

fn engine_of(ua: &[u8]) -> Engine {
    let spoofed_compat = contains_ci(ua, "compatible;") && !contains_ci(ua, "msie");
    // Only Mozilla-prefixed UAs can be browsers; "compatible;" without MSIE is how many bots imitate one.
    if !starts_with_ci(ua, "mozilla/") || spoofed_compat {
        return Engine::NotBrowser;
    }
    // iOS wrappers are WebKit under a Chrome or Firefox name and send neither Sec-CH-UA nor the desktop header set
    if ["crios/", "fxios/", "edgios/", "opios/"]
        .iter()
        .any(|t| contains_ci(ua, t))
    {
        return Engine::Other;
    }
    if let Some(v) = version_after(ua, "chrome/") {
        return Engine::Chromium(v);
    }
    if let Some(v) = version_after(ua, "firefox/") {
        return Engine::Firefox(v);
    }
    if contains_ci(ua, "safari/")
        && let Some(v) = version_after(ua, "version/")
    {
        return Engine::Safari(v);
    }
    Engine::Other
}

fn is_document(method: &[u8], dest: &[u8], path: &[u8]) -> bool {
    if !dest.is_empty() {
        return one_of(dest, &["document", "iframe", "frame"]);
    }
    // Without Sec-Fetch-Dest, guess a page load from the method and a missing or page-like file extension.
    if !one_of(method, &["GET", "HEAD"]) {
        return false;
    }
    let path = path.split(|&c| c == b'?').next().unwrap_or(&[]);
    let seg = path.rsplit(|&c| c == b'/').next().unwrap_or(&[]);
    match seg.iter().rposition(|&c| c == b'.') {
        None => true,
        Some(p) => seg
            .get(p + 1..)
            .is_some_and(|ext| one_of(ext, &["html", "htm", "php", "asp", "aspx", "jsp"])),
    }
}

fn is_wildcard_only(accept: &[u8]) -> bool {
    let main = accept.split(|&c| c == b';').next().unwrap_or(&[]);
    main.trim_ascii().eq_ignore_ascii_case(b"*/*")
}

fn plain_token(v: &[u8]) -> bool {
    v.len() <= MAX_TOKEN && v.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-')
}

fn fetch_inconsistent(site: &[u8], mode: &[u8], dest: &[u8], method: &[u8]) -> bool {
    let sites = ["same-origin", "same-site", "cross-site", "none"];
    let modes = [
        "navigate",
        "nested-navigate",
        "same-origin",
        "no-cors",
        "cors",
        "websocket",
    ];
    if (!site.is_empty() && !one_of(site, &sites))
        || (!mode.is_empty() && !one_of(mode, &modes))
        || (!dest.is_empty() && !plain_token(dest))
    {
        return true;
    }
    let navigate = one_of(mode, &["navigate", "nested-navigate"]);
    if one_of(mode, &["navigate"]) {
        let nav_dests = [
            "document",
            "iframe",
            "frame",
            "embed",
            "object",
            "fencedframe",
        ];
        if !dest.is_empty() && !one_of(dest, &nav_dests) {
            return true;
        }
        if !method.is_empty() && !one_of(method, &["GET", "POST", "HEAD"]) {
            return true;
        }
    }
    if !mode.is_empty() && !navigate && one_of(dest, &["document", "iframe", "frame"]) {
        return true;
    }
    // "none" marks a user-initiated navigation; extensions legitimately use it with cors
    !mode.is_empty() && !navigate && one_of(site, &["none"]) && !one_of(mode, &["cors"])
}

fn ch_contradicts(engine: Engine, ua: &[u8], ch: &[u8]) -> bool {
    match engine {
        Engine::Firefox(_) | Engine::Safari(_) => true,
        Engine::Chromium(major) => {
            if !contains_ci(ch, "chromium") {
                return true;
            }
            let edge_ua = contains_ci(ua, "edg/") || contains_ci(ua, "edga/");
            if edge_ua && !contains_ci(ch, "edge") {
                return true;
            }
            version_after(ch, "chromium\";v=\"").is_some_and(|v| v != major)
        }
        Engine::Other | Engine::NotBrowser => false,
    }
}

fn http_major(ver: &[u8]) -> Option<u8> {
    let rest = if starts_with_ci(ver, "http/") {
        ver.get(5..)?
    } else {
        ver
    };
    rest.first()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c - b'0')
}

type TokenGroup = (&'static [(&'static str, &'static str)], BotClass, u32);

fn ua_match(ua: &[u8]) -> Option<(&'static str, BotClass, u32)> {
    let groups: [TokenGroup; 5] = [
        (CRAWLER_TOKENS, BotClass::Crawler, W_UA_CRAWLER),
        (AUTOMATION_TOKENS, BotClass::Bot, W_UA_AUTOMATION),
        (TOOL_TOKENS, BotClass::Tool, W_UA_TOOL),
        (GENERIC_CRAWLER_TOKENS, BotClass::Crawler, W_UA_GENERIC),
        (GENERIC_SCRAPER_TOKENS, BotClass::Bot, W_UA_GENERIC),
    ];
    // Group order matters: the first group with a match wins, so named crawlers and automation outrank generic tokens.
    for (list, class, weight) in groups {
        if let Some((_, signal)) = list.iter().find(|(needle, _)| contains_ci(ua, needle)) {
            return Some((*signal, class, weight));
        }
    }
    None
}

// Header signals are scored first and carry the most weight; the User-Agent only adds a named signal and may pin the class afterwards.
pub fn classify(i: &BotInputs<'_>) -> BotVerdict {
    let ua = cap(i.user_agent, MAX_FIELD);
    let accept = cap(i.accept, MAX_FIELD);
    let lang = cap(i.accept_language, MAX_FIELD);
    let enc = cap(i.accept_encoding, MAX_FIELD);
    let site = cap(i.sec_fetch_site, MAX_FIELD);
    let mode = cap(i.sec_fetch_mode, MAX_FIELD);
    let dest = cap(i.sec_fetch_dest, MAX_FIELD);
    let ch = cap(i.sec_ch_ua, MAX_FIELD);
    let ver = cap(i.http_version, MAX_FIELD);
    let method = cap(i.method, MAX_FIELD);
    let tls = cap(i.tls_version, MAX_FIELD);
    let path = cap(i.path, MAX_PATH);

    let engine = engine_of(ua);
    let browser = engine != Engine::NotBrowser;
    // Non-browser clients are not expected to send browser headers, so a gap weighs less than in a browser UA.
    let weight = |browser_w: u32, other_w: u32| if browser { browser_w } else { other_w };
    // Sec-Fetch-* and Sec-CH-UA are only sent to secure origins, so over plain HTTP their absence proves nothing.
    let secure = !tls.is_empty();
    let modern = match engine {
        Engine::Chromium(v) => v >= MODERN_CHROMIUM,
        Engine::Firefox(v) => v >= MODERN_FIREFOX,
        Engine::Safari(v) => v >= MODERN_SAFARI,
        Engine::Other | Engine::NotBrowser => false,
    } && secure;
    let wants_ch = matches!(engine, Engine::Chromium(v) if v >= MODERN_CHROMIUM) && secure;

    let mut t = Tally {
        score: 0,
        signals: Vec::with_capacity(8),
    };

    if ua.is_empty() {
        t.add("empty_ua", W_EMPTY_UA);
    }
    if lang.is_empty() {
        t.add(
            "missing_accept_language",
            weight(W_NO_LANG_BROWSER, W_NO_LANG),
        );
    }
    if accept.is_empty() {
        t.add("missing_accept", weight(W_NO_ACCEPT_BROWSER, W_NO_ACCEPT));
    } else if is_wildcard_only(accept) && is_document(method, dest, path) {
        t.add(
            "accept_wildcard_only",
            weight(W_WILDCARD_BROWSER, W_WILDCARD),
        );
    }
    if enc.is_empty() {
        t.add(
            "missing_accept_encoding",
            weight(W_NO_ENCODING_BROWSER, W_NO_ENCODING),
        );
    }

    let fetch_sent = [site, mode, dest].iter().filter(|v| !v.is_empty()).count();
    if fetch_sent == 0 {
        if modern {
            t.add("no_sec_fetch", W_NO_SEC_FETCH);
        }
    } else {
        if fetch_sent < 3 {
            t.add("sec_fetch_partial", W_SEC_FETCH_PARTIAL);
        }
        if fetch_inconsistent(site, mode, dest, method) {
            t.add("sec_fetch_inconsistent", W_SEC_FETCH_INCONSISTENT);
        }
    }

    if ch.is_empty() {
        if wants_ch {
            t.add("no_sec_ch_ua", W_NO_SEC_CH_UA);
        }
    } else if ch_contradicts(engine, ua, ch) {
        t.add("sec_ch_ua_mismatch", W_CH_UA_MISMATCH);
    }

    if ver.eq_ignore_ascii_case(b"http/1.0") {
        t.add("http_1_0", W_HTTP_1_0);
    } else if modern && http_major(ver) == Some(1) {
        t.add("http1_modern_browser", W_HTTP1_MODERN);
    }
    if one_of(tls, &["SSLv3", "TLSv1", "TLSv1.1"]) {
        t.add("old_tls", W_OLD_TLS);
    }
    if method.eq_ignore_ascii_case(b"POST") && i.referer.is_empty() {
        t.add(
            "post_no_referer",
            weight(W_POST_NO_REFERER_BROWSER, W_POST_NO_REFERER),
        );
    }

    // A matched UA token pins the class even if the score is low: a declared crawler or tool is reported as such.
    let pinned = ua_match(ua).map(|(signal, class, w)| {
        t.add(signal, w);
        class
    });

    let score = t.score.min(MAX_SCORE) as u8;
    let class = pinned.unwrap_or(if score >= BOT_THRESHOLD {
        BotClass::Bot
    } else if score >= SUSPECT_THRESHOLD {
        BotClass::Suspect
    } else {
        BotClass::Human
    });
    BotVerdict {
        score,
        class,
        signals: t.signals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    const CHROME_CH: &str =
        "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"";
    const FIREFOX_UA: &str =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0";
    const SAFARI_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15";
    const DOC_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

    fn browser(ua: &'static str) -> BotInputs<'static> {
        BotInputs {
            user_agent: ua,
            accept: DOC_ACCEPT,
            accept_language: "en-US,en;q=0.9",
            accept_encoding: "gzip, deflate, br",
            sec_fetch_site: "none",
            sec_fetch_mode: "navigate",
            sec_fetch_dest: "document",
            http_version: "HTTP/2.0",
            method: "GET",
            tls_version: "TLSv1.3",
            path: "/",
            ..BotInputs::default()
        }
    }

    fn chrome() -> BotInputs<'static> {
        BotInputs {
            sec_ch_ua: CHROME_CH,
            ..browser(CHROME_UA)
        }
    }

    fn has(v: &BotVerdict, signal: &str) -> bool {
        v.signals.contains(&signal)
    }

    #[test]
    fn real_browser_header_sets_are_human() {
        for input in [chrome(), browser(FIREFOX_UA), browser(SAFARI_UA)] {
            let v = classify(&input);
            assert_eq!(v.score, 0, "{:?}", v.signals);
            assert_eq!(v.class, BotClass::Human);
            assert!(v.signals.is_empty());
        }
    }

    #[test]
    fn browser_subresource_requests_are_human() {
        let v = classify(&BotInputs {
            accept: "image/avif,image/webp,*/*",
            sec_fetch_site: "same-origin",
            sec_fetch_mode: "no-cors",
            sec_fetch_dest: "image",
            path: "/a.png",
            referer: "https://example.org/",
            ..chrome()
        });
        assert_eq!((v.score, v.class), (0, BotClass::Human));
        let v = classify(&BotInputs {
            accept: "*/*",
            sec_fetch_site: "same-origin",
            sec_fetch_mode: "cors",
            sec_fetch_dest: "empty",
            method: "POST",
            referer: "https://example.org/",
            ..chrome()
        });
        assert_eq!((v.score, v.class), (0, BotClass::Human));
    }

    #[test]
    fn headers_outrank_a_clean_user_agent() {
        let no_lang = classify(&BotInputs {
            accept_language: "",
            ..chrome()
        });
        let plain = classify(&BotInputs {
            user_agent: "MyApp/1.0",
            accept: DOC_ACCEPT,
            accept_language: "en",
            accept_encoding: "gzip",
            method: "GET",
            path: "/",
            http_version: "HTTP/1.1",
            ..BotInputs::default()
        });
        assert_eq!(plain.score, 0);
        assert!(no_lang.score > plain.score);
        assert_eq!(no_lang.class, BotClass::Suspect);
        assert_eq!(no_lang.signals, ["missing_accept_language"]);
    }

    #[test]
    fn spoofed_browser_ua_is_caught_by_headers_alone() {
        let v = classify(&BotInputs {
            accept: "*/*",
            accept_language: "",
            accept_encoding: "",
            sec_fetch_site: "",
            sec_fetch_mode: "",
            sec_fetch_dest: "",
            sec_ch_ua: "",
            http_version: "HTTP/1.1",
            ..chrome()
        });
        assert_eq!((v.score, v.class), (100, BotClass::Bot));
        for s in [
            "missing_accept_language",
            "accept_wildcard_only",
            "missing_accept_encoding",
            "no_sec_fetch",
            "no_sec_ch_ua",
            "http1_modern_browser",
        ] {
            assert!(has(&v, s), "{s}");
        }
        assert!(v.signals.iter().all(|s| !s.starts_with("ua_")));
    }

    #[test]
    fn user_agent_signals_come_after_header_signals() {
        let v = classify(&BotInputs {
            user_agent: "curl/8.5.0",
            accept: "*/*",
            http_version: "HTTP/1.1",
            method: "GET",
            path: "/",
            ..BotInputs::default()
        });
        assert_eq!(v.class, BotClass::Tool);
        assert_eq!(v.signals.last(), Some(&"ua_curl"));
        assert_eq!(v.signals.first(), Some(&"missing_accept_language"));
    }

    #[test]
    fn googlebot_is_a_crawler() {
        let v = classify(&BotInputs {
            user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            accept: "*/*",
            accept_encoding: "gzip, deflate, br",
            http_version: "HTTP/1.1",
            method: "GET",
            path: "/",
            ..BotInputs::default()
        });
        assert_eq!(v.class, BotClass::Crawler);
        assert_eq!(v.signals.last(), Some(&"ua_googlebot"));
        assert!(v.score >= BOT_THRESHOLD);
    }

    #[test]
    fn known_crawlers_tools_and_automation_map_to_their_class() {
        let crawlers = [
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
            "Mozilla/5.0 (compatible; Baiduspider/2.0)",
            "Mozilla/5.0 (compatible; YandexBot/3.0)",
            "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (Applebot/0.1)",
            "facebookexternalhit/1.1",
            "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
            "SomethingNew/1.0 (+https://example.org/about)",
        ];
        let tools = [
            "python-requests/2.31.0",
            "python-urllib3/2.0",
            "Go-http-client/1.1",
            "okhttp/4.12.0",
            "Java/17.0.1",
            "libwww-perl/6.67",
            "node-fetch/1.0",
            "axios/1.6.0",
            "python-httpx/0.27",
            "Scrapy/2.11",
            "Wget/1.21",
            "aiohttp/3.9",
        ];
        let automation = [
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 PhantomJS/2.1.1",
            "selenium/4.0",
            "puppeteer",
            "Playwright/1.40",
        ];
        for (list, class) in [
            (&crawlers[..], BotClass::Crawler),
            (&tools[..], BotClass::Tool),
            (&automation[..], BotClass::Bot),
        ] {
            for ua in list {
                let v = classify(&BotInputs {
                    user_agent: ua,
                    ..BotInputs::default()
                });
                assert_eq!(v.class, class, "{ua}");
                assert!(
                    v.signals.last().is_some_and(|s| s.starts_with("ua_")),
                    "{ua}"
                );
            }
        }
    }

    #[test]
    fn sec_fetch_values_must_agree_with_each_other_and_the_request() {
        let bad = [
            BotInputs {
                sec_fetch_dest: "image",
                ..chrome()
            },
            BotInputs {
                sec_fetch_mode: "cors",
                sec_fetch_dest: "document",
                sec_fetch_site: "same-origin",
                ..chrome()
            },
            BotInputs {
                method: "PUT",
                ..chrome()
            },
            BotInputs {
                sec_fetch_site: "bogus",
                ..chrome()
            },
            BotInputs {
                sec_fetch_mode: "no-cors",
                sec_fetch_dest: "image",
                ..chrome()
            },
        ];
        for input in bad {
            assert!(
                has(&classify(&input), "sec_fetch_inconsistent"),
                "{input:?}"
            );
        }
        let partial = classify(&BotInputs {
            sec_fetch_mode: "",
            ..chrome()
        });
        assert!(has(&partial, "sec_fetch_partial"));
    }

    #[test]
    fn sec_ch_ua_must_match_the_claimed_browser() {
        let firefox = classify(&BotInputs {
            sec_ch_ua: CHROME_CH,
            ..browser(FIREFOX_UA)
        });
        assert!(has(&firefox, "sec_ch_ua_mismatch"));
        let no_chromium = classify(&BotInputs {
            sec_ch_ua: "\"Not A;Brand\";v=\"99\"",
            ..chrome()
        });
        assert!(has(&no_chromium, "sec_ch_ua_mismatch"));
        let wrong_version = classify(&BotInputs {
            sec_ch_ua: "\"Chromium\";v=\"120\", \"Not-A.Brand\";v=\"99\"",
            ..chrome()
        });
        assert!(has(&wrong_version, "sec_ch_ua_mismatch"));
        let edge_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0";
        let edge_as_chrome = classify(&BotInputs {
            sec_ch_ua: CHROME_CH,
            ..browser(edge_ua)
        });
        assert!(has(&edge_as_chrome, "sec_ch_ua_mismatch"));
        let edge = classify(&BotInputs {
            sec_ch_ua: "\"Chromium\";v=\"124\", \"Microsoft Edge\";v=\"124\"",
            ..browser(edge_ua)
        });
        assert_eq!(edge.score, 0);
    }

    #[test]
    fn protocol_expectations_apply_only_over_tls() {
        let h1 = classify(&BotInputs {
            http_version: "HTTP/1.1",
            ..chrome()
        });
        assert!(has(&h1, "http1_modern_browser"));
        let plain = classify(&BotInputs {
            http_version: "HTTP/1.1",
            tls_version: "",
            sec_fetch_site: "",
            sec_fetch_mode: "",
            sec_fetch_dest: "",
            sec_ch_ua: "",
            ..chrome()
        });
        assert_eq!(plain.score, 0, "{:?}", plain.signals);
        let old = classify(&BotInputs {
            http_version: "HTTP/1.0",
            ..chrome()
        });
        assert!(has(&old, "http_1_0"));
        assert!(has(
            &classify(&BotInputs {
                tls_version: "TLSv1",
                ..chrome()
            }),
            "old_tls"
        ));
    }

    #[test]
    fn empty_user_agent_and_bare_post_are_flagged() {
        let v = classify(&BotInputs::default());
        assert!(has(&v, "empty_ua"));
        assert_eq!(v.class, BotClass::Bot);
        let post = classify(&BotInputs {
            method: "POST",
            referer: "",
            sec_fetch_site: "same-origin",
            sec_fetch_mode: "cors",
            sec_fetch_dest: "empty",
            ..chrome()
        });
        assert!(has(&post, "post_no_referer"));
        let with_ref = classify(&BotInputs {
            method: "POST",
            referer: "https://example.org/",
            sec_fetch_site: "same-origin",
            sec_fetch_mode: "cors",
            sec_fetch_dest: "empty",
            ..chrome()
        });
        assert!(!has(&with_ref, "post_no_referer"));
    }

    #[test]
    fn wildcard_accept_only_counts_on_document_requests() {
        let api = classify(&BotInputs {
            user_agent: "MyApp/1.0",
            accept: "*/*",
            accept_language: "en",
            accept_encoding: "gzip",
            method: "GET",
            path: "/static/app.js",
            ..BotInputs::default()
        });
        assert!(api.signals.is_empty());
        let page = classify(&BotInputs {
            path: "/index.html",
            ..BotInputs {
                user_agent: "MyApp/1.0",
                accept: "*/*",
                accept_language: "en",
                accept_encoding: "gzip",
                method: "GET",
                ..BotInputs::default()
            }
        });
        assert_eq!(page.signals, ["accept_wildcard_only"]);
    }

    #[test]
    fn score_and_class_thresholds_line_up() {
        const { assert!(SUSPECT_THRESHOLD < BOT_THRESHOLD) };
        assert_eq!(score_bucket(0), "0-19");
        assert_eq!(score_bucket(19), "0-19");
        assert_eq!(score_bucket(20), "20-39");
        assert_eq!(score_bucket(40), "40-59");
        assert_eq!(score_bucket(79), "60-79");
        assert_eq!(score_bucket(80), "80-100");
        assert_eq!(score_bucket(100), "80-100");
        assert_eq!(score_bucket(255), "80-100");
        let names: Vec<&str> = [
            BotClass::Human,
            BotClass::Suspect,
            BotClass::Crawler,
            BotClass::Tool,
            BotClass::Bot,
        ]
        .into_iter()
        .map(BotClass::as_str)
        .collect();
        assert_eq!(names, ["human", "suspect", "crawler", "tool", "bot"]);
    }

    #[test]
    fn hostile_inputs_never_panic() {
        let huge = "A".repeat(100 * 1024);
        let ctrl = "\0\r\n\x1b\x7f \t%00%0d%0a";
        let uni = "\u{202e}\u{feff}\u{1F600}\u{e9}\u{0301}日本語";
        let mixed = "Mozilla/5.0 \u{e9}Chrome/\u{ff}99999999999999 Version/\0";
        for s in [huge.as_str(), ctrl, uni, mixed, ""] {
            let v = classify(&BotInputs {
                user_agent: s,
                accept: s,
                accept_language: s,
                accept_encoding: s,
                sec_fetch_site: s,
                sec_fetch_mode: s,
                sec_fetch_dest: s,
                sec_ch_ua: s,
                http_version: s,
                referer: s,
                method: s,
                tls_version: s,
                path: s,
            });
            assert!(v.score <= 100);
            assert!(v.signals.len() <= 16);
        }
    }

    #[test]
    fn summary_defaults_and_round_trips() {
        let s = BotSummary::default();
        assert_eq!(s.total_requests, 0);
        assert!(s.classes.is_empty());
        let s = BotSummary {
            total_requests: 10,
            bot_requests: 4,
            bot_share_pct: 40.0,
            classes: vec![TopItem {
                key: "tool".into(),
                count: 4,
                bytes: 0,
            }],
            ..BotSummary::default()
        };
        let json = serde_json::to_string(&s).expect("serialises");
        assert_eq!(
            serde_json::from_str::<BotSummary>(&json).expect("parses"),
            s
        );
    }

    proptest! {
        #[test]
        fn classify_never_panics_and_stays_in_range(
            a in ".*", b in ".*", c in ".*", d in "[ -~]{0,40}"
        ) {
            let v = classify(&BotInputs {
                user_agent: &a,
                accept: &b,
                accept_language: &c,
                accept_encoding: &d,
                sec_fetch_site: &d,
                sec_fetch_mode: &b,
                sec_fetch_dest: &c,
                sec_ch_ua: &a,
                http_version: &d,
                referer: &b,
                method: &d,
                tls_version: &d,
                path: &c,
            });
            prop_assert!(v.score <= 100);
        }
    }
}
