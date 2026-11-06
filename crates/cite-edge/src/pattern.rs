// User regexes are parsed against a small grammar on which PCRE2 and the regex crate agree, and refused unless a bound on the work for a cap-byte subject holds.
pub const UA_CAP: usize = 512;
pub const REFERER_CAP: usize = 1024;
pub const HEADER_CAP: usize = 1024;
pub const PATH_CAP: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    Path,
    UserAgent,
    Referer,
    Header,
}

impl Subject {
    pub fn cap(self) -> usize {
        match self {
            Subject::Path => PATH_CAP,
            Subject::UserAgent => UA_CAP,
            Subject::Referer => REFERER_CAP,
            Subject::Header => HEADER_CAP,
        }
    }
}

// Counts above this are refused outright, whatever the subject length.
const MAX_COUNT: u64 = 1000;
// Upper bound on matching steps for a subject of cap bytes: start positions times the product of all repeat counts.
const MAX_STEPS: u64 = 20_000_000;
// Upper bound on how many ways a prefix can be matched by overlapping alternatives, multiplied along a sequence.
const MAX_AMBIGUITY: u64 = 4096;
// Upper bound on the work from one start position (repeat product times ambiguity), far below PCRE2's default match limit of 10 million, whose error HAProxy treats as no match.
const MAX_PER_START: u64 = 250_000;
const MAX_DEGREE: u32 = 3;
const MAX_DEPTH: u32 = 8;
// Punctuation that may follow a backslash and stands for itself in both engines.
const ESCAPABLE: &[u8] = b".+*?()|[]{}^$/-_,:;=!@%&~";

type Res<T> = Result<T, String>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum First {
    Lit(u8),
    Other,
}

// What the parser knows about a piece of pattern: repeat depth and product, alternation ambiguity, how it can start, and whether it is plain text.
#[derive(Clone, Copy)]
struct Node {
    d: u32,
    r: u64,
    a: u64,
    first: First,
    anchored: bool,
    plain: bool,
}

impl Node {
    fn atom(first: First) -> Self {
        Node {
            d: 0,
            r: 1,
            a: 1,
            first,
            anchored: false,
            plain: true,
        }
    }
}

enum Kind {
    Plain,
    ZeroWidth,
    Group { inner_plain: bool },
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    cap: u64,
}

// What the parser measured: start positions, the repeat product, the ambiguity and the repeats that apply at once.
pub(crate) struct Cost {
    pub starts: u64,
    pub r: u64,
    pub a: u64,
    pub d: u32,
}

pub(crate) fn measure(re: &str, cap: usize) -> Res<Cost> {
    let body = re.strip_prefix("(?i)").unwrap_or(re);
    if body.is_empty() {
        return Err("the pattern is empty".to_string());
    }
    let mut p = Parser {
        b: body.as_bytes(),
        i: 0,
        cap: cap as u64,
    };
    let node = p.alt(0)?;
    if p.i < p.b.len() {
        return Err("unmatched )".to_string());
    }
    Ok(Cost {
        starts: if node.anchored { 1 } else { p.cap },
        r: node.r,
        a: node.a,
        d: node.d,
    })
}

pub(crate) fn check_regex(re: &str, cap: usize) -> Res<()> {
    let c = measure(re, cap)?;
    let steps = c.starts.saturating_mul(c.r);
    if steps > MAX_STEPS {
        return Err(format!(
            "matching a {cap}-byte subject could take about {steps} steps (limit {MAX_STEPS}); use fewer or smaller repeats, or anchor the pattern with ^"
        ));
    }
    let per_start = c.r.saturating_mul(c.a);
    if per_start > MAX_PER_START {
        return Err(format!(
            "one start position could take about {per_start} steps (limit {MAX_PER_START}); use fewer or smaller repeats and fewer overlapping alternatives"
        ));
    }
    if c.a > MAX_AMBIGUITY {
        return Err(format!(
            "alternatives overlap in {} ways (limit {MAX_AMBIGUITY}); make them start with different characters",
            c.a
        ));
    }
    if c.d > MAX_DEGREE {
        return Err(format!(
            "{} repeats can apply at once (limit {MAX_DEGREE})",
            c.d
        ));
    }
    Ok(())
}

fn merge(branches: Vec<Node>) -> Node {
    if branches.len() == 1 {
        return branches[0];
    }
    let other = branches.iter().filter(|n| n.first == First::Other).count() as u64;
    let mut same = 0u64;
    for n in &branches {
        if let First::Lit(c) = n.first {
            let count = branches.iter().filter(|m| m.first == First::Lit(c)).count() as u64;
            same = same.max(count);
        }
    }
    let inner = branches.iter().map(|n| n.a).max().unwrap_or(1);
    Node {
        d: branches.iter().map(|n| n.d).max().unwrap_or(0),
        r: branches.iter().map(|n| n.r).max().unwrap_or(1),
        a: (other + same).max(1).saturating_mul(inner),
        first: First::Other,
        anchored: branches.iter().all(|n| n.anchored),
        plain: false,
    }
}

fn combine(items: &[Node]) -> Node {
    let mut out = Node::atom(items.first().map_or(First::Other, |n| n.first));
    out.anchored = items.first().is_some_and(|n| n.anchored);
    for n in items {
        out.d = out.d.saturating_add(n.d);
        out.r = out.r.saturating_mul(n.r);
        out.a = out.a.saturating_mul(n.a);
        out.plain &= n.plain;
    }
    out
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn alt(&mut self, depth: u32) -> Res<Node> {
        if depth > MAX_DEPTH {
            return Err(format!("groups nested deeper than {MAX_DEPTH}"));
        }
        let mut branches = vec![self.seq(depth)?];
        while self.peek() == Some(b'|') {
            self.i += 1;
            branches.push(self.seq(depth)?);
        }
        Ok(merge(branches))
    }

    fn seq(&mut self, depth: u32) -> Res<Node> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == b'|' || c == b')' {
                break;
            }
            items.push(self.item(depth)?);
        }
        Ok(combine(&items))
    }

    fn item(&mut self, depth: u32) -> Res<Node> {
        let c = self.b[self.i];
        let (mut node, kind) = match c {
            b'(' => self.group(depth)?,
            b'[' => (self.class()?, Kind::Plain),
            b'\\' => self.escape()?,
            b'.' => {
                self.i += 1;
                (Node::atom(First::Other), Kind::Plain)
            }
            b'^' => {
                self.i += 1;
                let mut n = Node::atom(First::Other);
                n.anchored = true;
                (n, Kind::ZeroWidth)
            }
            b'$' => {
                self.i += 1;
                (Node::atom(First::Other), Kind::ZeroWidth)
            }
            b'*' | b'+' | b'?' => {
                return Err(format!("`{}` has nothing to repeat", c as char));
            }
            b'{' => {
                return Err(
                    "`{` is only allowed as a repeat count after an atom; write \\{ for a brace"
                        .to_string(),
                );
            }
            b'}' | b']' => {
                return Err(format!(
                    "unescaped `{0}`; write \\{0} for the character",
                    c as char
                ));
            }
            _ => {
                self.i += 1;
                (Node::atom(First::Lit(c.to_ascii_lowercase())), Kind::Plain)
            }
        };
        let Some((min, max)) = self.quant()? else {
            return Ok(node);
        };
        if matches!(kind, Kind::ZeroWidth) {
            return Err("an anchor or \\b cannot be repeated".to_string());
        }
        let repeating = max.is_none_or(|m| m > 1);
        if let Kind::Group { inner_plain: false } = kind
            && repeating
        {
            return Err("a group that contains an alternation, a repeat or another group cannot be repeated more than once; only plain text can".to_string());
        }
        let choice = Some(min) != max;
        if repeating && choice {
            let factor = max.map_or(self.cap, |m| m.min(self.cap)).max(1);
            node.d = node.d.saturating_add(1);
            node.r = node.r.saturating_mul(factor);
        } else if choice {
            node.d = node.d.saturating_add(1);
            node.r = node.r.saturating_mul(2);
        }
        if min == 0 {
            node.first = First::Other;
            node.anchored = false;
        }
        node.plain = false;
        Ok(node)
    }

    fn group(&mut self, depth: u32) -> Res<(Node, Kind)> {
        self.i += 1;
        if self.peek() == Some(b'?') {
            self.i += 1;
            match self.peek() {
                Some(b':') => self.i += 1,
                other => {
                    let shown = other.map_or(String::new(), |c| (c as char).to_string());
                    return Err(format!(
                        "the group syntax `(?{shown}` is not supported; only (?:...) and a leading (?i)"
                    ));
                }
            }
        }
        let mut inner = self.alt(depth + 1)?;
        if self.peek() != Some(b')') {
            return Err("unclosed (".to_string());
        }
        self.i += 1;
        let inner_plain = inner.plain;
        inner.plain = false;
        Ok((inner, Kind::Group { inner_plain }))
    }

    fn escape(&mut self) -> Res<(Node, Kind)> {
        let Some(n) = self.b.get(self.i + 1).copied() else {
            return Err("dangling backslash".to_string());
        };
        self.i += 2;
        match n {
            b'd' | b'D' | b'w' | b'W' | b's' | b'S' => Ok((Node::atom(First::Other), Kind::Plain)),
            b'b' | b'B' => Ok((Node::atom(First::Other), Kind::ZeroWidth)),
            _ if ESCAPABLE.contains(&n) => {
                Ok((Node::atom(First::Lit(n.to_ascii_lowercase())), Kind::Plain))
            }
            _ => Err(format!("the escape `\\{}` is not supported", n as char)),
        }
    }

    fn class(&mut self) -> Res<Node> {
        self.i += 1;
        if self.peek() == Some(b'^') {
            self.i += 1;
        }
        let mut items = 0;
        loop {
            let Some(c) = self.peek() else {
                return Err("unclosed [".to_string());
            };
            match c {
                b']' => {
                    if items == 0 {
                        return Err("empty character class".to_string());
                    }
                    self.i += 1;
                    break;
                }
                b'[' => {
                    return Err("`[` inside a character class (nested or POSIX class syntax such as [[:space:]]) is not supported; use \\s, \\d or \\w".to_string());
                }
                b'^' => {
                    return Err(
                        "`^` inside a character class is only allowed right after the opening ["
                            .to_string(),
                    );
                }
                b'-' => {
                    let next = self.b.get(self.i + 1).copied();
                    if items > 0 && next != Some(b']') {
                        return Err("`-` inside a class must start or end it, or sit between the two ends of a range".to_string());
                    }
                    self.i += 1;
                    items += 1;
                }
                b'\\' => {
                    let Some(n) = self.b.get(self.i + 1).copied() else {
                        return Err("dangling backslash".to_string());
                    };
                    if matches!(n, b'd' | b'D' | b'w' | b'W' | b's' | b'S') {
                        self.i += 2;
                    } else if ESCAPABLE.contains(&n) {
                        self.i += 2;
                        self.range_tail(n)?;
                    } else {
                        return Err(format!(
                            "the escape `\\{}` is not supported inside a class",
                            n as char
                        ));
                    }
                    items += 1;
                }
                _ => {
                    self.i += 1;
                    self.range_tail(c)?;
                    items += 1;
                }
            }
        }
        Ok(Node::atom(First::Other))
    }

    // After a class member `start`, consumes `-end` when that makes a range.
    fn range_tail(&mut self, start: u8) -> Res<()> {
        if self.peek() != Some(b'-') || matches!(self.b.get(self.i + 1), None | Some(b']')) {
            return Ok(());
        }
        self.i += 1;
        let e = self.b[self.i];
        let end =
            if e == b'\\' {
                match self.b.get(self.i + 1).copied() {
                    Some(n) if ESCAPABLE.contains(&n) => {
                        self.i += 2;
                        n
                    }
                    _ => return Err(
                        "a range may only end in a plain character or an escaped punctuation mark"
                            .to_string(),
                    ),
                }
            } else if e.is_ascii_graphic() && !matches!(e, b'[' | b']' | b'^' | b'-') {
                self.i += 1;
                e
            } else {
                return Err(
                    "a range may only end in a plain character or an escaped punctuation mark"
                        .to_string(),
                );
            };
        if start > end {
            return Err("a range runs backwards".to_string());
        }
        Ok(())
    }

    // Returns the minimum and optional maximum of a repeat operator, rejecting lazy and possessive suffixes.
    fn quant(&mut self) -> Res<Option<(u64, Option<u64>)>> {
        let Some(c) = self.peek() else {
            return Ok(None);
        };
        let (min, max) = match c {
            b'?' => (0, Some(1)),
            b'*' => (0, None),
            b'+' => (1, None),
            b'{' => return self.counted(),
            _ => return Ok(None),
        };
        self.i += 1;
        self.no_suffix()?;
        Ok(Some((min, max)))
    }

    fn counted(&mut self) -> Res<Option<(u64, Option<u64>)>> {
        let rest = &self.b[self.i + 1..];
        let Some(end) = rest.iter().position(|c| *c == b'}') else {
            return Err("`{` without a closing }; write \\{ for a brace".to_string());
        };
        let body = std::str::from_utf8(&rest[..end]).unwrap_or("");
        let (lo, hi) = match body.split_once(',') {
            Some((lo, hi)) => (lo, Some(hi)),
            None => (body, None),
        };
        let digits = |t: &str| !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit());
        if !digits(lo) || hi.is_some_and(|h| !h.is_empty() && !digits(h)) {
            return Err(format!("`{{{body}}}` is not a valid repeat count"));
        }
        let num = |t: &str| t.parse::<u64>().unwrap_or(u64::MAX);
        let min = num(lo);
        let max = match hi {
            None => Some(min),
            Some("") => None,
            Some(h) => Some(num(h)),
        };
        let biggest = max.map_or(min, |m| m.max(min));
        if biggest > MAX_COUNT {
            return Err(format!("the repeat count {biggest} is above {MAX_COUNT}"));
        }
        if max.is_some_and(|m| m < min) {
            return Err(format!("`{{{body}}}` has a minimum above its maximum"));
        }
        self.i += end + 2;
        self.no_suffix()?;
        Ok(Some((min, max)))
    }

    fn no_suffix(&self) -> Res<()> {
        if matches!(self.peek(), Some(b'?' | b'+' | b'*' | b'{')) {
            return Err(
                "lazy (`+?`), possessive (`++`) and stacked repeats are not supported".to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use regex::Regex;

    fn ok(re: &str) {
        check_regex(re, UA_CAP).unwrap_or_else(|e| panic!("{re:?} refused: {e}"));
        Regex::new(re).unwrap_or_else(|e| panic!("{re:?} does not compile: {e}"));
    }

    fn refused(re: &str) -> String {
        match check_regex(re, UA_CAP) {
            Ok(()) => panic!("{re:?} accepted"),
            Err(e) => e,
        }
    }

    #[test]
    fn real_world_patterns_pass() {
        for re in [
            "^/api/v[0-9]+/",
            "(?i)(sqlmap|nikto)",
            "^/wp-(admin|login)\\.php$",
            "\\.(php|asp)$",
            "(?i)(^|/)\\.env",
            "[a-z0-9_-]+",
            "[^/]*",
            "\\d{1,3}",
            "a{2}",
            "(?:ab)+",
            "(ab)?",
            "a?b?c?",
            "\\bfoo\\b",
            "a.b",
            "^/a\\/b$",
            "[\\w.-]+@x",
            "(foo|bar)",
            "(foo|bar)?baz",
            "^/(a|b)/(c|d)$",
            "[-a]",
            "[a-]",
            "[a\\]b]",
            "x{0,1}",
            "(ab){3}",
            "(ab){1,10}",
            "^/[a-z]{1,8}/[^/]*$",
            "\\(a+\\)",
        ] {
            ok(re);
        }
        assert!(check_regex("(?i)abc", UA_CAP).is_ok());
    }

    // Constructs where the two engines are most likely to disagree; each accepted one has the meaning PCRE2 gives it, checked on ASCII subjects.
    #[test]
    fn edge_constructs_mean_the_same_in_both_engines() {
        let cases: [(&str, &str, bool); 30] = [
            ("x{0}y", "y", true),
            ("x{0}y", "xy", true),
            ("^x{0}$", "", true),
            ("^x{0,0}$", "x", false),
            ("^(?:)a$", "a", true),
            ("^()a$", "a", true),
            ("^(a|)b$", "b", true),
            ("^(a|)b$", "ab", true),
            ("^(|a)b$", "ab", true),
            ("a|^b", "xxa", true),
            ("a|^b", "bxx", true),
            ("a|^b", "xbx", false),
            ("a$b", "a", false),
            ("a^b", "ab", false),
            ("(?i)[a-z]+x", "ABX", true),
            ("(?i)^[^a-z]+$", "AB", false),
            ("(?i)^[A-C]+$", "abc", true),
            ("\\bfoo\\b", "a foo b", true),
            ("\\bfoo\\b", "afoo", false),
            ("foo\\b", "foo", true),
            ("\\bfoo", "xfoo", false),
            ("^\\.\\-\\_\\!\\@$", ".-_!@", true),
            ("^[\\.\\-\\_]x$", "-x", true),
            ("^[\\]\\[]x$", "]x", true),
            ("^[a\\^]x$", "^x", true),
            ("^x\\,\\:\\;\\=\\&\\~\\%y$", "x,:;=&~%y", true),
            ("^[\\w-]+$", "a-b_c", true),
            ("^[a-]+$", "a-", true),
            ("^a{2,3}$", "aaaa", false),
            ("^\\/a$", "/a", true),
        ];
        for (re, subject, want) in cases {
            ok(re);
            assert_eq!(
                Regex::new(re).expect("compiles").is_match(subject),
                want,
                "{re} on {subject:?}"
            );
        }
    }

    #[test]
    fn unsupported_constructs_are_named() {
        let cases = [
            ("a(?=b)", "(?="),
            ("a(?!b)", "(?!"),
            ("(?<=a)b", "(?<"),
            ("(?P<n>a)", "(?P"),
            ("(?<n>a)", "(?<"),
            ("(?>a)", "(?>"),
            ("(?s)a", "(?s"),
            ("a(?i)b", "(?i"),
            ("(?(1)a)", "(?("),
            ("(?R)", "(?R"),
            ("(?#note)", "(?#"),
            ("\\Qab\\E", "\\Q"),
            ("(a)\\1", "\\1"),
            ("\\p{L}", "\\p"),
            ("\\A", "\\A"),
            ("\\z", "\\z"),
            ("\\n", "\\n"),
            ("\\k<a>", "\\k"),
            ("a*+", "possessive"),
            ("a++", "possessive"),
            ("a*?", "lazy"),
            ("a+?", "lazy"),
            ("a??", "lazy"),
            ("a{2}?", "lazy"),
            ("a**", "stacked"),
            ("a{,3}", "valid repeat"),
            ("a{3,2}", "minimum"),
            ("a{x}", "valid repeat"),
            ("a{3", "closing"),
            ("{3}", "repeat count after an atom"),
            ("*a", "nothing to repeat"),
            ("a|*b", "nothing to repeat"),
            ("^*", "anchor"),
            ("\\b+", "anchor"),
            ("[[:alpha:]]", "POSIX"),
            ("[[.a.]]", "POSIX"),
            ("[[=a=]]", "POSIX"),
            ("[a[b]]", "nested"),
            ("[]a]", "empty"),
            ("[^]a]", "empty"),
            ("[a^b]", "`^`"),
            ("[a-c-e]", "`-`"),
            ("[z-a]", "backwards"),
            ("[\\b]", "inside a class"),
            ("[a", "unclosed ["),
            ("(a", "unclosed ("),
            ("a)", "unmatched"),
            ("a]", "unescaped"),
            ("a}", "unescaped"),
            ("\\", "dangling"),
        ];
        for (re, needle) in cases {
            let err = refused(re);
            assert!(err.contains(needle), "{re:?}: {err}");
        }
    }

    #[test]
    fn the_audited_reproducers_are_refused() {
        for re in [
            "[a-z]{1,1000}[a-z]{1,1000}[a-z]{1,1000}!",
            "\\w{1,1000}\\w{1,1000}\\w{1,1000}!",
            "(a|a){32}b",
            "[a-z]*[a-z]*[a-z]*!",
            "[[:a](x+)+y[:]]",
            "(a|aa){2,60}[0-9]",
            ".*.*.*.*[0-9]",
            ".*.*.*.*.*.*.*.*[0-9]",
            "(a{1,100}){1,100}[0-9]",
            "(a+)+",
            "(x*)*",
            "^/(a|aa)+$",
            "(a|b)*c",
            "((a+)b)+",
            "([a-z]+\\.)+x",
            "(a*)+?",
            "a{1,1001}",
            "a{1001,}",
            "(ab){1,99999999999}",
        ] {
            refused(re);
        }
    }

    #[test]
    fn work_and_ambiguity_bounds_apply() {
        ok("a?a?a?");
        refused("a?a?a?a?");
        refused(&"a?".repeat(30));
        ok(&"(a|b)".repeat(4));
        refused(&"(a|a)".repeat(14));
        refused(&"(aa|ab|ac|ad)".repeat(7));
        ok("^[a-z]{1,100}[a-z]{1,100}$");
        refused("^.*.*$");
        refused("^.*.*.*$");
        ok(".*x");
        refused(".*.*x");
        assert!(check_regex("^.*.*.*x", UA_CAP).is_err());
        assert!(check_regex(".*", PATH_CAP).is_ok());
        assert!(check_regex("[^/]*x[^/]*", PATH_CAP).is_err());
        assert!(check_regex("^[^/]*x[^/]*", PATH_CAP).is_err());
        assert!(check_regex("^[a-z]{1,1000}[a-z]{1,1000}[a-z]{1,76}!", UA_CAP).is_err());
    }

    #[test]
    fn ambiguity_and_repeats_are_bounded_together() {
        // twelve overlapping pairs (4096 ways) in front of one wide repeat: each limit alone allows it
        let re = format!("{}[a-z]+x", "(a|a)".repeat(12));
        assert!(check_regex(&re, UA_CAP).is_err());
        let err = check_regex(&re, UA_CAP).unwrap_err();
        assert!(err.contains("one start position"), "{err}");
        let optional = format!("{}[a-z]{{1,40}}x", "(a|a)".repeat(6));
        ok(&optional);
        // every `?` counts as a repeat too
        assert!(
            check_regex("a?a?a?a?", UA_CAP)
                .unwrap_err()
                .contains("repeats can apply")
        );
    }

    #[test]
    fn the_strongest_accepted_patterns_stay_inside_every_bound() {
        const FRAGS: [&str; 9] = [
            "[a-z]{1,60}",
            "[a-z]{1,120}",
            "[a-z]+",
            "[a-z]*",
            "a?",
            ".*",
            "(ab)+",
            "[0-9]{1,30}",
            "(a|b)",
        ];
        for cap in [UA_CAP, REFERER_CAP, PATH_CAP] {
            let (mut steps_max, mut start_max) = (0u64, 0u64);
            for anchor in ["", "^"] {
                for first in FRAGS {
                    for b in 0..=FRAGS.len() {
                        for c in 0..=FRAGS.len() {
                            let part = |i: usize| FRAGS.get(i).copied().unwrap_or("");
                            let re = format!("{anchor}{first}{}{}!", part(b), part(c));
                            if check_regex(&re, cap).is_err() {
                                continue;
                            }
                            let cost = measure(&re, cap).expect("measured");
                            steps_max = steps_max.max(cost.starts * cost.r);
                            start_max = start_max.max(cost.r * cost.a);
                            assert!(Regex::new(&re).is_ok(), "{re}");
                        }
                    }
                }
            }
            assert!(
                steps_max <= MAX_STEPS && start_max <= MAX_PER_START,
                "{cap}"
            );
            // the bounds are tight enough to matter, so the live battery holds patterns near them
            assert!(
                steps_max > MAX_STEPS / 20 && start_max > MAX_PER_START / 10,
                "{cap}: {steps_max} {start_max}"
            );
        }
    }

    #[test]
    fn groups_repeat_only_when_they_are_plain_text() {
        ok("(ab)+");
        ok("(?:abc){2,5}");
        refused("(a|b)+");
        refused("(a?)+");
        refused("(a(b))+");
        refused("((ab))*");
        refused("(a|b){2,3}");
        ok("(a|b)?");
        ok("(a+)?c");
        ok("(a|b)");
    }

    #[test]
    fn the_cap_changes_the_bound() {
        let re = "[a-z]+[a-z]+x";
        assert!(check_regex(re, 128).is_ok());
        assert!(check_regex(re, UA_CAP).is_err());
        assert_eq!(Subject::Path.cap(), 2048);
        assert_eq!(Subject::UserAgent.cap(), 512);
        assert_eq!(Subject::Referer.cap(), 1024);
        assert_eq!(Subject::Header.cap(), 1024);
    }

    #[test]
    fn deep_nesting_is_refused() {
        refused(&format!("{}a{}", "(".repeat(12), ")".repeat(12)));
        ok(&format!("{}a{}", "(".repeat(4), ")".repeat(4)));
    }

    proptest! {
        #[test]
        fn accepted_patterns_always_compile(picks in proptest::collection::vec(0usize..16, 1..10)) {
            const PARTS: [&str; 16] = [
                "/api", "v[0-9]+", "[a-z]{1,8}", "(foo|bar)", "(ab)?", "\\.", "[^/]*", "x?",
                "^", "$", "\\d{2,4}", "(?:ab)+", "\\w+", ".*", "(a|b|c)", "\\bq",
            ];
            let pattern: String = picks.iter().map(|p| PARTS[*p]).collect();
            if check_regex(&pattern, UA_CAP).is_ok() {
                prop_assert!(Regex::new(&pattern).is_ok(), "{pattern}");
            }
        }

        #[test]
        fn few_repeats_always_validate(picks in proptest::collection::vec(0usize..8, 1..7)) {
            // (text, repeats applied at once, unbounded)
            const PARTS: [(&str, u32, u32); 8] = [
                ("/api", 0, 0), ("v[0-9]+", 1, 1), ("[a-z]{1,8}", 1, 0), ("(foo|bar)", 0, 0),
                ("(ab)?", 1, 0), ("\\.", 0, 0), ("[^/]*", 1, 1), ("x?", 1, 0),
            ];
            let repeats: u32 = picks.iter().map(|p| PARTS[*p].1).sum();
            let unbounded: u32 = picks.iter().map(|p| PARTS[*p].2).sum();
            prop_assume!(repeats <= 3 && unbounded <= 1);
            let pattern: String = picks.iter().map(|p| PARTS[*p].0).collect();
            prop_assert!(check_regex(&pattern, UA_CAP).is_ok(), "{pattern}");
        }
    }
}
