use serde::Serialize;

use crate::validate::{ValidationError, invalid};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ServerStat {
    pub name: String,
    pub status: String,
    pub check: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BackendStat {
    pub name: String,
    pub status: String,
    pub sessions: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub servers: Vec<ServerStat>,
}

fn is_word(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn check_word(what: &str, s: &str) -> Result<(), ValidationError> {
    if !is_word(s) {
        return invalid(format!(
            "runtime {what}: {s:?} may only contain letters, digits, dash and underscore"
        ));
    }
    Ok(())
}

// The runtime socket is line based, so any whitespace or newline would start a new command.
fn check_path(path: &str) -> Result<(), ValidationError> {
    let ok = !path.is_empty()
        && path.len() <= 512
        && path
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'/'));
    if !ok {
        return invalid(format!(
            "runtime map path: {path:?} contains unsafe characters"
        ));
    }
    Ok(())
}

pub fn cmd_set_map(map_path: &str, key: &str, value: &str) -> Result<String, ValidationError> {
    check_path(map_path)?;
    check_word("map key", key)?;
    check_word("map value", value)?;
    Ok(format!("set map {map_path} {key} {value}\n"))
}

pub fn cmd_set_active(
    maps_dir: &str,
    site_id: &str,
    backend: &str,
) -> Result<String, ValidationError> {
    cmd_set_map(
        &format!("{}/active.map", maps_dir.trim_end_matches('/')),
        site_id,
        backend,
    )
}

pub fn cmd_set_maintenance(
    maps_dir: &str,
    site_id: &str,
    on: bool,
) -> Result<String, ValidationError> {
    let value = if on { "on" } else { "off" };
    cmd_set_map(
        &format!("{}/maint.map", maps_dir.trim_end_matches('/')),
        site_id,
        value,
    )
}

pub fn cmd_show_stat() -> &'static str {
    "show stat\n"
}

pub fn cmd_show_servers_state(backend: &str) -> Result<String, ValidationError> {
    check_word("backend", backend)?;
    Ok(format!("show servers state {backend}\n"))
}

pub fn cmd_set_server_state(
    backend: &str,
    server: &str,
    state: &str,
) -> Result<String, ValidationError> {
    check_word("backend", backend)?;
    check_word("server", server)?;
    if !matches!(state, "ready" | "drain" | "maint") {
        return invalid(format!(
            "runtime server state: {state:?} must be ready, drain or maint"
        ));
    }
    Ok(format!("set server {backend}/{server} state {state}\n"))
}

pub fn parse_stat_csv(csv: &str) -> Vec<BackendStat> {
    let mut lines = csv.lines();
    let Some(header) = lines.find(|l| l.starts_with('#')) else {
        return Vec::new();
    };
    let cols: Vec<&str> = header.trim_start_matches('#').trim().split(',').collect();
    let col = |name: &str| cols.iter().position(|c| *c == name);
    let (Some(px), Some(sv)) = (col("pxname"), col("svname")) else {
        return Vec::new();
    };
    let status = col("status");
    let scur = col("scur");
    let bin = col("bin");
    let bout = col("bout");
    let check = col("check_status");

    let mut out: Vec<BackendStat> = Vec::new();
    for line in lines {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        let get = |i: Option<usize>| i.and_then(|i| f.get(i).copied()).unwrap_or("");
        let num = |i: Option<usize>| get(i).parse::<u64>().unwrap_or(0);
        let (Some(&proxy), Some(&svname)) = (f.get(px), f.get(sv)) else {
            continue;
        };
        if proxy.is_empty() || svname == "FRONTEND" {
            continue;
        }
        // servers are listed before their BACKEND row, so entries are created on first sight
        let idx = match out.iter().position(|b| b.name == proxy) {
            Some(i) => i,
            None => {
                out.push(BackendStat {
                    name: proxy.to_string(),
                    ..Default::default()
                });
                out.len() - 1
            }
        };
        let entry = &mut out[idx];
        if svname == "BACKEND" {
            entry.status = get(status).to_string();
            entry.sessions = num(scur);
            entry.bytes_in = num(bin);
            entry.bytes_out = num(bout);
        } else {
            entry.servers.push(ServerStat {
                name: svname.to_string(),
                status: get(status).to_string(),
                check: get(check).to_string(),
            });
        }
    }
    out
}

// HAProxy reports check_status INI until a server's first check finishes, so only a passed latest check counts as up.
fn check_passed(check: &str) -> bool {
    matches!(check, "L4OK" | "L6OK" | "L7OK" | "L7OKC")
}

pub fn all_servers_up(stats: &[BackendStat], backend: &str) -> bool {
    let up = |b: &BackendStat| {
        !b.servers.is_empty()
            && b.servers
                .iter()
                .all(|s| s.status.starts_with("UP") && check_passed(&s.check))
    };
    stats.iter().find(|b| b.name == backend).is_some_and(up)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx\n\
fe_main,FRONTEND,,,3,10,20000,120,5000,9000,0,0,0,,,,,OPEN,,,,,,,,,1,2,0,,,,0,1,0,5,,,,0\n\
be_shop_blue,s1,0,0,1,2,,50,2000,4000,,0,,0,0,0,0,UP,100,1,0,0,0,300,0,,1,3,1,,50,,2,0,,2,L7OK,200,3,0\n\
be_shop_blue,s2,0,0,0,0,,0,0,0,,0,,0,0,0,0,DOWN,100,1,0,3,1,20,5,,1,3,2,,0,,2,0,,0,L4CON,,0,0\n\
be_shop_blue,BACKEND,0,0,1,2,2000,50,2000,4000,0,0,,0,0,0,0,UP,100,1,0,,0,300,0,,1,3,0,,50,,1,0,,2,,,,0\n\
be_shop_green,s1,0,0,0,0,,0,0,0,,0,,0,0,0,0,UP 1/2,100,1,0,0,0,10,0,,1,4,1,,0,,2,0,,0,L7OK,200,2,0\n\
be_shop_green,BACKEND,0,0,0,0,2000,0,0,0,0,0,,0,0,0,0,UP,100,1,0,,0,10,0,,1,4,0,,0,,1,0,,0,,,,0\n\
be_empty_blue,BACKEND,0,0,0,0,2000,0,0,0,0,0,,0,0,0,0,DOWN,0,0,0,,0,10,0,,1,5,0,,0,,1,0,,0,,,,0\n";

    #[test]
    fn parses_backends_and_servers() {
        let stats = parse_stat_csv(SAMPLE);
        let names: Vec<&str> = stats.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["be_shop_blue", "be_shop_green", "be_empty_blue"]);
        let blue = &stats[0];
        assert_eq!(blue.status, "UP");
        assert_eq!(
            (blue.sessions, blue.bytes_in, blue.bytes_out),
            (1, 2000, 4000)
        );
        assert_eq!(blue.servers.len(), 2);
        assert_eq!(blue.servers[0].check, "L7OK");
        assert_eq!(blue.servers[1].status, "DOWN");
        assert_eq!(blue.servers[1].check, "L4CON");
    }

    #[test]
    fn frontend_rows_are_skipped() {
        assert!(parse_stat_csv(SAMPLE).iter().all(|b| b.name != "fe_main"));
    }

    #[test]
    fn garbage_input_yields_nothing() {
        assert!(parse_stat_csv("").is_empty());
        assert!(parse_stat_csv("no header here\na,b,c\n").is_empty());
        assert!(parse_stat_csv("# a,b\nx,y\n").is_empty());
    }

    #[test]
    fn short_rows_do_not_panic() {
        let csv = "# pxname,svname,status,scur\nbe_a,BACKEND\nbe_a,s1,UP\n";
        let stats = parse_stat_csv(csv);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].servers[0].status, "UP");
        assert_eq!(stats[0].sessions, 0);
    }

    #[test]
    fn all_up_requires_every_server_up() {
        let stats = parse_stat_csv(SAMPLE);
        assert!(!all_servers_up(&stats, "be_shop_blue"));
        assert!(all_servers_up(&stats, "be_shop_green"));
    }

    #[test]
    fn all_up_waits_for_a_passing_check() {
        let head = "# pxname,svname,status,check_status\n";
        for (row, want) in [
            ("be_a,s1,UP,L7OK\n", true),
            ("be_a,s1,UP 1/2,L7OKC\n", true),
            ("be_a,s1,UP,INI\n", false),
            ("be_a,s1,UP,\n", false),
            ("be_a,s1,UP 2/3,L4CON\n", false),
            ("be_a,s1,UP 1/3,L7STS\n", false),
            ("be_a,s1,DOWN,L7OK\n", false),
            ("be_a,s1,UP,L7OK\nbe_a,s2,UP,INI\n", false),
        ] {
            let stats = parse_stat_csv(&format!("{head}{row}"));
            assert_eq!(all_servers_up(&stats, "be_a"), want, "{row:?}");
        }
    }

    #[test]
    fn all_up_false_for_empty_or_missing_backend() {
        let stats = parse_stat_csv(SAMPLE);
        assert!(!all_servers_up(&stats, "be_empty_blue"));
        assert!(!all_servers_up(&stats, "be_nope"));
        assert!(!all_servers_up(&[], "be_shop_blue"));
    }

    #[test]
    fn set_map_formats_command() {
        let cmd = cmd_set_map("/run/maps/active.map", "shop", "be_shop_green").unwrap();
        assert_eq!(cmd, "set map /run/maps/active.map shop be_shop_green\n");
        let cmd = cmd_set_active("/run/maps/", "shop", "be_shop_blue").unwrap();
        assert_eq!(cmd, "set map /run/maps/active.map shop be_shop_blue\n");
        let cmd = cmd_set_maintenance("/run/maps", "shop", true).unwrap();
        assert_eq!(cmd, "set map /run/maps/maint.map shop on\n");
    }

    #[test]
    fn set_map_rejects_injection() {
        for bad in ["a b", "a\nshutdown", "", "a;b", "a\"b", "a#"] {
            assert!(
                cmd_set_map("/m/active.map", bad, "v").is_err(),
                "key {bad:?}"
            );
            assert!(
                cmd_set_map("/m/active.map", "k", bad).is_err(),
                "value {bad:?}"
            );
        }
        assert!(cmd_set_map("/m/a b.map", "k", "v").is_err());
        assert!(cmd_set_map("/m/a\n.map", "k", "v").is_err());
    }

    #[test]
    fn server_state_commands() {
        assert_eq!(cmd_show_stat(), "show stat\n");
        assert_eq!(
            cmd_show_servers_state("be_a").unwrap(),
            "show servers state be_a\n"
        );
        assert_eq!(
            cmd_set_server_state("be_a", "s1", "drain").unwrap(),
            "set server be_a/s1 state drain\n"
        );
        assert!(cmd_set_server_state("be_a", "s1", "shutdown").is_err());
        assert!(cmd_set_server_state("be_a", "s1 x", "ready").is_err());
        assert!(cmd_show_servers_state("be_a\nquit").is_err());
    }
}
