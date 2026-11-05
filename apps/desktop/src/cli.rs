use crate::app::{Options, View};

pub const USAGE: &str = "usage: cite-desktop [--demo] [--view <name>] [--node <name>]\n\nviews: overview, nodes, sites, site-detail, site-new, traffic, firewall, maintenance, settings";

// Flags are parsed by hand: the surface is three options and no extra crate is justified.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut opts = Options {
        demo: false,
        view: None,
        select: None,
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--demo" => opts.demo = true,
            "--view" => {
                let name = args.next().ok_or("--view needs a view name")?;
                opts.view =
                    Some(View::parse(&name).ok_or_else(|| format!("unknown view {name:?}"))?);
            }
            "--node" => opts.select = Some(args.next().ok_or("--node needs a node name")?),
            "-h" | "--help" => return Err(USAGE.to_string()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Options, String> {
        parse(args.iter().map(|a| a.to_string()))
    }

    #[test]
    fn defaults_are_live_overview() {
        let o = run(&[]).expect("parse");
        assert!(!o.demo && o.view.is_none() && o.select.is_none());
    }

    #[test]
    fn flags_are_read() {
        let o = run(&["--demo", "--view", "traffic", "--node", "edge-fra"]).expect("parse");
        assert!(o.demo);
        assert_eq!(o.view, Some(View::Traffic));
        assert_eq!(o.select.as_deref(), Some("edge-fra"));
    }

    #[test]
    fn bad_input_is_reported() {
        assert!(run(&["--view"]).is_err());
        assert!(run(&["--view", "nope"]).is_err());
        assert!(run(&["--wat"]).is_err());
        assert!(run(&["--help"]).unwrap_err().contains("usage"));
    }
}
