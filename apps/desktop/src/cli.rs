use crate::app::{Options, View};

pub const USAGE: &str = "usage: cite-desktop [--demo] [--view <name>] [--node <name>]\n\nviews: overview, nodes, sites, site-detail, site-new, traffic, request-detail, bots, explore, export, firewall, maintenance, settings";

// Flags are parsed by hand: the surface is three options and no extra crate is justified.
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut opts = Options {
        demo: false,
        view: None,
        select: None,
        inspect: false,
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--demo" => opts.demo = true,
            "--view" => {
                let name = args.next().ok_or("--view needs a view name")?;
                // The detail card is part of the traffic view, so it is a flag rather than a View.
                opts.inspect = name == "request-detail";
                let lookup = if opts.inspect {
                    "traffic"
                } else {
                    name.as_str()
                };
                opts.view =
                    Some(View::parse(lookup).ok_or_else(|| format!("unknown view {name:?}"))?);
            }
            "--node" => opts.select = Some(args.next().ok_or("--node needs a node name")?),
            "-h" | "--help" => return Err(USAGE.to_string()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(opts)
}

// Preview launches (--demo or --view) open without taking focus so they never steal input.
pub fn takes_focus(opts: &Options) -> bool {
    !opts.demo && opts.view.is_none()
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
    fn bot_analytics_views_can_be_opened_directly() {
        for (name, view) in [
            ("bots", View::Bots),
            ("explore", View::Explore),
            ("export", View::Export),
        ] {
            let o = run(&["--demo", "--view", name]).expect("parse");
            assert_eq!(o.view.as_ref(), Some(&view));
            assert_eq!(view.section(), "Traffic");
        }
    }

    #[test]
    fn request_detail_opens_traffic_with_the_detail_card() {
        let o = run(&["--demo", "--view", "request-detail"]).expect("parse");
        assert_eq!(o.view, Some(View::Traffic));
        assert!(o.inspect);
        assert!(!run(&["--view", "traffic"]).expect("parse").inspect);
    }

    #[test]
    fn previews_do_not_take_focus() {
        assert!(takes_focus(&run(&[]).expect("parse")));
        assert!(takes_focus(&run(&["--node", "edge-fra"]).expect("parse")));
        assert!(!takes_focus(&run(&["--demo"]).expect("parse")));
        assert!(!takes_focus(&run(&["--view", "traffic"]).expect("parse")));
    }

    #[test]
    fn bad_input_is_reported() {
        assert!(run(&["--view"]).is_err());
        assert!(run(&["--view", "nope"]).is_err());
        assert!(run(&["--wat"]).is_err());
        assert!(run(&["--help"]).unwrap_err().contains("usage"));
    }
}
