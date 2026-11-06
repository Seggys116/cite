use super::*;

fn ev(ip: &str, status: u16, site: &str, path: &str, ua: &str, bytes_out: u64) -> LogEvent {
    LogEvent {
        site: site.into(),
        path: path.into(),
        user_agent: ua.into(),
        bytes_out,
        ..event(ip, status)
    }
}

async fn seeded() -> (Harness, String) {
    let h = start().await;
    let t = h.token().await;
    h.ingest([
        ev("10.0.0.1", 200, "blog", "/a", "curl/8.1", 100),
        ev("10.0.0.2", 404, "blog", "/b", "Mozilla/5.0", 5000),
        ev("10.0.0.2", 500, "shop", "/a", "curl/8.1", 300),
        ev("192.168.1.9", 200, "shop", "/c", "Googlebot/2.1", 20),
    ]);
    (h, t)
}

#[tokio::test]
async fn filters_narrow_the_summary_and_are_echoed() {
    let (h, t) = seeded().await;
    for (query, want) in [
        ("window=1h", 4),
        ("window=1h&site=shop", 2),
        ("window=1h&site=blog&site=shop", 4),
        ("window=1h&site=blog,shop", 4),
        ("window=1h&status_class=4xx,5xx", 2),
        ("window=1h&status_min=500", 1),
        ("window=1h&client_ip=10.0.0.0/8", 3),
        ("window=1h&client_ip=192.168.1.9", 1),
        ("window=1h&user_agent=CURL", 2),
        ("window=1h&path_exact=/a", 2),
        ("window=1h&path_prefix=/", 4),
        ("window=1h&host=a.example.com&method=get", 4),
        ("window=1h&min_bot_score=1", 0),
        (
            "window=1h&user_agent=%27%3B%20DROP%20TABLE%20requests%3B--",
            0,
        ),
        ("window=1h&user_agent=%25%25%25", 0),
        ("window=1h&blocked=unblocked", 4),
        ("window=1h&blocked=true", 0),
        ("window=1h&content_type=text/", 4),
        ("window=1h&min_duration_ms=6", 0),
    ] {
        let (status, s) = h.get(&t, &format!("/analytics/summary?{query}")).await;
        assert_eq!(status, 200, "{query}: {s}");
        assert_eq!(s["requests"], want, "{query}");
        assert_eq!(s["partial"], false, "{query}");
        assert!(s["filters"].is_object(), "{query}");
        assert!(s["to_ms"].as_i64() > s["from_ms"].as_i64(), "{query}");
    }
    let (_, s) = h
        .get(
            &t,
            "/analytics/summary?window=1h&site=blog&site=shop&status_class=2xx",
        )
        .await;
    assert_eq!(s["filters"]["window"], "1h");
    assert_eq!(s["filters"]["site"], json!(["blog", "shop"]));
    assert_eq!(s["filters"]["status_class"], json!(["2xx"]));
    assert_eq!(s["source"], "raw");

    let now = now_ms();
    let (status, s) = h
        .get(
            &t,
            &format!(
                "/analytics/summary?from={}&to={}",
                now - 3_600_000,
                now + 1000
            ),
        )
        .await;
    assert_eq!(status, 200, "{s}");
    assert_eq!(s["requests"], 4);
    assert_eq!(s["from_ms"], now - 3_600_000);
    assert_eq!(s["to_ms"], now + 1000);
    assert!(s["filters"].get("window").is_none());

    // the hostile value above changed nothing
    let (_, all) = h.get(&t, "/analytics/summary?window=1h").await;
    assert_eq!(all["requests"], 4);
}

#[tokio::test]
async fn every_endpoint_takes_the_same_filter() {
    let (h, t) = seeded().await;
    let (_, series) = h
        .get(
            &t,
            "/analytics/timeseries?window=1h&site=blog&status_class=4xx",
        )
        .await;
    let total: u64 = series["points"]
        .as_array()
        .expect("points")
        .iter()
        .map(|p| p["requests"].as_u64().unwrap_or(0))
        .sum();
    assert_eq!(total, 1);
    assert_eq!(series["step_secs"], 60);
    assert_eq!(series["partial"], false);

    let (_, bots) = h.get(&t, "/analytics/bots?window=1h&site=blog").await;
    assert_eq!(bots["total_requests"], 2);
    assert!(bots["filters"].is_object());

    let (_, top) = h
        .get(&t, "/analytics/top?kind=paths&window=1h&sort=bytes&limit=2")
        .await;
    assert_eq!(top["items"][0]["key"], "/b");
    assert_eq!(top["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(top["source"], "raw");
    let (_, by_count) = h.get(&t, "/analytics/top?kind=paths&window=1h").await;
    assert_eq!(by_count["items"][0]["key"], "/a");
    assert_eq!(by_count["items"][0]["count"], 2);
    let (_, narrowed) = h
        .get(&t, "/analytics/top?kind=ips&window=1h&site=shop&limit=5")
        .await;
    assert_eq!(narrowed["items"].as_array().map(Vec::len), Some(2));
}

#[tokio::test]
async fn facets_list_values_with_counts() {
    let (h, t) = seeded().await;
    let (status, f) = h.get(&t, "/analytics/facets?window=1h").await;
    assert_eq!(status, 200, "{f}");
    assert_eq!(
        f["site"],
        json!([{ "key": "blog", "count": 2 }, { "key": "shop", "count": 2 }])
    );
    assert_eq!(f["host"], json!([{ "key": "a.example.com", "count": 4 }]));
    assert_eq!(f["method"], json!([{ "key": "GET", "count": 4 }]));
    assert_eq!(
        f["status_class"],
        json!([
            { "key": "2xx", "count": 2 },
            { "key": "4xx", "count": 1 },
            { "key": "5xx", "count": 1 }
        ])
    );
    assert!(f["filters"].is_object() && f["partial"] == false);

    let (_, narrowed) = h
        .get(&t, "/analytics/facets?window=1h&client_ip=10.0.0.0/8")
        .await;
    assert_eq!(
        narrowed["site"],
        json!([{ "key": "blog", "count": 2 }, { "key": "shop", "count": 1 }])
    );
}

#[tokio::test]
async fn compare_reports_the_previous_period() {
    let (h, t) = seeded().await;
    let (status, c) = h.get(&t, "/analytics/compare?window=1h").await;
    assert_eq!(status, 200, "{c}");
    assert_eq!(c["against"], "previous");
    assert_eq!(c["current"]["requests"], 4);
    assert_eq!(c["previous"]["requests"], 0);
    assert_eq!(c["delta"]["requests"]["abs"], 4.0);
    assert!(c["delta"]["requests"].get("pct").is_none());
    let current = &c["current"];
    let previous = &c["previous"];
    assert_eq!(previous["to_ms"], current["from_ms"]);

    let (status, c) = h
        .get(
            &t,
            "/analytics/compare?window=1h&site=shop&against=previous",
        )
        .await;
    assert_eq!(status, 200, "{c}");
    assert_eq!(c["current"]["requests"], 2);
    assert_eq!(h.get(&t, "/analytics/compare?against=next").await.0, 400);
}

#[tokio::test]
async fn the_request_list_keeps_its_shape_and_pages_with_a_cursor() {
    let (h, t) = seeded().await;
    let (_, plain) = h.get(&t, "/analytics/requests?limit=2").await;
    assert_eq!(plain.as_array().map(Vec::len), Some(2));
    // the desktop client has always sent a window, which the list ignored
    let (status, windowed) = h.get(&t, "/analytics/requests?window=2w&limit=3").await;
    assert_eq!(status, 200);
    assert_eq!(windowed.as_array().map(Vec::len), Some(3));
    let (_, contains) = h.get(&t, "/analytics/requests?path=/a").await;
    assert_eq!(contains.as_array().map(Vec::len), Some(2));
    let (_, blocked) = h
        .get(&t, "/analytics/requests?blocked=false&limit=10")
        .await;
    assert_eq!(blocked.as_array().map(Vec::len), Some(4));

    let (_, first) = h
        .get(&t, "/analytics/requests?limit=2&envelope=true&window=1h")
        .await;
    assert_eq!(first["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(first["partial"], false);
    assert!(first["filters"].is_object());
    let mut paths: Vec<String> = first["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|e| e["path"].as_str().unwrap_or_default().to_string())
        .collect();
    let mut cursor = first["next_cursor"].clone();
    let mut pages = 1;
    while !cursor.is_null() {
        let (status, next) = h
            .get(
                &t,
                &format!(
                    "/analytics/requests?limit=2&envelope=true&window=1h&before_ts={}&before_id={}",
                    cursor["before_ts"], cursor["before_id"]
                ),
            )
            .await;
        assert_eq!(status, 200, "{next}");
        paths.extend(
            next["items"]
                .as_array()
                .expect("items")
                .iter()
                .map(|e| e["path"].as_str().unwrap_or_default().to_string()),
        );
        cursor = next["next_cursor"].clone();
        pages += 1;
        assert!(pages < 10);
    }
    paths.sort();
    assert_eq!(paths, ["/a", "/a", "/b", "/c"]);

    let (_, offset) = h
        .get(&t, "/analytics/requests?limit=2&offset=2&envelope=1")
        .await;
    assert_eq!(offset["items"].as_array().map(Vec::len), Some(2));
}

#[tokio::test]
async fn bad_analytics_filters_are_rejected_naming_the_parameter() {
    let (h, t) = seeded().await;
    let many: Vec<String> = (0..21).map(|i| format!("s{i}")).collect();
    let too_many = format!("/analytics/summary?site={}", many.join(","));
    for (query, name) in [
        ("/analytics/summary?colour=red".to_string(), "colour"),
        ("/analytics/summary?country=DE".to_string(), "country"),
        (
            "/analytics/summary?window=1h&from=1000".to_string(),
            "window",
        ),
        ("/analytics/summary?to=1000".to_string(), "from"),
        ("/analytics/summary?from=2000&to=1000".to_string(), "from"),
        ("/analytics/summary?from=abc".to_string(), "from"),
        (
            "/analytics/summary?from=0&to=40000000000".to_string(),
            "400 days",
        ),
        (too_many, "site"),
        (
            "/analytics/summary?status_class=9xx".to_string(),
            "status_class",
        ),
        ("/analytics/summary?user_agent=ab".to_string(), "user_agent"),
        (
            "/analytics/summary?client_ip=10.0.0.0/40".to_string(),
            "client_ip",
        ),
        (
            "/analytics/summary?min_bot_score=300".to_string(),
            "min_bot_score",
        ),
        ("/analytics/summary?host=a%00b".to_string(), "host"),
        (
            "/analytics/summary?bot_class=robot".to_string(),
            "bot_class",
        ),
        ("/analytics/summary?blocked=maybe".to_string(), "blocked"),
        (
            "/analytics/summary?window=1h&window=24h".to_string(),
            "window",
        ),
        ("/analytics/timeseries?sort=bytes".to_string(), "sort"),
        ("/analytics/facets?limit=3".to_string(), "limit"),
        (
            "/analytics/requests?limit=5&offset=100001".to_string(),
            "offset",
        ),
        ("/analytics/requests?before_ts=5".to_string(), "before_ts"),
        ("/analytics/requests?envelope=maybe".to_string(), "envelope"),
        (
            "/analytics/requests?envelope=true&window=2w".to_string(),
            "window",
        ),
        ("/analytics/top?kind=paths&sort=weird".to_string(), "sort"),
        (
            "/analytics/top?kind=paths&country=DE".to_string(),
            "country",
        ),
    ] {
        let (status, body) = h.get(&t, &query).await;
        assert_eq!(status, 400, "{query}: {body}");
        let message = body["error"].as_str().unwrap_or_default();
        assert!(message.contains(name), "{query}: {message}");
    }
}
