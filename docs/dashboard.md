# Dashboard

This page covers the web console that manages Cite nodes: what each view does, how it signs in, and how it talks to connectors.

The console source is in `crates/cite-dashboard/web`. The dashboard server that serves these files and relays requests to connectors is described in the last section of [Connector API](node-api.md); its source is not in this repository yet, so no run instructions are given here.

## Signing in

The first visit shows a setup form: a username, a password with confirmation, then a confirmation code from an authenticator app. After that, signing in takes the username, the password and the current six-digit code. The form requires at least 8 characters and shows a strength hint.

The Sign out action in the top bar and the command palette ends the session.

## Nodes

A node is a connector. Add one with a name, its connector URL (for example `https://edge.example.com:8443`) and a connector API token. Create the token with `POST /api/v1/tokens` on the connector, using a session from `POST /api/v1/auth/login`. The token is shown once.

The Nodes view lists the connectors this console manages. A node switcher in the header scopes every other view to one node or to All nodes. Removing a node removes it from the console only; the node keeps serving.

The connector's certificate comes from a self-signed authority created by `init`. The `init` output prints the CA certificate path and its SHA-256 fingerprint; compare the fingerprint before you trust the CA.

## Views

| View | What it shows or does |
|---|---|
| Overview | Health and traffic across every connected node, and recent deployments from all of them. |
| Nodes | Add and remove connectors. |
| Sites | A table of sites with node, kind (site or API), hosts, active slot, health and state. Create site opens the form described below. |
| Site page | Routing, health check settings, a live view of targets in each slot, deploy history, Deploy new version, Switch active slot, Roll back, a maintenance toggle with page choice, and Delete site. |
| Traffic | Requests over time, status classes, methods, latency (average, p50, p95, p99), response sizes, content types, top paths, client IPs, user agents, hosts and blocking rules, and a live request list that refreshes every 3 seconds. A time window selector offers 15 minutes, 1 hour, 24 hours, 7 days and 30 days. |
| Firewall | An ordered list of rules ("evaluated in order; the first match wins" in the UI) with path prefix, host, methods and client address matchers, an action and a scope of one site or all. |
| Maintenance | Custom maintenance pages: a name, a status code and the HTML. |
| Settings | Data retention, connection limits, API tokens, the audit log (most recent 200 entries), the rendered `haproxy.cfg` with process and backend status, and dashboard appearance and session. |

Connection limit changes apply on the next HAProxy reload. The retention form edits the settings described in [Analytics and retention](analytics.md), including the two privacy flags.

A command palette offers shortcuts to views, Create site, Add firewall rule, Add node, switching nodes, toggling the light or dark theme, reloading the view and signing out.

## Creating a site

| Field | Notes |
|---|---|
| Kind | Site or API. APIs usually route by path prefix, sites by host name. |
| Hosts | Host names that route to the site. |
| Path regex | Optional. A built-in tester shows whether the regex is valid and whether a sample path matches. Empty means every path on those hosts. |
| Blue and green targets | `host:port` addresses for each slot. At least one blue target is required. |
| Health check path | Must start with `/`. The form sends an interval of 2000 ms, a timeout of 1500 ms, 2 passes to be healthy and 3 failures to be down. |
| Placement | Selected nodes, or Replicate to all nodes. |

The new site starts with the blue slot active. The form sends one request to the dashboard server with the chosen nodes and the site definition. With Replicate to all nodes the same site is created on every connected node, each with its own targets, so use addresses that mean the same thing on each.

## How the console talks to connectors

The browser only ever talks to the dashboard server's `/api/v1`. The server holds each node's token and forwards `/nodes/{node}/...` to the matching connector route. Other routes handle login (`POST /session`), first-run setup (`POST /setup`, `POST /setup/confirm`), a summary across nodes (`GET /nodes/summary`) and placing a site on several nodes (`POST /deployments` with `mode` of `each` or `replicate`). Details and request shapes are in [Connector API](node-api.md).

Connectors still enforce their own rules: the source allowlist, TLS and token check apply to the dashboard server as they would to any client. See [Security model](security-model.md).
