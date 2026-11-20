// Fixture for scripts/e2e-data.sh. It writes a row through DATABASE_URL and reads it back over HTTP.
//
// /__env hands out a few connection strings so the test harness can reach the databases as the app does. That is
// test-only: the product never returns a password, and a real site must not expose its environment.
const { SQL } = Bun;

const EXPOSED = new Set(["DATABASE_URL", "RO_DATABASE_URL", "EXT_DATABASE_URL"]);

function open(name) {
  const url = process.env[name];
  if (!url) return null;
  // Every field is taken from the URL: Bun lets PG* variables (set here by the Generic preset for the site's own
  // database) fill fields over a URL, which would point a second database's URL at the wrong database.
  const u = new URL(url);
  return new SQL({
    hostname: u.hostname.replace(/^\[|\]$/g, ""),
    port: Number(u.port || 5432),
    database: decodeURIComponent(u.pathname.slice(1)),
    username: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    tls: ["require", "verify-ca", "verify-full"].includes(u.searchParams.get("sslmode")),
    max: 3,
    idleTimeout: 30,
    connectionTimeout: 5,
  });
}

const rw = open("DATABASE_URL");
const ro = open("RO_DATABASE_URL");
const ext = open("EXT_DATABASE_URL");

const text = (body, status = 200) => new Response(body, { status, headers: { "content-type": "text/plain" } });

async function handle(req) {
  const url = new URL(req.url);
  const path = url.pathname;
  if (path === "/" || path === "/health") return text("ok");
  if (path === "/__env") {
    const name = url.searchParams.get("name") ?? "";
    if (!EXPOSED.has(name) || process.env[name] === undefined) return text("not set", 404);
    return text(process.env[name]);
  }
  if (path === "/ext/count") {
    if (!ext) return text("EXT_DATABASE_URL is not set", 503);
    const [row] = await ext`select count(*)::int as n from ext_items`;
    return text(String(row.n));
  }
  if (!rw) return text("DATABASE_URL is not set", 503);
  if (path === "/ping") {
    await rw`select 1`;
    return text("pong");
  }
  if (path === "/notes/count") {
    const [row] = await rw`select count(*)::int as n from notes`;
    return text(String(row.n));
  }
  if (path === "/ro/count") {
    if (!ro) return text("RO_DATABASE_URL is not set", 503);
    const [row] = await ro`select count(*)::int as n from notes`;
    return text(String(row.n));
  }
  if (path === "/notes" && req.method === "POST") {
    const body = (await req.text()) || "note";
    const [row] = await rw`insert into notes (body) values (${body}) returning id`;
    return text(JSON.stringify({ id: row.id, body }));
  }
  if (path === "/notes" && req.method === "DELETE") {
    await rw`delete from notes`;
    return text("deleted");
  }
  return text("not found", 404);
}

Bun.serve({
  port: Number(process.env.PORT),
  hostname: "127.0.0.1",
  fetch: async (req) => {
    try {
      return await handle(req);
    } catch (e) {
      return text("error: " + (e && e.message ? e.message : String(e)), 500);
    }
  },
});
