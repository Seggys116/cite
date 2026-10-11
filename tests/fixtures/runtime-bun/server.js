const banner = await Bun.file("banner.txt").text();
Bun.serve({
  port: Number(process.env.PORT),
  hostname: "127.0.0.1",
  fetch: () => new Response("<html>" + banner + " " + Bun.version + "</html>\n", { headers: { "content-type": "text/html" } }),
});
