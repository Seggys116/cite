const http = require("http");
if (process.env.CRASH_IMMEDIATELY === "1") {
  process.exit(1);
}
const port = process.env.PORT || 3000;
http
  .createServer((req, res) => {
    if (req.url.startsWith("/crash")) process.exit(1);
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  })
  .listen(port, "127.0.0.1");
