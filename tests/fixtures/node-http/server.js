const http = require("http");
const port = process.env.PORT || 3000;
http
  .createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("node-http " + (process.env.SITE_VERSION || "v1"));
  })
  .listen(port, "127.0.0.1");
