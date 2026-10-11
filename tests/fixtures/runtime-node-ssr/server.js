const http = require("http");
const fs = require("fs");
const banner = fs.readFileSync("banner.txt", "utf8");
http
  .createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<html>" + banner + " " + process.version + "</html>\n");
  })
  .listen(Number(process.env.PORT), "127.0.0.1");
