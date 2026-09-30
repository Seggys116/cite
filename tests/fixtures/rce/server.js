// Deliberately vulnerable SSR fixture ; the only attack surface is eval.
const http = require("http");

function finish(res, text) {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end(String(text));
}

http
  .createServer((req, res) => {
    if (req.url === "/health") {
      finish(res, "ok");
      return;
    }
    if (req.url !== "/eval") {
      finish(res, "cite-rce");
      return;
    }
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const code = Buffer.concat(chunks).toString("utf8");
      try {
        const value = eval(code);
        const send = (out) => finish(res, out);
        if (value && typeof value.then === "function") {
          value.then(send, (err) => finish(res, "ERR " + (err.code || "") + " " + err.message));
        } else {
          send(value);
        }
      } catch (err) {
        finish(res, "ERR " + (err.code || "") + " " + err.message);
      }
    });
  })
  .listen(process.env.PORT || 3000, "127.0.0.1");
