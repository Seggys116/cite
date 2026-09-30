const fs = require("fs");
fs.mkdirSync("dist", { recursive: true });
fs.copyFileSync("index.html", "dist/index.html");
