const fs = require("fs");
const isNumber = require("is-number");
fs.mkdirSync("dist", { recursive: true });
fs.writeFileSync("dist/index.html", "<html>yarn-ok " + isNumber(5) + "</html>\n");
