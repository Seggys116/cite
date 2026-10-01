const fs = require("fs");
const isNumber = require("is-number");
fs.writeFileSync("banner.txt", "node-ok " + isNumber(5));
