const isNumber = require("is-number");
await Bun.write("banner.txt", "bun-ok " + isNumber(5));
