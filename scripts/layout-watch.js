const fs = require("fs");

const root = "/data";
const violations = "/tmp/cite-layout-violations";
const samples = "/tmp/cite-layout-samples";
const tmpName = /^\..+\.tmp\.\d+\.[0-9a-f]+$/;
const allowedRoot = new Set(["releases", "control", "status", "state"]);
const slotFile = { control: "desired.json", status: "executor.json", state: "state.json" };

let n = 0;

function readNames(dir, bad) {
  try {
    return fs.readdirSync(dir);
  } catch (err) {
    bad.push(String(err));
    return [];
  }
}

function check() {
  n += 1;
  const bad = [];
  for (const name of readNames(root, bad)) {
    if (!allowedRoot.has(name)) bad.push(name);
  }
  for (const name of readNames(`${root}/releases`, bad)) {
    if (name !== "blue" && name !== "green") {
      bad.push(`release ${name}`);
      continue;
    }
    for (const child of readNames(`${root}/releases/${name}`, bad)) {
      if (child !== "app" && child !== "release.json" && !tmpName.test(child)) {
        bad.push(`${name}/${child}`);
      }
    }
  }
  for (const dir of Object.keys(slotFile)) {
    for (const child of readNames(`${root}/${dir}`, bad)) {
      if (child !== slotFile[dir] && !tmpName.test(child)) bad.push(`${dir}/${child}`);
    }
  }
  if (bad.length) fs.appendFileSync(violations, `${bad.join(" ")}\n`);
  fs.writeFileSync(`${samples}.tmp`, String(n));
  fs.renameSync(`${samples}.tmp`, samples);
}

setInterval(check, 20);
check();
