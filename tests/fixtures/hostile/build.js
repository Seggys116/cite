// Hostile build: records what each attack achieved, leaves a daemon behind, then hangs until the supervisor times out.
const fs = require("fs");
const net = require("net");
const path = require("path");
const { spawn, execFileSync } = require("child_process");

const lines = [];
function note(line) {
  lines.push(line);
  const home = process.env.HOME || process.cwd();
  fs.appendFileSync(path.join(home, "results.txt"), line + "\n");
}

function tryRead(label, file) {
  try {
    fs.readFileSync(file);
    note(label + " READABLE");
  } catch (err) {
    note(label + " DENIED " + err.code);
  }
}

function tryWrite(file) {
  try {
    fs.writeFileSync(file, "pwned");
    note("write " + file + " WROTE");
  } catch (err) {
    note("write " + file + " DENIED " + err.code);
  }
}

function connect(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve("TIMEOUT");
    }, 800);
    socket.on("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      resolve("CONNECTED");
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      resolve("DENIED " + err.code);
    });
  });
}

async function main() {
  if (process.env.CITE_GITHUB_TOKEN === undefined) {
    note("token DENIED absent");
  } else {
    note("token READABLE in env");
  }
  tryRead("proc1", "/proc/1/environ");
  tryRead("mem", "/proc/1/mem");

  const socketResult = await new Promise((resolve) => {
    const socket = net.connect("/run/cite/manager.sock");
    const timer = setTimeout(() => {
      socket.destroy();
      resolve("TIMEOUT");
    }, 800);
    socket.on("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      resolve("CONNECTED");
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      resolve("DENIED " + err.code);
    });
  });
  note("socket " + socketResult);

  try {
    const out = execFileSync("/usr/local/bin/cite-manager", ["__ptrace-probe"], {
      encoding: "utf8",
      timeout: 2000,
    });
    note(out.trim());
  } catch (err) {
    note("ptrace DENIED " + (err.code || err.message));
  }

  tryWrite("/etc/cite-hostile");
  tryWrite("/tmp/cite-hostile");
  tryWrite("/var/lib/cite/releases/cite-hostile");
  tryWrite("/var/lib/cite/state/cite-hostile");
  tryWrite("/var/lib/cite/cache/cite-hostile");

  try {
    fs.symlinkSync("/etc/passwd", "escape");
    note("symlink CREATED");
  } catch (err) {
    note("symlink DENIED " + err.code);
  }
  try {
    fs.linkSync("/etc/passwd", "hardlink");
    note("hardlink CREATED");
  } catch (err) {
    note("hardlink DENIED " + err.code);
  }

  note("metadata " + (await connect("169.254.169.254", 80)));

  const limits = fs.readFileSync("/proc/self/limits", "utf8");
  const nproc = limits.match(/Max processes\s+(\S+)/);
  const fsize = limits.match(/Max file size\s+(\S+)/);
  note("nproc " + (nproc ? nproc[1] : "missing"));
  note("fsize " + (fsize ? fsize[1] : "missing"));

  const kids = [];
  let blocked = false;
  for (let i = 0; i < 600 && !blocked; i++) {
    const child = spawn("/bin/sleep", ["30"], { stdio: "ignore" });
    const failed = await new Promise((resolve) => {
      child.once("error", (err) => resolve(err.code || "error"));
      child.once("spawn", () => resolve(null));
    });
    if (failed) {
      blocked = true;
      note("fork DENIED " + failed);
    } else {
      kids.push(child);
    }
  }
  await Promise.all(
    kids.map(
      (child) =>
        new Promise((resolve) => {
          child.once("exit", resolve);
          child.kill("SIGKILL");
        }),
    ),
  );
  if (!blocked) note("fork STARTED " + kids.length);

  const marker = path.join(process.cwd(), "out-straggler.txt");
  const daemon = await new Promise((resolve, reject) => {
    const child = spawn(
      "/bin/sh",
      ["-c", "while true; do printf x >> \"$1\"; sleep 0.2; done", "sh", marker],
      { detached: true, stdio: "ignore" },
    );
    child.once("error", reject);
    child.once("spawn", () => resolve(child));
  });
  daemon.unref();
  note("straggler " + (daemon.pid || "none"));

  fs.mkdirSync("dist", { recursive: true });
  fs.writeFileSync("dist/index.html", "<html>hostile</html>");
  note("results-ready");
  setInterval(() => {}, 1000);
}

main().catch((err) => {
  note("fixture error " + err.message);
  process.exit(1);
});
