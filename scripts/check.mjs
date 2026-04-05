import { readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const ROOT_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const SERVER_FILE = path.join(ROOT_DIR, "server.mjs");
const FRONTEND_FILE = path.join(ROOT_DIR, "frontend", "index.html");
const FRONTEND_SCRIPT_FILE = path.join(ROOT_DIR, "frontend", "app.js");
const LOCAL_FILE = path.join(ROOT_DIR, "index.html");

function runCheck(args, label) {
  const result = spawnSync(process.execPath, ["--check", ...args], {
    cwd: ROOT_DIR,
    encoding: "utf8",
  });

  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || `${label} failed.\n`);
    process.exit(result.status || 1);
  }
}

function checkFrontendShell() {
  const html = readFileSync(FRONTEND_FILE, "utf8");
  if (!html.includes('href="styles.css"')) {
    throw new Error("frontend/index.html is missing the styles.css reference.");
  }
  if (!html.includes('src="app.js"')) {
    throw new Error("frontend/index.html is missing the app.js module reference.");
  }
}

function checkRootLauncher() {
  const local = readFileSync(LOCAL_FILE, "utf8");

  if (local.includes('<script type="module">') || local.length > 15000) {
    console.warn(
      [
        "Warning: root index.html looks too large to be a simple launcher.",
        "frontend/index.html is the live website source of truth.",
        "Keep the root index as a thin local launcher rather than a second application copy.",
      ].join("\n"),
    );
  }
}

console.log("Checking server syntax...");
runCheck([SERVER_FILE], "server.mjs");

console.log("Checking frontend shell references...");
checkFrontendShell();

console.log("Checking frontend module syntax...");
runCheck([FRONTEND_SCRIPT_FILE], "frontend/app.js");

checkRootLauncher();
console.log("Hummingbird syntax checks passed.");
