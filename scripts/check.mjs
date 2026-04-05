import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const ROOT_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const SERVER_FILE = path.join(ROOT_DIR, "server.mjs");
const FRONTEND_FILE = path.join(ROOT_DIR, "frontend", "index.html");
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

function extractFrontendModule() {
  const html = readFileSync(FRONTEND_FILE, "utf8");
  const marker = '<script type="module">';
  const start = html.indexOf(marker);
  const end = html.lastIndexOf("</script>");

  if (start < 0 || end < 0 || end <= start) {
    throw new Error("Could not extract the frontend module script from frontend/index.html.");
  }

  const tempDir = mkdtempSync(path.join(tmpdir(), "hummingbird-check-"));
  const tempFile = path.join(tempDir, "frontend-script.js");
  writeFileSync(tempFile, html.slice(start + marker.length, end), "utf8");
  return { tempDir, tempFile };
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

console.log("Checking frontend module syntax...");
const { tempDir, tempFile } = extractFrontendModule();
try {
  runCheck([tempFile], "frontend/index.html script");
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}

checkRootLauncher();
console.log("Hummingbird syntax checks passed.");
