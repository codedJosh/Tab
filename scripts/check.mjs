import { readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const ROOT_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const SERVER_FILE = path.join(ROOT_DIR, "server.mjs");
const FRONTEND_FILE = path.join(ROOT_DIR, "frontend", "index.html");
const REGIONAL_FRONTEND_FILE = path.join(ROOT_DIR, "frontend", "regional-operations.html");
const FRONTEND_SCRIPT_FILE = path.join(ROOT_DIR, "frontend", "app.js");
const LOCAL_FILE = path.join(ROOT_DIR, "index.html");
const REGIONAL_SHARED_MARKERS = [
  "regionalOperations",
  "regionalRole",
  "regionalRegion",
  "regionalBanking",
  "transportRequests",
  "reports",
];

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

function assertFrontendShell(html, label) {
  if (!html.includes('href="styles.css"')) {
    throw new Error(`${label} is missing the styles.css reference.`);
  }
  if (!html.includes('src="app.js"')) {
    throw new Error(`${label} is missing the app.js module reference.`);
  }
}

function checkFrontendShell() {
  const html = readFileSync(FRONTEND_FILE, "utf8");
  assertFrontendShell(html, "frontend/index.html");

  const regionalHtml = readFileSync(REGIONAL_FRONTEND_FILE, "utf8");
  assertFrontendShell(regionalHtml, "frontend/regional-operations.html");
  if (!regionalHtml.includes('window.HUMMINGBIRD_PUBLIC_SCREEN = "regional-operations"')) {
    throw new Error(
      "frontend/regional-operations.html is missing the dedicated regional public screen bootstrap.",
    );
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

function checkRegionalSharedContract() {
  const frontendScript = readFileSync(FRONTEND_SCRIPT_FILE, "utf8");
  const serverScript = readFileSync(SERVER_FILE, "utf8");

  REGIONAL_SHARED_MARKERS.forEach((marker) => {
    if (!frontendScript.includes(marker)) {
      throw new Error(
        `frontend/app.js is missing the shared regional marker "${marker}".`,
      );
    }
    if (!serverScript.includes(marker)) {
      throw new Error(
        `server.mjs is missing the shared regional marker "${marker}".`,
      );
    }
  });

  const frontendRequirements = [
    "normalizeRegionalOperationsState",
    "normalizeRegionalBankingInfo",
    "data-form=\"regional-ops-sign-in\"",
    "data-form=\"submit-regional-funding-request\"",
  ];
  const backendRequirements = [
    "normalizeRegionalOperationsState",
    "normalizeRegionalBankingInfo",
    "invalid_workspace_payload",
    "incomingState.regionalOperations",
  ];

  frontendRequirements.forEach((marker) => {
    if (!frontendScript.includes(marker)) {
      throw new Error(
        `frontend/app.js is missing the regional frontend contract marker "${marker}".`,
      );
    }
  });

  backendRequirements.forEach((marker) => {
    if (!serverScript.includes(marker)) {
      throw new Error(
        `server.mjs is missing the regional backend contract marker "${marker}".`,
      );
    }
  });
}

console.log("Checking server syntax...");
runCheck([SERVER_FILE], "server.mjs");

console.log("Checking frontend shell references...");
checkFrontendShell();

console.log("Checking frontend module syntax...");
runCheck([FRONTEND_SCRIPT_FILE], "frontend/app.js");

console.log("Checking shared frontend/backend regional contract...");
checkRegionalSharedContract();

checkRootLauncher();
console.log("Hummingbird syntax checks passed.");
