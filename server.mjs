import { publicWorkspace, applyPrivateEntryCommand, judgeWorkspace, memberWorkspace } from "./frontend/public-workspace.js";
import { applyTournamentChanges } from "./frontend/tournament-patch.js";
import { registrationTeamSize } from "./frontend/tournament-rules.js";
import { evaluateDrawEntryConflicts } from "./frontend/draw-integrity.js";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import compression from "compression";
import dotenv from "dotenv";
import express from "express";
import { Pool } from "pg";
import sharp from "sharp";

dotenv.config();

const PORT = Number(process.env.PORT || 8787);
const DATABASE_URL = String(process.env.DATABASE_URL || "").trim();
const DATABASE_SSL = String(process.env.DATABASE_SSL || "").trim().toLowerCase();
const JADE_SESSION_SECRET = String(process.env.JADE_SESSION_SECRET || "").trim();
const RESEND_API_KEY = String(process.env.RESEND_API_KEY || "").trim();
const RESEND_FROM_EMAIL = String(process.env.RESEND_FROM_EMAIL || "").trim();
const RESEND_REPLY_TO =
  String(process.env.RESEND_REPLY_TO || "").trim() || "hummingbird@myjade.org";
const PUBLIC_APP_URL = String(process.env.PUBLIC_APP_URL || "").trim();
const DEFAULT_PUBLIC_APP_URL = "https://www.jadehummingbird.org";
const PRIVATE_LINK_EMAIL_COOLDOWN_MINUTES = Math.max(
  0,
  Number(process.env.PRIVATE_LINK_EMAIL_COOLDOWN_MINUTES || 10) || 10,
);
const PRIVATE_LINK_EMAIL_COOLDOWN_MS = PRIVATE_LINK_EMAIL_COOLDOWN_MINUTES * 60 * 1000;
const PASSWORD_RESET_EXPIRY_MINUTES = Math.max(
  10,
  Number(process.env.PASSWORD_RESET_EXPIRY_MINUTES || 60) || 60,
);
const PASSWORD_RESET_EXPIRY_MS = PASSWORD_RESET_EXPIRY_MINUTES * 60 * 1000;
const WORKSPACE_ID = String(process.env.JADE_WORKSPACE_ID || "primary").trim() || "primary";
const WORKSPACE_CONTRACT_VERSION = "2026-04-05-ironclad";
const REQUIRED_WORKSPACE_ROOT_KEYS = [
  "workspaceContractVersion",
  "version",
  "appSettings",
  "users",
  "recoveryRequests",
  "tournaments",
  "regionalOperations",
];
const REQUIRED_REGIONAL_OPERATIONS_KEYS = ["reports", "transportRequests"];
const REQUIRED_USER_CONTRACT_KEYS = [
  "email",
  "regionalRole",
  "regionalRegion",
  "regionalBanking",
  "registeredTournamentIds",
  "pinnedTournamentIds",
];

const REGIONAL_OPERATIONS_ROLE_VALUES = new Set([
  "regional_coordinator",
  "deputy_regional_coordinator",
  "membership_experience_specialist",
  "regional_development_manager",
  "deputy_regional_development_manager",
  "tertiary_development_specialist",
]);
const DEFAULT_BRANDING = {
  appName: "JADE Hummingbird",
  subtitle:
    "Premium tournament operations, controlled publishing, and calm competitor access in one place.",
  accent: "#1f6a4e",
  accentDeep: "#123f2f",
};
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const configuredFrontendDir = String(process.env.FRONTEND_DIR || "").trim();
const FRONTEND_DIR = configuredFrontendDir
  ? path.resolve(configuredFrontendDir)
  : [
      path.join(__dirname, "frontend"),
      __dirname,
      path.join(__dirname, "..", "frontend"),
      path.join(__dirname, ".."),
    ].find((candidate) => fs.existsSync(path.join(candidate, "index.html"))) || __dirname;
const FRONTEND_ENTRY = path.join(FRONTEND_DIR, "index.html");

const MANAGER_EMAIL = "joshuaatkins374@gmail.com";
const REGIONAL_OPERATION_REGIONS = [
  "Region 1",
  "Region 2",
  "Region 3",
  "Region 4",
  "Region 5",
  "Region 6",
];
const JAMAICA_PARISHES = [
  "Kingston",
  "St. Andrew",
  "St. Thomas",
  "Portland",
  "St. Mary",
  "St. Ann",
  "Trelawny",
  "St. James",
  "Hanover",
  "Westmoreland",
  "St. Elizabeth",
  "Manchester",
  "Clarendon",
  "St. Catherine",
];
const JAMAICA_MAJOR_BANKS = [
  "NCB",
  "Scotiabank Jamaica",
  "JN Bank",
  "CIBC Caribbean",
  "Sagicor Bank Jamaica",
  "JMMB Bank",
  "First Global Bank",
  "VM Building Society",
];
const REGIONAL_BANK_ACCOUNT_TYPES = ["chequing", "savings"];
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 14;
const WORKSPACE_HISTORY_INTERVAL = Math.max(
  1,
  Number(process.env.WORKSPACE_HISTORY_INTERVAL || 25) || 25,
);
const WORKSPACE_HISTORY_LIMIT = Math.max(
  5,
  Number(process.env.WORKSPACE_HISTORY_LIMIT || 10) || 10,
);
const PASSWORD_HASH_VERSION = "pbkdf2-sha256-v1";
const PASSWORD_HASH_ITERATIONS = 210000;
const PASSWORD_SALT_BYTES = 16;
const MAX_BODY_SIZE = process.env.MAX_BODY_SIZE || "30mb";
const API_CONCURRENCY = Math.max(
  1,
  Number(process.env.API_CONCURRENCY || 2) || 2,
);
const API_QUEUE_LIMIT = Math.max(
  API_CONCURRENCY,
  Number(process.env.API_QUEUE_LIMIT || 24) || 24,
);
const SLOW_REQUEST_MS = Math.max(
  500,
  Number(process.env.SLOW_REQUEST_MS || 2500) || 2500,
);
const MEMORY_WARNING_MB = Math.max(
  128,
  Number(process.env.MEMORY_WARNING_MB || 400) || 400,
);
const EMBEDDED_IMAGE_COMPACT_THRESHOLD_BYTES = Math.max(
  256 * 1024,
  Number(process.env.EMBEDDED_IMAGE_COMPACT_THRESHOLD_BYTES || 750 * 1024) ||
    750 * 1024,
);
const TOURNAMENT_BANNER_MAX_WIDTH = 1600;
const TOURNAMENT_BANNER_MAX_HEIGHT = 600;
const PRIORITY_API_ACTIONS = new Set(["sign_in", "access_link"]);
const TOURNAMENT_PERMISSION_KEYS = [
  "managerEmails",
  "tabManagerEmails",
  "tabDirectorEmails",
  "caTeamEmails",
  "tournamentDirectorEmails",
  "convenorEmails",
  "registrationOfficerEmails",
  "financeOfficerEmails",
  "equityOfficerEmails",
  "judgeEmails",
  "debaterEmails",
];

function parseDatabaseUrl() {
  try {
    return new URL(DATABASE_URL);
  } catch (_error) {
    return null;
  }
}

const parsedDatabaseUrl = parseDatabaseUrl();
const databaseHostname = String(parsedDatabaseUrl?.hostname || "").trim().toLowerCase();
const hasDatabaseSslMode = Boolean(parsedDatabaseUrl?.searchParams?.has("sslmode"));

if (!DATABASE_URL) {
  throw new Error("Missing DATABASE_URL for JADE backend.");
}

if (!JADE_SESSION_SECRET) {
  throw new Error("Missing JADE_SESSION_SECRET for JADE backend.");
}

const isLocalDatabaseHost = /^(localhost|127\.0\.0\.1|::1)$/.test(databaseHostname);
const isLikelyPrivateDatabaseHost =
  Boolean(databaseHostname) &&
  (!databaseHostname.includes(".") ||
    databaseHostname.endsWith(".internal") ||
    databaseHostname.endsWith(".local"));

const shouldAutoUseSsl =
  !hasDatabaseSslMode && !isLocalDatabaseHost && !isLikelyPrivateDatabaseHost;

function buildPoolConfig() {
  const config = {
    connectionString: DATABASE_URL,
    max: Math.max(2, Number(process.env.DATABASE_POOL_MAX || 4) || 4),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    keepAlive: true,
  };

  if (DATABASE_SSL === "true") {
    config.ssl = { rejectUnauthorized: false };
  } else if (DATABASE_SSL === "false") {
    config.ssl = false;
  } else if (shouldAutoUseSsl) {
    config.ssl = { rejectUnauthorized: false };
  }

  return config;
}

const pool = new Pool(buildPoolConfig());

pool.on("error", (error) => {
  // A dropped idle connection should be replaced by the pool, not terminate Node.
  console.error("Postgres pool connection error:", error);
});

function parseImageDataUrl(value) {
  const match = /^data:(image\/[a-z0-9.+-]+);base64,(.+)$/is.exec(
    String(value || "").trim(),
  );
  if (!match) {
    return null;
  }
  try {
    return {
      mimeType: match[1].toLowerCase(),
      buffer: Buffer.from(match[2], "base64"),
    };
  } catch (_error) {
    return null;
  }
}

async function compactTournamentBannerDataUrl(value) {
  const parsed = parseImageDataUrl(value);
  if (!parsed || parsed.buffer.length < EMBEDDED_IMAGE_COMPACT_THRESHOLD_BYTES) {
    return null;
  }

  const optimized = await sharp(parsed.buffer)
    .rotate()
    .resize({
      width: TOURNAMENT_BANNER_MAX_WIDTH,
      height: TOURNAMENT_BANNER_MAX_HEIGHT,
      fit: "inside",
      withoutEnlargement: true,
    })
    .webp({ quality: 78, effort: 4 })
    .toBuffer();

  if (optimized.length >= parsed.buffer.length) {
    return null;
  }
  return {
    dataUrl: `data:image/webp;base64,${optimized.toString("base64")}`,
    beforeBytes: parsed.buffer.length,
    afterBytes: optimized.length,
  };
}

async function compactOversizedEmbeddedAssets() {
  const client = await pool.connect();
  try {
    const workspace = await readWorkspaceRecord(client);
    if (!workspace?.state) {
      return;
    }

    let changed = 0;
    let beforeBytes = 0;
    let afterBytes = 0;
    for (const tournament of workspace.state.tournaments || []) {
      const compacted = await compactTournamentBannerDataUrl(tournament.bannerImage);
      if (!compacted) {
        continue;
      }
      tournament.bannerImage = compacted.dataUrl;
      changed += 1;
      beforeBytes += compacted.beforeBytes;
      afterBytes += compacted.afterBytes;
    }

    if (!changed) {
      return;
    }

    await writeWorkspaceState(client, workspace.state, {
      expectedRevision: workspace.revision,
      normalized: true,
      clone: false,
      returnState: false,
    });
    console.log("Compacted embedded tournament banners", {
      changed,
      beforeMb: Math.round((beforeBytes / 1024 / 1024) * 10) / 10,
      afterMb: Math.round((afterBytes / 1024 / 1024) * 10) / 10,
    });
  } finally {
    client.release();
  }
}

async function ensureStorageSchema() {
  const client = await pool.connect();
  try {
    await client.query(`
      create table if not exists jade_workspaces (
        id text primary key,
        state jsonb not null,
        revision bigint not null default 1,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
      )
    `);
    await client.query(`
      create index if not exists jade_workspaces_updated_at_idx
      on jade_workspaces (updated_at desc)
    `);
    await client.query(`
      alter table jade_workspaces
      add column if not exists revision bigint not null default 1
    `);
    await client.query(`
      create table if not exists jade_workspace_history (
        workspace_id text not null references jade_workspaces(id) on delete cascade,
        revision bigint not null,
        state jsonb not null,
        created_at timestamptz not null default now(),
        primary key (workspace_id, revision)
      )
    `);
    await client.query(`
      create index if not exists jade_workspace_history_workspace_idx
      on jade_workspace_history (workspace_id, revision desc)
    `);
    await client.query(`
      create table if not exists jade_sessions (
        id text primary key,
        workspace_id text not null references jade_workspaces(id) on delete cascade,
        email text not null,
        token_hash text not null unique,
        created_at timestamptz not null default now(),
        expires_at timestamptz not null
      )
    `);
    await client.query("alter table jade_sessions add column if not exists access_scope jsonb");
    await client.query(`
      create index if not exists jade_sessions_workspace_idx
      on jade_sessions (workspace_id)
    `);
    await client.query(`
      create index if not exists jade_sessions_email_idx
      on jade_sessions (email)
    `);
    await client.query(`
      create index if not exists jade_sessions_expires_idx
      on jade_sessions (expires_at)
    `);
    await client.query("delete from jade_sessions where expires_at <= now()");
    await client.query(
      `
        delete from jade_workspace_history history
        where history.workspace_id = $1
          and history.revision not in (
            select revision
            from jade_workspace_history
            where workspace_id = $1
            order by revision desc
            limit $2
          )
      `,
      [WORKSPACE_ID, WORKSPACE_HISTORY_LIMIT],
    );
  } finally {
    client.release();
  }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function normalizeWorkspaceRevision(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? Math.round(numeric) : 0;
}

function nowText() {
  return new Date().toLocaleString("en-US", {
    timeZone: "America/Jamaica",
  });
}

function normalizeEmail(value = "") {
  return String(value || "").trim().toLowerCase();
}

function shouldResetLegacyBrandingName(value = "") {
  const normalized = normalizeTextKey(value);
  return (
    normalized === "debatetab command" ||
    normalized === "jade debate tab" ||
    normalized === "hummingbird tab system" ||
    normalized === "jade corporate tab" ||
    normalized === "corporate tab" ||
    normalized === "jade corporate tab system" ||
    normalized.includes("corporate tab")
  );
}

function normalizeBrandingSettings(record = {}) {
  const next = {
    ...DEFAULT_BRANDING,
    ...(record && typeof record === "object" ? record : {}),
  };

  if (shouldResetLegacyBrandingName(next.appName)) {
    next.appName = DEFAULT_BRANDING.appName;
  }

  if (
    String(next.subtitle || "").trim() ===
      "Professional debate tournament operations, permissions, publishing, and private access." ||
    String(next.subtitle || "").trim() ===
      "Advanced debate tournament operations, access control, and publishing."
  ) {
    next.subtitle = DEFAULT_BRANDING.subtitle;
  }

  if (String(next.accent || "").trim() === "#a33a2b") {
    next.accent = DEFAULT_BRANDING.accent;
  }

  if (String(next.accent || "").trim() === "#163b6d") {
    next.accent = DEFAULT_BRANDING.accent;
  }

  if (String(next.accentDeep || "").trim() === "#7b251a") {
    next.accentDeep = DEFAULT_BRANDING.accentDeep;
  }

  if (String(next.accentDeep || "").trim() === "#0b274d") {
    next.accentDeep = DEFAULT_BRANDING.accentDeep;
  }

  return next;
}

function createWorkspaceContractError(context = "workspace", detail = "") {
  const error = new Error(
    "JADE Hummingbird rejected a workspace payload because the live data contract did not match the current system" +
      (detail ? ": " + detail : "."),
  );
  error.statusCode = 409;
  error.code = "workspace_contract_mismatch";
  error.context = context;
  return error;
}

function assertWorkspaceContract(candidate, context = "workspace", options = {}) {
  const allowMissingVersion = options.allowMissingVersion === true;
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw createWorkspaceContractError(context, "workspace data was not an object");
  }

  REQUIRED_WORKSPACE_ROOT_KEYS.forEach((key) => {
    if (allowMissingVersion && key === "workspaceContractVersion") {
      return;
    }
    if (!Object.prototype.hasOwnProperty.call(candidate, key)) {
      throw createWorkspaceContractError(context, `missing "${key}"`);
    }
  });

  const contractVersion = String(candidate.workspaceContractVersion || "").trim();
  if (
    (!allowMissingVersion || contractVersion) &&
    contractVersion !== WORKSPACE_CONTRACT_VERSION
  ) {
    throw createWorkspaceContractError(
      context,
      `expected contract ${WORKSPACE_CONTRACT_VERSION} but received ${contractVersion || "none"}`,
    );
  }

  if (!Array.isArray(candidate.users)) {
    throw createWorkspaceContractError(context, "users must be an array");
  }
  if (!Array.isArray(candidate.tournaments)) {
    throw createWorkspaceContractError(context, "tournaments must be an array");
  }
  if (!Array.isArray(candidate.recoveryRequests)) {
    throw createWorkspaceContractError(context, "recoveryRequests must be an array");
  }

  const regionalOperations = candidate.regionalOperations;
  if (
    !regionalOperations ||
    typeof regionalOperations !== "object" ||
    Array.isArray(regionalOperations)
  ) {
    throw createWorkspaceContractError(context, "regional operations state was invalid");
  }

  REQUIRED_REGIONAL_OPERATIONS_KEYS.forEach((key) => {
    if (!Array.isArray(regionalOperations[key])) {
      throw createWorkspaceContractError(
        context,
        `regionalOperations.${key} must be an array`,
      );
    }
  });

  const seenEmails = new Set();
  candidate.users.forEach((user, index) => {
    if (!user || typeof user !== "object" || Array.isArray(user)) {
      throw createWorkspaceContractError(context, `user ${index + 1} was invalid`);
    }
    REQUIRED_USER_CONTRACT_KEYS.forEach((key) => {
      if (!Object.prototype.hasOwnProperty.call(user, key)) {
        throw createWorkspaceContractError(
          context,
          `user ${index + 1} is missing "${key}"`,
        );
      }
    });
    const email = normalizeEmail(user.email);
    if (!email) {
      throw createWorkspaceContractError(context, `user ${index + 1} is missing an email`);
    }
    if (seenEmails.has(email)) {
      throw createWorkspaceContractError(context, `duplicate user email "${email}"`);
    }
    seenEmails.add(email);
  });

  const seenTournamentIds = new Set();
  candidate.tournaments.forEach((tournament, index) => {
    if (!tournament || typeof tournament !== "object" || Array.isArray(tournament)) {
      throw createWorkspaceContractError(context, `tournament ${index + 1} was invalid`);
    }
    const id = String(tournament.id || "").trim();
    if (!id) {
      throw createWorkspaceContractError(context, `tournament ${index + 1} is missing an id`);
    }
    if (seenTournamentIds.has(id)) {
      throw createWorkspaceContractError(context, `duplicate tournament id "${id}"`);
    }
    seenTournamentIds.add(id);
  });

  return candidate;
}

function normalizeGlobalRole(value = "member") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replaceAll(" ", "_")
    .replaceAll("-", "_");

  if (["system_admin", "system_manager", "admin", "administrator"].includes(normalized)) {
    return "system_admin";
  }

  if (normalized === "manager") {
    return "manager";
  }

  return "member";
}

function normalizeRegionalOperationsRole(value = "") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replaceAll(" ", "_")
    .replaceAll("-", "_");

  if (REGIONAL_OPERATIONS_ROLE_VALUES.has(normalized)) return normalized;

  return "";
}

function createId(prefix) {
  return prefix + "-" + crypto.randomBytes(4).toString("hex");
}

function normalizeTimestampKey(value, fallbackText = "") {
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 0) {
    return Math.round(numeric);
  }
  const parsed = Date.parse(String(fallbackText || "").trim());
  return Number.isFinite(parsed) && parsed > 0 ? parsed : Date.now();
}

function normalizeOptionalTimestampKey(value, fallbackText = "") {
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 0) {
    return Math.round(numeric);
  }
  const parsed = Date.parse(String(fallbackText || "").trim());
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function normalizeStringList(value, max = 200) {
  if (!Array.isArray(value)) {
    return [];
  }

  return Array.from(
    new Set(
      value
        .map((item) => String(item || "").trim())
        .filter(Boolean),
    ),
  ).slice(0, max);
}

function normalizePrivateAccessEmailEvents(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }

  return Object.entries(value).reduce((events, [rawKey, rawTimestamp]) => {
    const key = String(rawKey || "").trim().toLowerCase();
    if (!key) {
      return events;
    }

    const numeric = Number(rawTimestamp);
    if (Number.isFinite(numeric) && numeric > 0) {
      events[key] = Math.round(numeric);
      return events;
    }

    const parsed = Date.parse(String(rawTimestamp || "").trim());
    if (Number.isFinite(parsed) && parsed > 0) {
      events[key] = Math.round(parsed);
    }
    return events;
  }, {});
}

function normalizePermissionEmailList(value = [], max = 400) {
  return normalizeStringList(
    (Array.isArray(value) ? value : [])
      .map((entry) => normalizeEmail(entry))
      .filter(Boolean),
    max,
  );
}

function normalizeTournamentPermissions(record = {}) {
  const next = record && typeof record === "object" ? clone(record) : {};
  TOURNAMENT_PERMISSION_KEYS.forEach((key) => {
    next[key] = normalizePermissionEmailList(
      next[key],
      key === "debaterEmails" ? 800 : 400,
    );
  });
  return next;
}

function normalizeTextKey(value = "") {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function normalizeRegionalRegion(value = "") {
  const raw = String(value || "").trim();
  if (!raw) {
    return "";
  }

  const normalized = normalizeTextKey(raw);
  const matchedRegion = REGIONAL_OPERATION_REGIONS.find(
    (region, index) =>
      normalizeTextKey(region) === normalized ||
      String(index + 1) === normalized ||
      normalizeTextKey("Region " + (index + 1)) === normalized,
  );

  return matchedRegion || raw;
}

function normalizeRegionalParish(value = "") {
  const raw = String(value || "").trim();
  if (!raw) {
    return "";
  }
  const normalized = normalizeTextKey(raw);
  const matched = JAMAICA_PARISHES.find((parish) => normalizeTextKey(parish) === normalized);
  return matched || raw;
}

function normalizeRegionalBankAccountType(value = "") {
  const normalized = normalizeTextKey(value);
  if (["chequing", "checking", "current"].includes(normalized)) {
    return "chequing";
  }
  if (normalized === "saving") {
    return "savings";
  }
  if (REGIONAL_BANK_ACCOUNT_TYPES.includes(normalized)) {
    return normalized;
  }
  return "";
}

function createTemporaryRegistrationPassword() {
  return crypto.randomBytes(24).toString("base64url");
}

function createPasswordSalt() {
  return crypto.randomBytes(PASSWORD_SALT_BYTES).toString("hex");
}

function deriveSecurePasswordHash(password, salt, iterations = PASSWORD_HASH_ITERATIONS) {
  return crypto
    .pbkdf2Sync(
      Buffer.from(String(password || ""), "utf8"),
      Buffer.from(String(salt || ""), "hex"),
      Number(iterations) || PASSWORD_HASH_ITERATIONS,
      32,
      "sha256",
    )
    .toString("hex");
}

function hashLegacyPassword(password) {
  return crypto.createHash("sha256").update(String(password || ""), "utf8").digest("hex");
}

function buildSecurePasswordRecord(password) {
  const passwordSalt = createPasswordSalt();
  return {
    passwordHash: deriveSecurePasswordHash(password, passwordSalt),
    passwordSalt,
    passwordIterations: PASSWORD_HASH_ITERATIONS,
    passwordVersion: PASSWORD_HASH_VERSION,
  };
}

function hasSecurePasswordRecord(user = {}) {
  return (
    String(user.passwordVersion || "").trim() === PASSWORD_HASH_VERSION &&
    /^[a-f0-9]{16,}$/i.test(String(user.passwordSalt || "").trim())
  );
}

function verifyUserPassword(user = {}, password = "") {
  if (hasSecurePasswordRecord(user)) {
    const computedHash = deriveSecurePasswordHash(
      password,
      user.passwordSalt,
      user.passwordIterations,
    );
    return {
      ok: computedHash === user.passwordHash,
      needsUpgrade: false,
    };
  }

  const legacyHash = hashLegacyPassword(password);
  const matches = legacyHash === String(user.passwordHash || "");
  return {
    ok: matches,
    needsUpgrade: matches,
  };
}

function normalizeRegionalReportEntry(entry = {}) {
  const createdAt = String(entry.createdAt || nowText()).trim();
  const reportDate = String(entry.reportDate || entry.reportingWindowEnd || "").trim();
  return {
    id: String(entry.id || createId("regional-report")).trim(),
    region: normalizeRegionalRegion(entry.region),
    school: String(entry.school || entry.schoolName || "").trim(),
    reportDate,
    reportingWindowStart: String(entry.reportingWindowStart || "").trim(),
    reportingWindowEnd: String(entry.reportingWindowEnd || reportDate).trim(),
    summary: String(entry.summary || "").trim(),
    highlights: String(entry.highlights || "").trim(),
    challenges: String(entry.challenges || "").trim(),
    supportNeeded: String(entry.supportNeeded || "").trim(),
    jadeSupport: String(entry.jadeSupport || entry.supportNeeded || "").trim(),
    additionalNotes: String(entry.additionalNotes || "").trim(),
    experienceRating: Math.max(0, Math.min(10, Number(entry.experienceRating || 0) || 0)),
    submittedByEmail: normalizeEmail(entry.submittedByEmail || entry.authorEmail),
    submittedByName: String(entry.submittedByName || entry.authorName || "").trim(),
    submittedByRole: normalizeRegionalOperationsRole(
      entry.submittedByRole || entry.authorRole,
    ),
    createdAt,
    createdAtKey: normalizeTimestampKey(entry.createdAtKey, createdAt),
  };
}

function normalizeRegionalFundingStatus(value = "pending") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replaceAll(" ", "_")
    .replaceAll("-", "_");

  if (["approved", "rejected", "paid"].includes(normalized)) {
    return normalized;
  }

  return "pending";
}

function normalizeRegionalBankingInfo(record = {}) {
  const next = record && typeof record === "object" ? record : {};
  const normalizedBank = String(next.bankName || next.bank || "").trim();
  const knownBank =
    JAMAICA_MAJOR_BANKS.find(
      (bank) => normalizeTextKey(bank) === normalizeTextKey(normalizedBank),
    ) || normalizedBank;

  return {
    bankName: knownBank,
    accountType: normalizeRegionalBankAccountType(
      next.accountType || next.account_kind || next.type,
    ),
    accountName: String(
      next.accountName || next.accountHolderName || next.accountHolder || "",
    ).trim(),
    accountNumber: String(next.accountNumber || next.accountNo || "").trim(),
    branchName: String(next.branchName || next.branch || "").trim(),
  };
}

function normalizeRegionalFundingRequestEntry(entry = {}) {
  const createdAt = String(entry.createdAt || nowText()).trim();
  const normalizedBank = String(entry.bankName || entry.bank || "").trim();
  const knownBank =
    JAMAICA_MAJOR_BANKS.find(
      (bank) => normalizeTextKey(bank) === normalizeTextKey(normalizedBank),
    ) || normalizedBank;

  return {
    id: String(entry.id || createId("regional-funding")).trim(),
    region: normalizeRegionalRegion(entry.region),
    school: String(entry.school || entry.schoolName || "").trim(),
    tripDate: String(entry.tripDate || "").trim(),
    amountJmd: Math.max(0, Number(entry.amountJmd || entry.amount || 0) || 0),
    categories: Array.from(
      new Set(
        (Array.isArray(entry.categories) ? entry.categories : [])
          .map((value) => String(value || "").trim())
          .filter(Boolean),
      ),
    ),
    otherCategoryText: String(entry.otherCategoryText || "").trim(),
    amountOrItemRequired: String(entry.amountOrItemRequired || "").trim(),
    bankName: knownBank,
    accountType: normalizeRegionalBankAccountType(
      entry.accountType || entry.account_kind || entry.type,
    ),
    accountName: String(
      entry.accountName || entry.accountHolderName || entry.accountHolder || "",
    ).trim(),
    accountNumber: String(entry.accountNumber || entry.accountNo || "").trim(),
    branchName: String(entry.branchName || entry.branch || "").trim(),
    justification: String(entry.justification || "").trim(),
    status: normalizeRegionalFundingStatus(entry.status),
    managerNote: String(entry.managerNote || "").trim(),
    submittedByEmail: normalizeEmail(entry.submittedByEmail || entry.authorEmail),
    submittedByName: String(entry.submittedByName || entry.authorName || "").trim(),
    submittedByRole: normalizeRegionalOperationsRole(
      entry.submittedByRole || entry.authorRole,
    ),
    reviewedByEmail: normalizeEmail(entry.reviewedByEmail || ""),
    reviewedAt: String(entry.reviewedAt || "").trim(),
    createdAt,
    createdAtKey: normalizeTimestampKey(entry.createdAtKey, createdAt),
  };
}

function normalizeRegionalContactEntry(entry = {}) {
  const createdAt = String(entry.createdAt || nowText()).trim();
  return {
    id: String(entry.id || createId("regional-contact")).trim(),
    region: normalizeRegionalRegion(entry.region),
    contactName: String(entry.contactName || entry.name || "").trim(),
    institution: String(entry.institution || entry.affiliation || "").trim(),
    role: String(entry.role || "").trim(),
    email: normalizeEmail(entry.email),
    phoneNumber: String(entry.phoneNumber || entry.phone || "").trim(),
    createdByName: String(entry.createdByName || "").trim(),
    createdByEmail: normalizeEmail(entry.createdByEmail),
    createdAt,
    createdAtKey: normalizeTimestampKey(entry.createdAtKey, createdAt),
  };
}

function normalizeRegionalWorkshopResourceEntry(entry = {}) {
  const createdAt = String(entry.createdAt || nowText()).trim();
  return {
    id: String(entry.id || createId("regional-workshop-resource")).trim(),
    title: String(entry.title || "").trim(),
    description: String(entry.description || "").trim(),
    fileName: String(entry.fileName || "").trim(),
    fileType: String(entry.fileType || "").trim(),
    fileSize: Math.max(0, Number(entry.fileSize || 0) || 0),
    fileDataUrl: String(entry.fileDataUrl || "").trim(),
    linkUrl: String(entry.linkUrl || "").trim(),
    createdByName: String(entry.createdByName || "").trim(),
    createdByEmail: normalizeEmail(entry.createdByEmail),
    createdAt,
    createdAtKey: normalizeTimestampKey(entry.createdAtKey, createdAt),
  };
}

function normalizeRegionalOperationsState(record = {}) {
  const next = record && typeof record === "object" ? clone(record) : {};
  next.reports = Array.isArray(next.reports)
    ? next.reports
        .map((entry) => normalizeRegionalReportEntry(entry))
        .sort((left, right) => Number(right.createdAtKey) - Number(left.createdAtKey))
    : [];
  next.transportRequests = Array.isArray(next.transportRequests)
    ? next.transportRequests
        .map((entry) => normalizeRegionalFundingRequestEntry(entry))
        .sort((left, right) => Number(right.createdAtKey) - Number(left.createdAtKey))
    : [];
  next.contacts = Array.isArray(next.contacts)
    ? next.contacts
        .map((entry) => normalizeRegionalContactEntry(entry))
        .sort(
          (left, right) =>
            normalizeRegionalRegion(left.region).localeCompare(normalizeRegionalRegion(right.region)) ||
            Number(right.createdAtKey) - Number(left.createdAtKey),
        )
    : [];
  next.workshopResources = Array.isArray(next.workshopResources)
    ? next.workshopResources
        .map((entry) => normalizeRegionalWorkshopResourceEntry(entry))
        .sort((left, right) => Number(right.createdAtKey) - Number(left.createdAtKey))
    : [];
  return next;
}

function normalizeUserRecord(user = {}) {
  const createdAt = String(user.createdAt || nowText()).trim();
  return {
    id: String(user.id || createId("user")).trim(),
    name: String(user.name || "").trim(),
    email: normalizeEmail(user.email),
    passwordHash: String(user.passwordHash || "").trim(),
    passwordSalt: String(user.passwordSalt || "").trim(),
    passwordVersion: String(user.passwordVersion || "").trim(),
    passwordIterations: Number(user.passwordIterations || 0) || PASSWORD_HASH_ITERATIONS,
    globalRole: normalizeGlobalRole(user.globalRole || "member"),
    createdAt,
    createdAtKey: normalizeTimestampKey(user.createdAtKey, createdAt),
    createdSource: String(user.createdSource || user.source || "registered").trim() || "registered",
    createdBy: normalizeEmail(user.createdBy),
    lastLoginAt: String(user.lastLoginAt || "").trim(),
    active: user.active !== false,
    privateAccessToken: String(
      user.privateAccessToken || user.accessToken || createId("access"),
    ).trim(),
    privateAccessIssuedAt: String(user.privateAccessIssuedAt || createdAt).trim(),
    lastPrivateAccessAt: String(user.lastPrivateAccessAt || "").trim(),
    privateAccessEmailLastSentAt: String(user.privateAccessEmailLastSentAt || "").trim(),
    privateAccessEmailLastSentAtKey: normalizeOptionalTimestampKey(
      user.privateAccessEmailLastSentAtKey,
      user.privateAccessEmailLastSentAt,
    ),
    privateAccessEmailEvents: normalizePrivateAccessEmailEvents(user.privateAccessEmailEvents),
    pinnedTournamentIds: Array.isArray(user.pinnedTournamentIds)
      ? Array.from(new Set(user.pinnedTournamentIds.map((value) => String(value || "").trim()).filter(Boolean))).slice(0, 12)
      : [],
    archivedTournamentIds: normalizeStringList(user.archivedTournamentIds, 200),
    deletedTournamentIds: normalizeStringList(user.deletedTournamentIds, 200),
    registeredTournamentIds: normalizeStringList(user.registeredTournamentIds, 200),
    regionalRole: normalizeRegionalOperationsRole(user.regionalRole),
    regionalRegion: normalizeRegionalRegion(user.regionalRegion),
    regionalParish: normalizeRegionalParish(user.regionalParish || user.parish || ""),
    phoneNumber: String(user.phoneNumber || user.phone || "").trim(),
    regionalBanking: normalizeRegionalBankingInfo(user.regionalBanking || user.regionalBank || {}),
    themePreset: String(user.themePreset || "jade_classic").trim() || "jade_classic",
    preferredLandingView:
      String(user.preferredLandingView || "overview").trim() || "overview",
  };
}

function mergeRegisteredTournamentIdsForUser(user = {}, syncedIds = []) {
  const deletedIds = new Set(normalizeStringList(user.deletedTournamentIds || [], 200));
  const existingIds = normalizeStringList(user.registeredTournamentIds || [], 200).filter(
    (id) => !deletedIds.has(id),
  );
  const visibleSyncedIds = normalizeStringList(syncedIds || [], 200).filter(
    (id) => !deletedIds.has(id),
  );
  return normalizeStringList([...existingIds, ...visibleSyncedIds], 200);
}

function buildUser(name, email, globalRole, password, metadata = {}) {
  return normalizeUserRecord({
    id: createId("user"),
    name,
    email: normalizeEmail(email),
    ...buildSecurePasswordRecord(password),
    globalRole: normalizeGlobalRole(globalRole),
    createdAt: nowText(),
    createdAtKey: Date.now(),
    createdSource: metadata.createdSource || "registered",
    createdBy: metadata.createdBy || "",
    lastLoginAt: "",
    active: true,
    regionalRole: metadata.regionalRole || "",
    regionalRegion: metadata.regionalRegion || "",
    regionalParish: metadata.regionalParish || "",
    phoneNumber: metadata.phoneNumber || "",
    regionalBanking: normalizeRegionalBankingInfo(metadata.regionalBanking || {}),
  });
}

function canClaimRegisteredAccount(user = {}) {
  return (
    String(user.createdSource || "").trim().toLowerCase() === "registered" &&
    !String(user.lastLoginAt || "").trim()
  );
}

function normalizeTournamentRegistrationSettings(record = {}) {
  const hasDebaterOpenSetting =
    Object.prototype.hasOwnProperty.call(record, "debaterOpen") ||
    Object.prototype.hasOwnProperty.call(record, "participantOpen") ||
    Object.prototype.hasOwnProperty.call(record, "debaterRegistrationOpen") ||
    Object.prototype.hasOwnProperty.call(record, "participantRegistrationOpen");
  const hasJudgeOpenSetting =
    Object.prototype.hasOwnProperty.call(record, "judgeOpen") ||
    Object.prototype.hasOwnProperty.call(record, "judgeRegistrationOpen");

  return {
    debaterOpen: hasDebaterOpenSetting
      ? Boolean(
          record.debaterOpen ||
            record.participantOpen ||
            record.debaterRegistrationOpen ||
            record.participantRegistrationOpen,
        )
      : true,
    judgeOpen: hasJudgeOpenSetting
      ? Boolean(record.judgeOpen || record.judgeRegistrationOpen)
      : true,
    debaterNote: String(
      record.debaterNote || record.participantNote || record.debaterRegistrationNote || "",
    ).trim(),
    judgeNote: String(record.judgeNote || record.judgeRegistrationNote || "").trim(),
  };
}

function getTournamentRegistrationAvailability(tournament, role = "debater") {
  const targetRole = String(role || "debater").trim().toLowerCase() === "judge"
    ? "judge"
    : "debater";
  const registration = normalizeTournamentRegistrationSettings(tournament?.registration || {});
  const roleOpen = targetRole === "judge" ? registration.judgeOpen : registration.debaterOpen;
  const issues = [];

  if (String(tournament?.status || "").trim().toLowerCase() !== "open") {
    issues.push("Tournament is closed.");
  }

  if (!roleOpen) {
    issues.push(
      targetRole === "judge"
        ? "Judge registration is turned off in Setup."
        : "Debater registration is turned off in Setup.",
    );
  }

  return {
    role: targetRole,
    open: issues.length === 0,
    roleOpen,
    reason:
      issues[0] ||
      (targetRole === "judge" ? "Judge registration is live." : "Debater registration is live."),
  };
}

function getRegistrationTeamSize(tournament) {
  return registrationTeamSize(tournament);
}

function createTeamRecord(name, institution = "", extras = {}) {
  return {
    id: String(extras.id || createId("team")).trim(),
    name: String(name || "").trim(),
    institution: String(institution || "").trim(),
    publicAlias: String(extras.publicAlias || "").trim(),
    notes: String(extras.notes || "").trim(),
    source: String(extras.source || "manual").trim() || "manual",
    createdAt: String(extras.createdAt || nowText()).trim(),
  };
}

function createParticipantRecord(email, name, teamName = "", extras = {}) {
  return {
    id: String(extras.id || createId("participant")).trim(),
    email: normalizeEmail(email),
    name: String(name || "").trim(),
    institution: String(extras.institution || "").trim(),
    teamId: String(extras.teamId || "").trim(),
    teamName: String(teamName || extras.teamName || "").trim(),
    wins: Number(extras.wins || 0) || 0,
    losses: Number(extras.losses || 0) || 0,
    points: Number(extras.points || 0) || 0,
    firsts: Number(extras.firsts || 0) || 0,
    seconds: Number(extras.seconds || 0) || 0,
    thirds: Number(extras.thirds || 0) || 0,
    fourths: Number(extras.fourths || 0) || 0,
    speakerScore: Number(extras.speakerScore || 0) || 0,
    rank: Number(extras.rank || 0) || 0,
    token: String(extras.token || createId("token")).trim(),
    feedback: Array.isArray(extras.feedback) ? clone(extras.feedback) : [],
  };
}

function normalizeJudgeAffiliationType(value, institution = "") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, " ");

  if (["independent", "independent judge", "ind"].includes(normalized)) {
    return "independent";
  }

  if (
    [
      "institutional",
      "institutionally affiliated",
      "institutional judge",
      "affiliated",
      "institution",
    ].includes(normalized)
  ) {
    return "institutional";
  }

  return String(institution || "").trim() ? "institutional" : "independent";
}

function createJudgeRecord(name, email, institution = "", extras = {}) {
  const normalizedInstitution = String(institution || "").trim();
  const affiliationType = normalizeJudgeAffiliationType(
    extras.affiliationType || extras.affiliation,
    normalizedInstitution,
  );
  return {
    id: String(extras.id || createId("judge")).trim(),
    name: String(name || "").trim() || String(email || "").trim().split("@")[0],
    email: normalizeEmail(email),
    institution: affiliationType === "independent" ? "" : normalizedInstitution,
    affiliationType,
    panelQuality: String(extras.panelQuality || "wing").trim() || "wing",
    qualityTier: String(extras.qualityTier || "solid").trim() || "solid",
    notes: String(extras.notes || "").trim(),
    active: extras.active !== false,
    createdAt: String(extras.createdAt || nowText()).trim(),
  };
}

function ensureWorkspaceState(state, options = {}) {
  const next =
    state && typeof state === "object"
      ? options.clone === false
        ? state
        : clone(state)
      : {};
  const incomingContractVersion = String(next.workspaceContractVersion || "").trim();
  if (
    incomingContractVersion &&
    incomingContractVersion !== WORKSPACE_CONTRACT_VERSION
  ) {
    throw createWorkspaceContractError(
      "workspace normalization",
      `expected contract ${WORKSPACE_CONTRACT_VERSION} but received ${incomingContractVersion}`,
    );
  }
  next.workspaceContractVersion = WORKSPACE_CONTRACT_VERSION;
  next.appSettings = next.appSettings && typeof next.appSettings === "object" ? next.appSettings : {};
  next.appSettings.branding = normalizeBrandingSettings(next.appSettings.branding || {});
  next.users = Array.isArray(next.users) ? next.users.map((user) => normalizeUserRecord(user)) : [];
  next.recoveryRequests = Array.isArray(next.recoveryRequests) ? next.recoveryRequests : [];
  next.tournaments = Array.isArray(next.tournaments) ? next.tournaments : [];
  next.regionalOperations = normalizeRegionalOperationsState(next.regionalOperations || {});
  return assertWorkspaceContract(
    synchronizeUserTournamentHistory(next),
    "workspace normalization",
  );
}

function synchronizeUserTournamentHistory(workspaceState) {
  const next = workspaceState && typeof workspaceState === "object" ? workspaceState : {};
  const users = Array.isArray(next.users) ? next.users.map((user) => normalizeUserRecord(user)) : [];
  const tournaments = Array.isArray(next.tournaments) ? next.tournaments : [];
  const historyByEmail = new Map();
  const linkedUserSeeds = new Map();

  tournaments.forEach((tournament) => {
    const tournamentId = String(tournament?.id || "").trim();
    if (!tournamentId) {
      return;
    }

    const remember = (email) => {
      const normalizedEmail = normalizeEmail(email);
      if (!normalizedEmail) {
        return;
      }
      if (!historyByEmail.has(normalizedEmail)) {
        historyByEmail.set(normalizedEmail, new Set());
      }
      historyByEmail.get(normalizedEmail).add(tournamentId);
    };

    (tournament?.participants || []).forEach((participant) => {
      remember(participant?.email);
      const normalizedEmail = normalizeEmail(participant?.email);
      if (normalizedEmail && !linkedUserSeeds.has(normalizedEmail)) {
        linkedUserSeeds.set(normalizedEmail, {
          email: normalizedEmail,
          name: String(participant?.name || normalizedEmail.split("@")[0]).trim(),
          createdSource: "registered",
        });
      }
    });
    (tournament?.judges || []).forEach((judge) => {
      remember(judge?.email);
      const normalizedEmail = normalizeEmail(judge?.email);
      if (normalizedEmail && !linkedUserSeeds.has(normalizedEmail)) {
        linkedUserSeeds.set(normalizedEmail, {
          email: normalizedEmail,
          name: String(judge?.name || normalizedEmail.split("@")[0]).trim(),
          createdSource: "registered",
        });
      }
    });
    TOURNAMENT_PERMISSION_KEYS.forEach((key) => {
      (tournament?.permissions?.[key] || []).forEach(remember);
    });
  });

  const nextUsers = users.map((user) =>
    normalizeUserRecord({
      ...user,
      registeredTournamentIds: mergeRegisteredTournamentIdsForUser(
        user,
        Array.from(historyByEmail.get(user.email) || []),
      ),
    }),
  );

  const existingEmails = new Set(nextUsers.map((user) => user.email));
  linkedUserSeeds.forEach((seed) => {
    if (existingEmails.has(seed.email)) {
      return;
    }
    nextUsers.push(
      buildUser(
        seed.name || seed.email.split("@")[0],
        seed.email,
        "member",
        createTemporaryRegistrationPassword(),
        {
          createdSource: seed.createdSource || "registered",
          createdBy: "system",
        },
      ),
    );
    existingEmails.add(seed.email);
  });

  next.users = nextUsers.map((user) =>
    normalizeUserRecord({
      ...user,
      registeredTournamentIds: mergeRegisteredTournamentIdsForUser(
        user,
        Array.from(historyByEmail.get(user.email) || []),
      ),
    }),
  );

  return next;
}

function rememberUserTournamentHistory(state, email, tournamentId) {
  const normalizedEmail = normalizeEmail(email);
  const normalizedTournamentId = String(tournamentId || "").trim();
  if (!normalizedEmail || !normalizedTournamentId) {
    return;
  }

  state.users = (state.users || []).map((user) =>
    normalizeEmail(user.email) === normalizedEmail
      ? normalizeUserRecord(
          normalizeStringList(user.deletedTournamentIds || [], 200).includes(normalizedTournamentId)
            ? {
                ...user,
                registeredTournamentIds: normalizeStringList(
                  user.registeredTournamentIds || [],
                  200,
                ).filter((id) => id !== normalizedTournamentId),
              }
            : {
                ...user,
                registeredTournamentIds: normalizeStringList(
                  [...(user.registeredTournamentIds || []), normalizedTournamentId],
                  200,
                ),
              },
        )
      : normalizeUserRecord(user),
  );
}

function ensureRegistrationUser(
  state,
  {
    name,
    email,
    password = "",
    createdSource = "registered",
    createdBy = "",
    requirePassword = false,
    markLoggedIn = false,
  } = {},
) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    return null;
  }

  const minimumPasswordLength = Number(state?.appSettings?.auth?.minimumPasswordLength || 12);
  const existingUser = (state.users || []).find((user) => user.email === normalizedEmail) || null;

  if (existingUser) {
    if (!existingUser.active) {
      const error = new Error("This account has been disabled by the manager.");
      error.statusCode = 403;
      error.code = "account_disabled";
      throw error;
    }

    if (requirePassword) {
      const passwordCheck = verifyUserPassword(existingUser, password);
      if (!passwordCheck.ok) {
        if (canClaimRegisteredAccount(existingUser)) {
          if (String(password || "").length < minimumPasswordLength) {
            const error = new Error("New passwords must be at least " + minimumPasswordLength + " characters long.");
            error.statusCode = 422;
            error.code = "password_too_short";
            throw error;
          }
          Object.assign(existingUser, buildSecurePasswordRecord(password), {
            name: String(name || existingUser.name || normalizedEmail.split("@")[0]).trim(),
            createdSource,
            createdBy: normalizeEmail(createdBy) || existingUser.createdBy,
          });
        } else {
          const error = new Error("That password is not correct for the existing account.");
          error.statusCode = 401;
          error.code = "invalid_password";
          throw error;
        }
      } else if (passwordCheck.needsUpgrade) {
        Object.assign(existingUser, buildSecurePasswordRecord(password));
      }
    }

    if (!String(existingUser.name || "").trim() && String(name || "").trim()) {
      existingUser.name = String(name || "").trim();
    }
    if (markLoggedIn) {
      existingUser.lastLoginAt = nowText();
    }
    return existingUser;
  }

  if (requirePassword && String(password || "").length < minimumPasswordLength) {
    const error = new Error(
      "Password must be at least " + minimumPasswordLength + " characters long.",
    );
    error.statusCode = 422;
    error.code = "password_too_short";
    throw error;
  }

  const user = buildUser(
    String(name || normalizedEmail.split("@")[0]).trim(),
    normalizedEmail,
    "member",
    requirePassword ? password : createTemporaryRegistrationPassword(),
    {
      createdSource,
      createdBy: normalizeEmail(createdBy) || normalizedEmail,
    },
  );
  if (markLoggedIn) {
    user.lastLoginAt = nowText();
  }
  state.users.push(user);
  return user;
}

function getTournamentRegistrationTeam(tournament, teamName, institution) {
  const matches = (team) => normalizeTextKey(team.name) === normalizeTextKey(teamName) &&
    normalizeTextKey(team.institution) === normalizeTextKey(institution);
  const existingTeam = (tournament.teams || []).find(matches);
  if (existingTeam) return existingTeam;
  const legacyMember = (tournament.participants || []).find((participant) =>
    participant.teamId && matches({ name: participant.teamName, institution: participant.institution }));
  return legacyMember ? createTeamRecord(teamName, institution, { id: legacyMember.teamId, source: "derived" }) : null;
}

function getTournamentRegistrationRosterConflict(tournament, teamName, institution, rosterEmails) {
  const existingTeam = getTournamentRegistrationTeam(tournament, teamName, institution);
  const isRequestedTeam = (participant) => participant.teamId
    ? Boolean(existingTeam && String(participant.teamId) === String(existingTeam.id))
    : Boolean(participant.teamName && normalizeTextKey(participant.teamName) === normalizeTextKey(teamName) &&
        normalizeTextKey(participant.institution) === normalizeTextKey(institution));
  const existingParticipants = tournament.participants || [];
  if (existingParticipants.some((participant) =>
    rosterEmails.includes(normalizeEmail(participant.email)) &&
    (participant.teamId || participant.teamName) && !isRequestedTeam(participant))) {
    return "A team member is already registered with another team. Ask the tournament staff to update their assignment.";
  }
  if (existingParticipants.some((participant) =>
    isRequestedTeam(participant) && !rosterEmails.includes(normalizeEmail(participant.email)))) {
    return "That team already has a different roster. Ask the tournament staff to update it.";
  }
  return "";
}

function upsertTournamentRegistrationTeam(tournament, teamName, institution, notes = "") {
  const normalizedTeamName = String(teamName || "").trim();
  const normalizedInstitution = String(institution || "").trim();
  if (!normalizedTeamName) {
    return null;
  }

  const candidate = createTeamRecord(normalizedTeamName, normalizedInstitution, {
    notes,
    source: "manual",
  });
  const existingTeam = getTournamentRegistrationTeam(tournament, normalizedTeamName, normalizedInstitution);

  if (existingTeam) {
    if (!(tournament.teams || []).some((team) => team.id === existingTeam.id)) {
      tournament.teams = [...(tournament.teams || []), existingTeam];
    }
    tournament.teams = (tournament.teams || []).map((team) =>
      team.id === existingTeam.id
        ? {
            ...team,
            institution: team.institution || normalizedInstitution,
            notes: team.notes || notes,
            source: "manual",
          }
        : team,
    );
    return (tournament.teams || []).find((team) => team.id === existingTeam.id) || existingTeam;
  }

  tournament.teams = [...(tournament.teams || []), candidate];
  return candidate;
}

function upsertTournamentParticipantRegistration(
  tournament,
  { name, email, institution, team, teamName } = {},
) {
  const normalizedName = String(name || "").trim();
  const normalizedEmail = normalizeEmail(email);
  const normalizedTeamName = String(team?.name || teamName || "").trim();
  if (!normalizedName && !normalizedEmail) {
    return null;
  }

  const matchingParticipants = (tournament.participants || []).filter((participant) =>
    normalizedEmail && normalizeEmail(participant.email) === normalizedEmail);
  if (matchingParticipants.length > 1 || matchingParticipants.some((participant) =>
    normalizeTextKey(participant.name) !== normalizeTextKey(normalizedName) ||
    (participant.teamId && participant.teamId !== team?.id))) {
    const error = new Error("This email is already attached to a different or ambiguous registration. Ask tournament staff to correct it.");
    error.code = "team_roster_conflict";
    error.statusCode = 409;
    throw error;
  }
  const existingIndex = (tournament.participants || []).findIndex((participant) =>
    normalizedEmail
      ? normalizeEmail(participant.email) === normalizedEmail
      : normalizeTextKey(participant.name) === normalizeTextKey(normalizedName) &&
        normalizeTextKey(participant.teamName || "") === normalizeTextKey(normalizedTeamName),
  );
  const existing = existingIndex >= 0 ? tournament.participants[existingIndex] : null;
  const nextParticipant = createParticipantRecord(
    normalizedEmail,
    normalizedName || normalizedEmail,
    normalizedTeamName,
    {
      id: existing?.id,
      institution: String(institution || team?.institution || existing?.institution || "").trim(),
      teamId: String(team?.id || existing?.teamId || "").trim(),
      wins: existing?.wins || 0,
      losses: existing?.losses || 0,
      points: existing?.points || 0,
      firsts: existing?.firsts || 0,
      seconds: existing?.seconds || 0,
      thirds: existing?.thirds || 0,
      fourths: existing?.fourths || 0,
      speakerScore: existing?.speakerScore || 0,
      token: existing?.token,
      feedback: Array.isArray(existing?.feedback) ? existing.feedback : [],
    },
  );

  if (existingIndex >= 0) {
    tournament.participants[existingIndex] = nextParticipant;
  } else {
    tournament.participants = [...(tournament.participants || []), nextParticipant];
  }

  const debaterEmails = new Set(tournament.permissions?.debaterEmails || []);
  if (normalizedEmail) {
    debaterEmails.add(normalizedEmail);
  }
  tournament.permissions = normalizeTournamentPermissions({
    ...(tournament.permissions || {}),
    debaterEmails: Array.from(debaterEmails),
  });
  return nextParticipant;
}

function upsertTournamentJudgeRegistration(
  tournament,
  { name, email, institution, affiliationType, notes } = {},
) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    return null;
  }

  const existingJudge =
    (tournament.judges || []).find((judge) => normalizeEmail(judge.email) === normalizedEmail) ||
    null;
  const judge = createJudgeRecord(
    String(name || "").trim(),
    normalizedEmail,
    String(institution || "").trim(),
    {
      id: existingJudge?.id,
      affiliationType,
      panelQuality: existingJudge?.panelQuality || "wing",
      qualityTier: existingJudge?.qualityTier || "solid",
      notes: String(existingJudge?.notes || notes || "").trim(),
      active: existingJudge?.active,
      createdAt: existingJudge?.createdAt,
    },
  );

  tournament.judges = existingJudge
    ? (tournament.judges || []).map((entry) =>
        normalizeEmail(entry.email) === normalizedEmail ? { ...entry, ...judge } : entry,
      )
    : [...(tournament.judges || []), judge];

  const judgeEmails = new Set(tournament.permissions?.judgeEmails || []);
  judgeEmails.add(normalizedEmail);
  tournament.permissions = normalizeTournamentPermissions({
    ...(tournament.permissions || {}),
    judgeEmails: Array.from(judgeEmails),
  });
  return judge;
}

function addTournamentAuditEntry(tournament, actorEmail, message) {
  const entry = {
    id: createId("audit"),
    actor: normalizeEmail(actorEmail),
    at: nowText(),
    message: String(message || "").trim(),
  };
  tournament.auditLog = [entry, ...(Array.isArray(tournament.auditLog) ? tournament.auditLog : [])];
  return tournament;
}

function isSystemAdmin(state, email) {
  const normalizedEmail = normalizeEmail(email);
  const user = (state?.users || []).find((entry) => entry.email === normalizedEmail);
  const role = normalizeGlobalRole(user?.globalRole || "");
  return (
    normalizedEmail === normalizeEmail(MANAGER_EMAIL) ||
    role === "system_admin" ||
    role === "manager"
  );
}

function getAuthenticatedAccountAccess(state, email) {
  const normalizedEmail = normalizeEmail(email);
  if (isSystemAdmin(state, normalizedEmail)) {
    return { state, sessionScope: null };
  }
  return {
    state: memberWorkspace(state, normalizedEmail),
    sessionScope: { role: "member", email: normalizedEmail },
  };
}

function assertDrawReleaseIntegrity(previousTournament, nextTournament) {
  const previousDraw = new Map((previousTournament?.draw || []).map((entry) => [String(entry.id || ""), entry]));
  const nextDraw = new Map((nextTournament?.draw || []).map((entry) => [String(entry.id || ""), entry]));
  const fail = (message, code = "draw_release_blocked", ruleCode = "") => {
    const error = new Error(message);
    error.statusCode = 422;
    error.code = code;
    if (ruleCode) error.ruleCode = ruleCode;
    throw error;
  };
  for (const [id, previous] of previousDraw) {
    if (String(previous.status || "").toLowerCase() !== "published") continue;
    const next = nextDraw.get(id);
    if (!next || String(next.status || "").toLowerCase() !== "published") {
      fail("Round " + Number(previous.round || 0) + " is published and locked. Its draw cannot be reset or unpublished.", "published_round_locked");
    }
    for (const field of ["round", "room", "matchup", "slots", "entryIds", "teamIds", "participantIds"]) {
      if (JSON.stringify(previous[field] ?? null) !== JSON.stringify(next[field] ?? null)) {
        fail("Round " + Number(previous.round || 0) + " is published and locked. Its room assignments cannot be changed.", "published_round_locked");
      }
    }
  }
  const newlyPublished = (nextTournament?.draw || []).filter((entry) => {
    const previous = previousDraw.get(String(entry.id || ""));
    return String(entry.status || "").toLowerCase() === "published" &&
      String(previous?.status || "").toLowerCase() !== "published";
  });
  if (!newlyPublished.length) return;
  const controls = new Map((nextTournament?.roundControls || []).map((entry) => [Number(entry.round), entry]));
  const rounds = new Set(newlyPublished.map((entry) => Number(entry.round)));
  for (const round of rounds) {
    const control = controls.get(round);
    if (!String(control?.motionTitle || control?.motionText || "").trim()) {
      fail("Save a motion for Round " + round + " before publishing its draw.");
    }
    const rooms = (nextTournament?.draw || []).filter((entry) => Number(entry.round) === round);
    if (!rooms.length || rooms.some((entry) => String(entry.status || "").toLowerCase() !== "published")) {
      fail("Publish every room in Round " + round + " together after its checks pass.");
    }
    const roomNames = new Set();
    const entryKeys = new Set();
    const assignedParticipants = new Set();
    const roundJudgeRooms = new Map();
    for (const room of rooms) {
      const name = String(room.room || "").trim();
      if (!name || /overflow/i.test(name) || /overflow/i.test(String(room.matchup || ""))) {
        fail("Name every room and resolve overflow entries before publishing Round " + round + ".");
      }
      const roomKey = normalizeTextKey(name);
      if (roomNames.has(roomKey)) fail("Use a unique room name for every room in Round " + round + ".");
      roomNames.add(roomKey);
      const slots = Array.isArray(room.slots) ? room.slots : [];
      const keys = slots.map((slot) => String(slot.teamId || "").trim() || String(slot.entryId || "").trim() || normalizeTextKey(slot.teamName || slot.shortLabel || slot.label)).filter(Boolean);
      if (!keys.length || new Set(keys).size !== keys.length) {
        fail("Add distinct team entries to every room before publishing Round " + round + ".");
      }
      for (const key of keys) {
        if (entryKeys.has(key)) fail("A team or speaker entry appears in more than one room in Round " + round + ".");
        entryKeys.add(key);
      }
      for (const slot of slots) {
        for (const participantId of slot.participantIds || []) {
          const id = String(participantId || "");
          if (assignedParticipants.has(id)) fail("A speaker appears in more than one room in Round " + round + ".");
          assignedParticipants.add(id);
          const participant = (nextTournament?.participants || []).find((entry) => String(entry.id) === id);
          if (!participant) fail("A room contains an unregistered speaker. Refresh the draw before publishing.");
          if (participant.teamId && slot.teamId && String(participant.teamId) !== String(slot.teamId)) {
            fail("A registered team is split across sides. Correct the team assignment before publishing.");
          }
        }
      }
      const chair = (nextTournament?.judgeAllocations || []).some((allocation) =>
        String(allocation.drawId || "") === String(room.id || "") &&
        /chair/.test(String(allocation.panelRole || allocation.role || "").toLowerCase()),
      );
      if (!chair) fail("Assign a chair to " + name + " before publishing Round " + round + ".");
      for (const allocation of nextTournament?.judgeAllocations || []) {
        if (String(allocation.drawId || "") !== String(room.id || "")) continue;
        const email = normalizeEmail(allocation.judgeEmail);
        if (!email) continue;
        const previousRoom = roundJudgeRooms.get(email);
        if (previousRoom && previousRoom !== String(room.id || "")) {
          fail("A judge is assigned to more than one room in Round " + round + ". Resolve the duplicate assignment before publishing.");
        }
        roundJudgeRooms.set(email, String(room.id || ""));
      }
      const severeConflicts = evaluateDrawEntryConflicts(nextTournament, room).filter((issue) => issue.blocksPublication);
      if (severeConflicts.length) {
        fail("Resolve the conflict in " + name + " before publishing Round " + round + ": " + severeConflicts[0].detail, "draw_release_blocked", severeConflicts[0].code);
      }
    }
  }
}

function assertScoringPersistAuthorization(previousState, nextState, actorEmail, restrictedJudge = false) {
  const actor = normalizeEmail(actorEmail);
  if (!restrictedJudge && isSystemAdmin(previousState, actor)) return;
  const forbidden = () => {
    const error = new Error("This account cannot change tournament scoring or access rules.");
    error.statusCode = 403;
    error.code = "scoring_permission_denied";
    throw error;
  };
  const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);
  const canonicalStandings = (entries) => (entries || []).map((entry) => ({
    id: String(entry.id || ""), name: String(entry.name || ""),
    wins: Number(entry.wins || 0), losses: Number(entry.losses || 0),
    points: Number(entry.points || 0), speaks: Number(entry.speaks || 0),
    firsts: Number(entry.firsts || 0), seconds: Number(entry.seconds || 0),
    thirds: Number(entry.thirds || 0), fourths: Number(entry.fourths || 0),
  })).sort((left, right) => left.id.localeCompare(right.id));
  if (!equal(previousState.appSettings, nextState.appSettings) ||
      !equal(previousState.regionalOperations, nextState.regionalOperations) ||
      (previousState.users || []).length !== (nextState.users || []).length) forbidden();
  const previousUsers = new Map((previousState.users || []).map((user) => [normalizeEmail(user.email), user]));
  for (const user of nextState.users || []) {
    const previous = previousUsers.get(normalizeEmail(user.email));
    if (!previous || !equal(previous.globalRole, user.globalRole) ||
        !equal(previous.active, user.active)) forbidden();
    if (normalizeEmail(user.email) !== actor && !equal(previous, user)) forbidden();
    if (normalizeEmail(user.email) === actor &&
        (!equal(previous.passwordHash, user.passwordHash) ||
         !equal(previous.passwordSalt, user.passwordSalt) ||
         !equal(previous.privateAccessToken, user.privateAccessToken))) forbidden();
  }
  const previousTournaments = new Map((previousState.tournaments || []).map((entry) => [entry.id, entry]));
  for (const next of nextState.tournaments || []) {
    const previous = previousTournaments.get(next.id);
    if (!previous) forbidden();
    const managers = [
      ...(previous.permissions?.managerEmails || []),
      ...(previous.permissions?.tabDirectorEmails || []),
      ...(previous.permissions?.tabManagerEmails || []),
      ...(previous.permissions?.caTeamEmails || []),
    ];
    if (!restrictedJudge && (normalizeEmail(previous.ownerEmail) === actor || managers.some((email) => normalizeEmail(email) === actor))) {
      continue;
    }
    if (!equal(previous.ownerEmail, next.ownerEmail) ||
        !equal(previous.code, next.code) ||
        !equal(previous.status, next.status)) forbidden();
    if (!equal(previous.permissions, next.permissions) ||
        !equal(previous.format, next.format) ||
        !equal(previous.participantModel, next.participantModel) ||
        !equal(previous.config, next.config) ||
        !equal(canonicalStandings(previous.standings), canonicalStandings(next.standings))) forbidden();
    const previousAllocations = new Map((previous.judgeAllocations || []).map((entry) => [entry.id, entry]));
    const stableAllocation = (entry) => {
      const copy = { ...entry };
      for (const key of ["ballotResults", "replySpeeches", "draft"]) {
        if (!Object.keys(copy[key] || {}).length) delete copy[key];
      }
      return copy;
    };
    const roundFormat = (round) => {
      const profile = (next.config?.roundProfiles || []).find((entry) => Number(entry.round) === Number(round));
      return String(profile?.format || next.format || "").trim();
    };
    const slotKey = (slot) => String(slot.entryId || slot.teamId || slot.label || "").trim();
    const canonicalResults = (results) => Object.fromEntries(Object.entries(results || {})
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => [key, {
        rank: Number.isInteger(Number(value?.rank)) && Number(value.rank) > 0 ? Number(value.rank) : null,
        outcome: ["win", "loss", "draw"].includes(String(value?.outcome || "").toLowerCase())
          ? String(value.outcome).toLowerCase() : "",
      }]).filter(([, value]) => value.rank || value.outcome));
    for (const allocation of next.judgeAllocations || []) {
      const old = previousAllocations.get(allocation.id);
      if (!old) forbidden();
      if (equal(stableAllocation(old), stableAllocation(allocation))) continue;
      if (old.submittedAt && String(old.panelRole || "").toLowerCase() === "chair" &&
          roundFormat(old.round) === "World Schools" &&
          !Object.keys(old.ballotResults || {}).length &&
          equal(canonicalResults(allocation.ballotResults), canonicalResults(
            (previous.draw || []).find((entry) => entry.id === old.drawId)?.officialResults)) &&
          equal({ ...stableAllocation(old), ballotResults: undefined },
                { ...stableAllocation(allocation), ballotResults: undefined })) continue;
      if (normalizeEmail(old.judgeEmail) !== actor || old.submittedAt ||
          !equal({ ...old, status: undefined, checkedIn: undefined, checkedInAt: undefined,
            checkedInAtKey: undefined, submittedAt: undefined, submittedAtKey: undefined,
            ballotResults: undefined, replySpeeches: undefined, draft: undefined },
            { ...allocation, status: undefined, checkedIn: undefined, checkedInAt: undefined,
              checkedInAtKey: undefined, submittedAt: undefined, submittedAtKey: undefined,
              ballotResults: undefined, replySpeeches: undefined, draft: undefined })) forbidden();
      if (allocation.submittedAt && !old.submittedAt) {
        const draw = (previous.draw || []).find((entry) => entry.id === old.drawId);
        if (!draw) forbidden();
        const format = roundFormat(old.round);
        if (String(old.panelRole || "").toLowerCase() !== "chair" && format !== "World Schools") forbidden();
        const slots = draw.slots || [];
        const results = allocation.ballotResults || {};
        if (format === "British Parliamentary" || format === "Iron Person British Parliamentary") {
          const ranks = slots.map((slot) => Number(results[slotKey(slot)]?.rank));
          if (ranks.some((rank) => !Number.isInteger(rank) || rank < 1 || rank > slots.length) ||
              new Set(ranks).size !== slots.length) forbidden();
        } else if (format === "World Schools" || format === "American Parliamentary" ||
                   format === "JADE Parliamentary") {
          const outcomes = slots.map((slot) => results[slotKey(slot)]?.outcome);
          if (slots.length !== 2 || outcomes.filter((value) => value === "win").length !== 1 ||
              outcomes.filter((value) => value === "loss").length !== 1) forbidden();
        }
        if (format === "World Schools") {
          for (const slot of slots) {
            const reply = allocation.replySpeeches?.[slotKey(slot)];
            const score = Number(reply?.score);
            if (!(slot.participantIds || []).slice(0, 2).includes(reply?.participantId) ||
                !Number.isFinite(score) || score < 30 || score > 40 ||
                !Number.isInteger(score * 2)) forbidden();
            const parts = ["Content", "Style", "Strategy"].map((category) => Number(reply.breakdown?.[category]));
            if (parts.some((value, index) => !Number.isFinite(value) || value < 0 ||
                value > (index === 2 ? 10 : 20) || !Number.isInteger(value * 2)) ||
                Math.abs(parts.reduce((sum, value) => sum + value, 0) - score) > 0.001) forbidden();
          }
        }
        const assignedIds = old.participantIds?.length
          ? old.participantIds
          : draw.participantIds || [];
        for (const participantId of assignedIds) {
          const participant = (next.participants || []).find((entry) => entry.id === participantId);
          const entries = (participant?.feedback || []).filter((entry) =>
            entry.allocationId === old.id && normalizeEmail(entry.judgeEmail) === actor);
          if (entries.length !== 1 || entries[0].drawId !== old.drawId) forbidden();
        }
      }
    }
    if ((previous.judgeAllocations || []).length !== (next.judgeAllocations || []).length) forbidden();
    const ownAllocationIds = new Set((previous.judgeAllocations || [])
      .filter((entry) => normalizeEmail(entry.judgeEmail) === actor && !entry.submittedAt)
      .map((entry) => entry.id));
    const previousParticipants = new Map((previous.participants || []).map((entry) => [entry.id, entry]));
    for (const participant of next.participants || []) {
      const old = previousParticipants.get(participant.id);
      if (!old) forbidden();
      const stripOwnFeedback = (entries) => (entries || []).filter((entry) =>
        !(ownAllocationIds.has(entry.allocationId) && normalizeEmail(entry.judgeEmail) === actor));
      const scoringFields = (record) => ({
        teamId: String(record.teamId || ""), teamName: String(record.teamName || ""),
        speakerScore: Number(record.speakerScore || 0),
        wins: Number(record.wins || 0), losses: Number(record.losses || 0),
        points: Number(record.points || 0),
        firsts: Number(record.firsts || 0), seconds: Number(record.seconds || 0),
        thirds: Number(record.thirds || 0), fourths: Number(record.fourths || 0),
        feedback: stripOwnFeedback(record.feedback),
      });
      if (!equal(scoringFields(old), scoringFields(participant))) forbidden();
      for (const entry of participant.feedback || []) {
        if (!ownAllocationIds.has(entry.allocationId) || normalizeEmail(entry.judgeEmail) !== actor) continue;
        const allocation = previousAllocations.get(entry.allocationId);
        const draw = (previous.draw || []).find((entry) => entry.id === allocation?.drawId);
        const assignedIds = allocation?.participantIds?.length
          ? allocation.participantIds
          : draw?.participantIds || [];
        if (!assignedIds.includes(participant.id) ||
            entry.drawId !== allocation.drawId) forbidden();
        const score = Number(entry.speakerScore);
        const format = roundFormat(allocation.round);
        if (!Number.isFinite(score) || score < (format === "World Schools" ? 60 : 0) ||
            score > (format === "World Schools" ? 80 : 100)) forbidden();
        if (format === "World Schools") {
          const parts = ["Content", "Style", "Strategy"].map((category) => Number(entry.scores?.[category]));
          if (parts.some((value, index) => !Number.isFinite(value) || value < 0 ||
              value > (index === 2 ? 20 : 40)) ||
              Math.abs(parts.reduce((sum, value) => sum + value, 0) - score) > 0.001) forbidden();
        }
      }
    }
    if ((previous.participants || []).length !== (next.participants || []).length) forbidden();
    const previousDraw = new Map((previous.draw || []).map((entry) => [entry.id, entry]));
    for (const draw of next.draw || []) {
      const old = previousDraw.get(draw.id);
      if (!old) forbidden();
      if (equal(old, draw)) continue;
      const chair = (previous.judgeAllocations || []).find((entry) =>
        entry.drawId === draw.id && normalizeEmail(entry.judgeEmail) === actor &&
        String(entry.panelRole || "").toLowerCase() === "chair" && !entry.submittedAt);
      const ownWorldSchoolsVote = (previous.judgeAllocations || []).some((entry) =>
        entry.drawId === draw.id && normalizeEmail(entry.judgeEmail) === actor && !entry.submittedAt &&
        roundFormat(draw.round) === "World Schools");
      if (!equal(canonicalResults(old.officialResults), canonicalResults(draw.officialResults)) &&
          !chair && !ownWorldSchoolsVote) forbidden();
      if (!equal(old.slots, draw.slots) || !equal(old.round, draw.round) ||
          !equal(old.teamIds, draw.teamIds) || !equal(old.participantIds, draw.participantIds)) forbidden();
      if (!equal(canonicalResults(old.officialResults), canonicalResults(draw.officialResults))) {
        const submittedNow = (next.judgeAllocations || []).some((entry) =>
          entry.drawId === draw.id && normalizeEmail(entry.judgeEmail) === actor &&
          Boolean(entry.submittedAt) && !previousAllocations.get(entry.id)?.submittedAt);
        if (!submittedNow) forbidden();
        const format = roundFormat(draw.round);
        const keys = (draw.slots || []).map(slotKey);
        if (format === "World Schools") {
          const panel = Array.from(new Map((next.judgeAllocations || [])
            .filter((entry) => entry.drawId === draw.id)
            .map((entry) => [normalizeEmail(entry.judgeEmail), entry])).values());
          const votes = panel.filter((entry) => entry.submittedAt).map((entry) => {
            const results = Object.keys(entry.ballotResults || {}).length
              ? entry.ballotResults
              : String(entry.panelRole || "").toLowerCase() === "chair"
                ? old.officialResults || {} : {};
            return keys.find((key) => results[key]?.outcome === "win" &&
              results[keys.find((other) => other !== key)]?.outcome === "loss");
          })
            .filter(Boolean);
          const winner = keys.find((key) => votes.filter((vote) => vote === key).length > panel.length / 2);
          const expected = winner
            ? Object.fromEntries(keys.map((key) => [key, { rank: null, outcome: key === winner ? "win" : "loss" }]))
            : {};
          if (!equal(canonicalResults(expected), canonicalResults(draw.officialResults))) forbidden();
        } else if (!equal(canonicalResults((next.judgeAllocations || []).find((entry) =>
          entry.drawId === draw.id && normalizeEmail(entry.judgeEmail) === actor)?.ballotResults || {}),
          canonicalResults(draw.officialResults))) forbidden();
      }
    }
    if ((previous.draw || []).length !== (next.draw || []).length) forbidden();
  }
  if ((previousState.tournaments || []).length !== (nextState.tournaments || []).length) forbidden();
}

function hasSystemAdminAccounts(state) {
  return (state?.users || []).some((entry) => {
    const normalizedEmail = normalizeEmail(entry?.email);
    const role = normalizeGlobalRole(entry?.globalRole || "");
    return (
      entry?.active !== false &&
      (normalizedEmail === normalizeEmail(MANAGER_EMAIL) ||
        role === "system_admin" ||
        role === "manager")
    );
  });
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function hashSessionToken(token) {
  return crypto.createHash("sha256").update(String(token || ""), "utf8").digest("hex");
}

function createPasswordResetToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function hashPasswordResetToken(token) {
  return crypto.createHash("sha256").update(String(token || ""), "utf8").digest("hex");
}

function sendJson(response, statusCode, payload) {
  response.status(statusCode).json({
    contractVersion: WORKSPACE_CONTRACT_VERSION,
    ...payload,
  });
}

function sendError(response, statusCode, code, message) {
  sendJson(response, statusCode, {
    ok: false,
    code,
    error: message,
    message,
  });
}

function sendStatePayload(response, statusCode, payload = {}) {
  const extras = { ...(payload || {}) };
  delete extras.state;
  delete extras.revision;
  delete extras.sessionToken;
  delete extras.userEmail;
  sendJson(response, statusCode, {
    ok: true,
    initialized: true,
    state: payload.state || null,
    revision: normalizeWorkspaceRevision(payload.revision),
    ...(payload.sessionToken ? { sessionToken: payload.sessionToken } : {}),
    ...(payload.userEmail ? { userEmail: payload.userEmail } : {}),
    ...extras,
  });
}

function getRuntimeMetrics() {
  const memory = process.memoryUsage();
  const toMb = (bytes) => Math.round((Number(bytes || 0) / 1024 / 1024) * 10) / 10;
  return {
    memory: {
      rssMb: toMb(memory.rss),
      heapUsedMb: toMb(memory.heapUsed),
      heapTotalMb: toMb(memory.heapTotal),
      externalMb: toMb(memory.external),
    },
    databasePool: {
      total: pool.totalCount,
      idle: pool.idleCount,
      waiting: pool.waitingCount,
      maximum: buildPoolConfig().max,
    },
  };
}

function createApiConcurrencyGate(limit, queueLimit) {
  let active = 0;
  const queue = [];

  const startNext = () => {
    if (active >= limit || !queue.length) {
      return;
    }
    const nextRequest = queue.shift();
    if (nextRequest.cancelled) {
      startNext();
      return;
    }
    active += 1;
    nextRequest.start();
  };

  return (request, response, next) => {
    if (request.method !== "POST" || request.path !== "/api") {
      next();
      return;
    }
    const action = String(request.headers["x-jade-action"] || "")
      .trim()
      .toLowerCase();
    if (PRIORITY_API_ACTIONS.has(action)) {
      next();
      return;
    }

    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      active = Math.max(0, active - 1);
      startNext();
    };
    const start = () => {
      request.resume();
      response.once("finish", release);
      response.once("close", release);
      next();
    };

    if (active < limit) {
      active += 1;
      start();
      return;
    }

    if (queue.length >= queueLimit) {
      sendError(
        response,
        503,
        "backend_busy",
        "JADE Hummingbird is processing several updates. Please try again in a moment.",
      );
      return;
    }

    request.pause();
    const queuedRequest = { start, cancelled: false };
    response.once("close", () => {
      if (released) return;
      queuedRequest.cancelled = true;
    });
    queue.push(queuedRequest);
  };
}

async function withTransaction(work) {
  const client = await pool.connect();
  try {
    await client.query("begin");
    const result = await work(client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

async function readWorkspaceRecord(client, { forUpdate = false } = {}) {
  const result = await client.query(
    "select state, revision from jade_workspaces where id = $1 limit 1" + (forUpdate ? " for update" : ""),
    [WORKSPACE_ID],
  );
  if (!result.rows[0]?.state) {
    return null;
  }
  return {
    // PostgreSQL gives this request its own decoded object, so normalizing it
    // in place avoids briefly retaining another complete workspace copy.
    state: ensureWorkspaceState(result.rows[0].state, { clone: false }),
    revision: normalizeWorkspaceRevision(result.rows[0].revision),
  };
}

async function readWorkspaceRevision(client) {
  const result = await client.query(
    "select revision from jade_workspaces where id = $1 limit 1",
    [WORKSPACE_ID],
  );
  const revision = normalizeWorkspaceRevision(result.rows[0]?.revision);
  return revision || 0;
}

async function writeWorkspaceState(client, state, options = {}) {
  const normalized = options.normalized
    ? state
    : ensureWorkspaceState(state, { clone: options.clone !== false });
  const expectedRevision = normalizeWorkspaceRevision(options.expectedRevision);
  const params = [WORKSPACE_ID, JSON.stringify(normalized)];
  let result;

  if (expectedRevision > 0) {
    params.push(expectedRevision);
    result = await client.query(
      `
        insert into jade_workspaces (id, state, revision, updated_at)
        values ($1, $2::jsonb, 1, now())
        on conflict (id)
        do update
          set state = excluded.state,
              revision = jade_workspaces.revision + 1,
              updated_at = now()
        where jade_workspaces.revision = $3
        returning revision
      `,
      params,
    );

    if (!result.rows[0]) {
      const currentRecord = await readWorkspaceRecord(client);
      if (currentRecord) {
        const error = new Error("The workspace changed on another device. Refresh and try again.");
        error.statusCode = 409;
        error.code = "stale_revision";
        error.currentRevision = currentRecord.revision;
        throw error;
      }
    }
  } else {
    result = await client.query(
      `
        insert into jade_workspaces (id, state, revision, updated_at)
        values ($1, $2::jsonb, 1, now())
        on conflict (id)
        do update
          set state = excluded.state,
              revision = jade_workspaces.revision + 1,
              updated_at = now()
        returning revision
      `,
      params,
    );
  }

  const revision = normalizeWorkspaceRevision(result.rows[0]?.revision) || 1;
  const shouldSaveHistory =
    revision === 1 || revision % WORKSPACE_HISTORY_INTERVAL === 0;
  if (shouldSaveHistory) {
    await client.query(
      `
        insert into jade_workspace_history (workspace_id, revision, state)
        values ($1, $2, $3::jsonb)
        on conflict (workspace_id, revision) do nothing
      `,
      [WORKSPACE_ID, revision, params[1]],
    );
    await client.query(
      `
        delete from jade_workspace_history
        where workspace_id = $1
          and revision not in (
            select revision
            from jade_workspace_history
            where workspace_id = $1
            order by revision desc
            limit $2
          )
      `,
      [WORKSPACE_ID, WORKSPACE_HISTORY_LIMIT],
    );
  }
  return {
    ...(options.returnState === false ? {} : { state: normalized }),
    revision,
  };
}

async function issueSession(client, email, scope = null) {
  const token = createSessionToken();
  const tokenHash = hashSessionToken(token);
  const id = createId("session");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

  await client.query(
    `
      insert into jade_sessions (id, workspace_id, email, token_hash, expires_at, access_scope)
      values ($1, $2, $3, $4, $5, $6::jsonb)
    `,
    [id, WORKSPACE_ID, normalizeEmail(email), tokenHash, expiresAt, scope ? JSON.stringify(scope) : null],
  );

  return token;
}

async function getSession(client, token) {
  const tokenHash = hashSessionToken(token);
  const result = await client.query(
    `
      select id, workspace_id, email, expires_at, access_scope
      from jade_sessions
      where token_hash = $1 and workspace_id = $2 and expires_at > now()
      limit 1
    `,
    [tokenHash, WORKSPACE_ID],
  );

  return result.rows[0] || null;
}

function getUserByAccessToken(state, token) {
  const target = String(token || "").trim();
  if (!target) {
    return null;
  }
  return (state?.users || []).find((user) => user.privateAccessToken === target) || null;
}

function escapeEmailHtml(value = "") {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function resolvePublicDashboardUrl() {
  const candidate = PUBLIC_APP_URL || DEFAULT_PUBLIC_APP_URL;
  try {
    const url = new URL(candidate);
    if (url.pathname.endsWith("/api")) {
      url.pathname = url.pathname.slice(0, -4) || "/";
    }
    if (url.pathname.endsWith("/api/")) {
      url.pathname = url.pathname.slice(0, -5) || "/";
    }
    if (url.pathname.endsWith("/index.html")) {
      url.pathname = url.pathname.slice(0, -"/index.html".length) || "/";
    }
    url.search = "";
    url.hash = "";
    return url;
  } catch (error) {
    return new URL("https://jadehummingbird.org");
  }
}

function isAllowedBrowserOrigin(value = "") {
  const origin = String(value || "").trim();
  if (!origin) return false;
  const allowed = new Set([
    "https://jadehummingbird.org",
    "https://www.jadehummingbird.org",
    "http://localhost:8787",
    "http://127.0.0.1:8787",
  ]);
  if (PUBLIC_APP_URL) {
    try {
      allowed.add(new URL(PUBLIC_APP_URL).origin);
    } catch (error) {
      // An invalid deployment URL is ignored; link generation falls back to JADE's canonical domain.
    }
  }
  return allowed.has(origin);
}

function applyBrowserCorsHeaders(request, response) {
  const origin = String(request.headers.origin || "").trim();
  const allowed = !origin || isAllowedBrowserOrigin(origin);
  response.setHeader("Vary", "Origin");
  response.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Accept, X-JADE-Action",
  );
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (origin && allowed) {
    response.setHeader("Access-Control-Allow-Origin", origin);
  }
  return { origin, allowed };
}

function normalizePrivateAccessPortal(value = "") {
  const key = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (["regional", "regional_operations", "regional_ops"].includes(key)) {
    return "regional_operations";
  }
  return "";
}

function buildUserAccessUrl(request, token, options = {}) {
  const targetToken = String(token || "").trim();
  const portal = normalizePrivateAccessPortal(options.portal || options.screen || "");
  const baseUrl = resolvePublicDashboardUrl();
  const url =
    portal === "regional_operations"
      ? new URL("regional-operations.html", baseUrl)
      : baseUrl;
  url.searchParams.delete("token");
  url.searchParams.delete("screen");
  url.searchParams.delete("view");
  url.searchParams.delete("manage");
  url.searchParams.delete("tab");
  url.searchParams.delete("section");
  url.searchParams.delete("access");
  if (targetToken) url.searchParams.set("access", targetToken);
  if (options.tournamentId && normalizePrivateAccessEmailReason(options.reason) === "judge_registration") url.searchParams.set("event", String(options.tournamentId));
  return url.toString();
}

function buildPasswordResetUrl(request, token) {
  const baseUrl = resolvePublicDashboardUrl();
  baseUrl.searchParams.delete("access");
  baseUrl.searchParams.delete("token");
  baseUrl.searchParams.delete("view");
  baseUrl.searchParams.delete("manage");
  baseUrl.searchParams.delete("tab");
  baseUrl.searchParams.delete("section");
  baseUrl.searchParams.set("screen", "reset-password");
  baseUrl.searchParams.set("reset", String(token || "").trim());
  return baseUrl.toString();
}

function listRecipientTournamentNames(state, user, tournamentId = "") {
  const names = new Set();
  const tournamentMap = new Map(
    (state?.tournaments || []).map((tournament) => [
      String(tournament?.id || "").trim(),
      String(tournament?.name || "").trim(),
    ]),
  );

  const explicitTournamentId = String(tournamentId || "").trim();
  if (explicitTournamentId && tournamentMap.get(explicitTournamentId)) {
    names.add(tournamentMap.get(explicitTournamentId));
  }

  const deletedIds = new Set(normalizeStringList(user?.deletedTournamentIds || [], 200));
  (user?.registeredTournamentIds || []).forEach((id) => {
    const tournamentIdKey = String(id || "").trim();
    if (deletedIds.has(tournamentIdKey)) {
      return;
    }
    const name = tournamentMap.get(tournamentIdKey);
    if (name) {
      names.add(name);
    }
  });

  return Array.from(names).filter(Boolean).slice(0, 3);
}

function normalizePrivateAccessEmailReason(reason = "registration") {
  const key = String(reason || "registration")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return key || "registration";
}

function getPrivateAccessEmailReasonLabel(reasonKey = "registration") {
  if (reasonKey === "manual_resend") return "manual resend";
  if (reasonKey === "regional_operations") return "regional operations access";
  if (reasonKey === "participant_registration") return "debater registration";
  if (reasonKey === "judge_registration") return "judge registration";
  if (reasonKey === "appointment") return "tournament appointment";
  if (reasonKey === "sign_up") return "account sign-up";
  if (reasonKey === "account_created") return "account creation";
  if (reasonKey === "account_reactivated") return "account reactivation";
  return "registration";
}

function buildPrivateAccessEmailCopy({
  user,
  accessUrl,
  tournamentNames = [],
  reasonKey,
  portal = "",
}) {
  const recipientName = String(user?.name || "").trim() || "there";
  const portalKey = normalizePrivateAccessPortal(portal);
  const regionalPortal = portalKey === "regional_operations";
  const headlineTournament =
    !regionalPortal && tournamentNames.length > 0 ? " for " + tournamentNames[0] : "";
  const reasonLabel = getPrivateAccessEmailReasonLabel(reasonKey);
  const appName = DEFAULT_BRANDING.appName;
  const subject =
    regionalPortal
      ? "Your " + appName + " Regional Operations private access URL"
      : "Your " + appName + " private access URL" + headlineTournament;
  const tournamentLine = regionalPortal
    ? "This link opens the Regional Coordination and Operations portal for reports, requests, contacts, workshop resources, and regional staff tools."
    : tournamentNames.length
    ? "Tournament context: " + tournamentNames.join(", ") + "."
    : "Tournament context will appear in your portal as soon as you are assigned.";
  const accessLabel = regionalPortal
    ? "Open Regional Coordination and Operations"
    : "Open your private access URL";

  const text =
    "Hi " +
    recipientName +
    ",\n\n" +
    (regionalPortal
      ? "Your Regional Coordination and Operations private access URL for " +
        appName +
        " is ready."
      : "Your private access URL for " + appName + " is ready.") +
    "\n\n" +
    accessUrl +
    "\n\n" +
    tournamentLine +
    "\n" +
    "Reason: " +
    reasonLabel +
    ".\n\n" +
    "If this was not expected, reply to this email and a manager will help.\n";

  const html =
    "<p>Hi " +
    escapeEmailHtml(recipientName) +
    ",</p>" +
    (regionalPortal
      ? "<p>Your <strong>Regional Coordination and Operations</strong> private access URL for <strong>" +
        escapeEmailHtml(appName) +
        "</strong> is ready.</p>"
      : "<p>Your private access URL for <strong>" +
        escapeEmailHtml(appName) +
        "</strong> is ready.</p>") +
    "<p><a href=\"" +
    escapeEmailHtml(accessUrl) +
    "\">" +
    escapeEmailHtml(accessLabel) +
    "</a></p>" +
    "<p>" +
    escapeEmailHtml(tournamentLine) +
    "<br/>Reason: " +
    escapeEmailHtml(reasonLabel) +
    ".</p>" +
    "<p>If this was not expected, reply to this email and a manager will help.</p>";

  return { subject, text, html };
}

function markPrivateAccessEmailSent(user, reasonKey, sentAtMs = Date.now()) {
  const target = user && typeof user === "object" ? user : null;
  if (!target) {
    return;
  }
  const events = normalizePrivateAccessEmailEvents(target.privateAccessEmailEvents);
  events[reasonKey] = sentAtMs;
  target.privateAccessEmailEvents = events;
  target.privateAccessEmailLastSentAtKey = sentAtMs;
  target.privateAccessEmailLastSentAt = nowText();
}

function getPrivateAccessEmailCooldown(user, reasonKey, nowMs = Date.now()) {
  const lastSentAtKey = Number(user?.privateAccessEmailLastSentAtKey || 0);
  const reasonHistory = normalizePrivateAccessEmailEvents(user?.privateAccessEmailEvents);
  const lastReasonAtKey = Number(reasonHistory?.[reasonKey] || 0);
  const lastSentAt = Math.max(lastSentAtKey, lastReasonAtKey);

  if (PRIVATE_LINK_EMAIL_COOLDOWN_MS <= 0 || lastSentAt <= 0) {
    return {
      blocked: false,
      remainingSeconds: 0,
    };
  }

  const elapsedMs = nowMs - lastSentAt;
  if (elapsedMs >= PRIVATE_LINK_EMAIL_COOLDOWN_MS) {
    return {
      blocked: false,
      remainingSeconds: 0,
    };
  }

  const remainingSeconds = Math.max(
    1,
    Math.ceil((PRIVATE_LINK_EMAIL_COOLDOWN_MS - elapsedMs) / 1000),
  );
  return {
    blocked: true,
    remainingSeconds,
  };
}

async function sendPrivateAccessEmail({
  state,
  user,
  request,
  reason = "registration",
  tournamentId = "",
  force = false,
  portal = "",
} = {}) {
  const targetUser = user && typeof user === "object" ? user : null;
  const email = normalizeEmail(targetUser?.email);
  const reasonKey = normalizePrivateAccessEmailReason(reason);
  const portalKey =
    normalizePrivateAccessPortal(portal) ||
    (normalizeRegionalOperationsRole(targetUser?.regionalRole)
      ? "regional_operations"
      : "");

  if (!targetUser || !email) {
    return {
      email,
      status: "failed",
      reason: reasonKey,
      message: "No valid account was available for private URL email delivery.",
    };
  }

  if (targetUser.active === false) {
    return {
      email,
      status: "failed",
      reason: reasonKey,
      message: "Private URL email delivery is disabled for inactive accounts.",
    };
  }

  const cooldown = getPrivateAccessEmailCooldown(targetUser, reasonKey);
  if (!force && cooldown.blocked) {
    return {
      email,
      status: "skipped_cooldown",
      reason: reasonKey,
      cooldownRemainingSeconds: cooldown.remainingSeconds,
      message:
        "Skipped duplicate private URL email because cooldown is active for another " +
        cooldown.remainingSeconds +
        " seconds.",
    };
  }

  if (!RESEND_API_KEY || !RESEND_FROM_EMAIL) {
    console.warn(
      "Private URL email skipped because RESEND_API_KEY or RESEND_FROM_EMAIL is missing.",
    );
    return {
      email,
      status: "failed",
      reason: reasonKey,
      message:
        "Email delivery is not configured on this backend yet. Account and private URL are still ready.",
    };
  }

  if (!String(targetUser.privateAccessToken || "").trim()) {
    targetUser.privateAccessToken = createId("access");
    targetUser.privateAccessIssuedAt = nowText();
  }

  const accessUrl = buildUserAccessUrl(request, targetUser.privateAccessToken, {
    portal: portalKey, tournamentId, reason: reasonKey,
  });
  const tournamentNames = listRecipientTournamentNames(state, targetUser, tournamentId);
  const emailCopy = buildPrivateAccessEmailCopy({
    user: targetUser,
    accessUrl,
    tournamentNames,
    reasonKey,
    portal: portalKey,
  });

  try {
    const resendResponse = await fetch("https://api.resend.com/emails", {
      signal: AbortSignal.timeout(8000),
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + RESEND_API_KEY,
      },
      body: JSON.stringify({
        from: RESEND_FROM_EMAIL,
        to: [email],
        subject: emailCopy.subject,
        text: emailCopy.text,
        html: emailCopy.html,
        ...(RESEND_REPLY_TO ? { reply_to: RESEND_REPLY_TO } : {}),
      }),
    });

    if (!resendResponse.ok) {
      let providerMessage = "Email provider rejected the request.";
      try {
        const payload = await resendResponse.json();
        if (payload?.message) {
          providerMessage = String(payload.message);
        }
      } catch (error) {
        // Keep the default provider message.
      }
      console.error(
        "Private URL email delivery failed:",
        resendResponse.status,
        providerMessage,
      );
      return {
        email,
        status: "failed",
        reason: reasonKey,
        message:
          "Account was saved, but private URL email delivery failed. You can still copy the private URL manually.",
      };
    }

    markPrivateAccessEmailSent(targetUser, reasonKey);

    return {
      email,
      status: "sent",
      reason: reasonKey,
      message: "Private URL email sent successfully.",
    };
  } catch (error) {
    console.error("Private URL email delivery crashed:", error);
    return {
      email,
      status: "failed",
      reason: reasonKey,
      message:
        "Account was saved, but private URL email delivery failed. You can still copy the private URL manually.",
    };
  }
}

async function deliverCommittedRegistrationEmails(result, request, reason, tournamentId) {
  const recipients = (result.notificationEmails || []).map((email) =>
    result.state.users.find((user) => user.email === email)).filter(Boolean);
  delete result.notificationEmails;
  result.notifications = await Promise.all(recipients.map((user) =>
    sendPrivateAccessEmail({ state: result.state, user, request, reason, tournamentId })));
  // Merge delivery receipts only. Never save the pre-email workspace snapshot.
  const sent = recipients.filter((user) => result.notifications.some((entry) => entry.email === user.email && entry.status === "sent"));
  if (!sent.length) return;
  try {
    const latest = await withTransaction(async (client) => {
      const workspace = await readWorkspaceRecord(client, { forUpdate: true });
      for (const sentUser of sent) {
        const current = workspace.state.users.find((user) => user.email === sentUser.email);
        if (current) markPrivateAccessEmailSent(current, reason);
      }
      return writeWorkspaceState(client, workspace.state, { expectedRevision: workspace.revision });
    });
    result.state = latest.state;
    result.revision = latest.revision;
  } catch (error) {
    console.error("Registration saved; email receipt could not be recorded:", error.message);
  }
}

async function sendPasswordResetEmail({ request, user, token } = {}) {
  const targetUser = user && typeof user === "object" ? user : null;
  const email = normalizeEmail(targetUser?.email);
  if (!targetUser || !email) {
    return {
      email,
      status: "skipped",
      message: "No matching account was available for password reset delivery.",
    };
  }

  if (targetUser.active === false) {
    return {
      email,
      status: "skipped",
      message: "Password reset delivery is disabled for inactive accounts.",
    };
  }

  if (!RESEND_API_KEY || !RESEND_FROM_EMAIL) {
    console.warn(
      "Password reset email skipped because RESEND_API_KEY or RESEND_FROM_EMAIL is missing.",
    );
    return {
      email,
      status: "failed",
      message: "Email delivery is not configured on this backend yet.",
    };
  }

  const resetUrl = buildPasswordResetUrl(request, token);
  const recipientName = String(targetUser.name || "").trim() || "there";
  const subject = "Reset your " + DEFAULT_BRANDING.appName + " password";
  const text =
    "Hi " +
    recipientName +
    ",\n\n" +
    "Use this link to reset your " +
    DEFAULT_BRANDING.appName +
    " password. The link expires in " +
    PASSWORD_RESET_EXPIRY_MINUTES +
    " minutes.\n\n" +
    resetUrl +
    "\n\n" +
    "If you did not request this reset, you can ignore this email.\n";
  const html =
    "<p>Hi " +
    escapeEmailHtml(recipientName) +
    ",</p>" +
    "<p>Use this link to reset your <strong>" +
    escapeEmailHtml(DEFAULT_BRANDING.appName) +
    "</strong> password. The link expires in " +
    escapeEmailHtml(PASSWORD_RESET_EXPIRY_MINUTES) +
    " minutes.</p>" +
    "<p><a href=\"" +
    escapeEmailHtml(resetUrl) +
    "\">Reset your password</a></p>" +
    "<p>If you did not request this reset, you can ignore this email.</p>";

  try {
    const resendResponse = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + RESEND_API_KEY,
      },
      body: JSON.stringify({
        from: RESEND_FROM_EMAIL,
        to: [email],
        subject,
        text,
        html,
        ...(RESEND_REPLY_TO ? { reply_to: RESEND_REPLY_TO } : {}),
      }),
    });

    if (!resendResponse.ok) {
      let providerMessage = "Email provider rejected the request.";
      try {
        const payload = await resendResponse.json();
        if (payload?.message) {
          providerMessage = String(payload.message);
        }
      } catch (error) {
        // Keep the default provider message.
      }
      console.error("Password reset email delivery failed:", resendResponse.status, providerMessage);
      return {
        email,
        status: "failed",
        message: "Password reset email delivery failed.",
      };
    }

    return {
      email,
      status: "sent",
      message: "Password reset email sent.",
    };
  } catch (error) {
    console.error("Password reset email delivery crashed:", error);
    return {
      email,
      status: "failed",
      message: "Password reset email delivery failed.",
    };
  }
}

function collectPersistPrivateEmailTargets(previousState, nextState) {
  const previousUsersByEmail = new Map(
    (previousState?.users || []).map((user) => [normalizeEmail(user.email), user]),
  );
  const nextUsersByEmail = new Map(
    (nextState?.users || []).map((user) => [normalizeEmail(user.email), user]),
  );
  const recipients = new Map();

  const registerRecipient = (email, reason, tournamentId = "") => {
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail) {
      return;
    }
    if (!nextUsersByEmail.has(normalizedEmail)) {
      return;
    }
    if (!recipients.has(normalizedEmail)) {
      recipients.set(normalizedEmail, {
        email: normalizedEmail,
        reasons: new Set(),
        tournamentIds: new Set(),
      });
    }
    const entry = recipients.get(normalizedEmail);
    entry.reasons.add(reason);
    if (tournamentId) {
      entry.tournamentIds.add(String(tournamentId).trim());
    }
  };

  nextUsersByEmail.forEach((nextUser, email) => {
    const previousUser = previousUsersByEmail.get(email);
    if (!previousUser) {
      registerRecipient(email, "account_created");
      return;
    }
    if (previousUser.active === false && nextUser.active !== false) {
      registerRecipient(email, "account_reactivated");
    }
  });

  const previousTournaments = new Map(
    (previousState?.tournaments || []).map((tournament) => [
      String(tournament?.id || "").trim(),
      tournament,
    ]),
  );

  (nextState?.tournaments || []).forEach((tournament) => {
    const tournamentId = String(tournament?.id || "").trim();
    if (!tournamentId) {
      return;
    }
    const previousTournament = previousTournaments.get(tournamentId) || null;

    const previousParticipantEmails = new Set(
      (previousTournament?.participants || [])
        .map((participant) => normalizeEmail(participant?.email))
        .filter(Boolean),
    );
    (tournament?.participants || []).forEach((participant) => {
      const participantEmail = normalizeEmail(participant?.email);
      if (participantEmail && !previousParticipantEmails.has(participantEmail)) {
        registerRecipient(participantEmail, "participant_registration", tournamentId);
      }
    });

    const previousJudgeEmails = new Set(
      (previousTournament?.judges || [])
        .map((judge) => normalizeEmail(judge?.email))
        .filter(Boolean),
    );
    (tournament?.judges || []).forEach((judge) => {
      const judgeEmail = normalizeEmail(judge?.email);
      if (judgeEmail && !previousJudgeEmails.has(judgeEmail)) {
        registerRecipient(judgeEmail, "judge_registration", tournamentId);
      }
    });

    TOURNAMENT_PERMISSION_KEYS.forEach((key) => {
      const previousEmails = new Set(
        (previousTournament?.permissions?.[key] || [])
          .map((value) => normalizeEmail(value))
          .filter(Boolean),
      );
      (tournament?.permissions?.[key] || []).forEach((value) => {
        const permissionEmail = normalizeEmail(value);
        if (permissionEmail && !previousEmails.has(permissionEmail)) {
          registerRecipient(permissionEmail, "appointment", tournamentId);
        }
      });
    });
  });

  return Array.from(recipients.values()).map((entry) => ({
    email: entry.email,
    reasons: Array.from(entry.reasons),
    tournamentIds: Array.from(entry.tournamentIds),
  }));
}

function pickPersistEmailReason(reasons = []) {
  const normalizedReasons = new Set(
    (Array.isArray(reasons) ? reasons : []).map((reason) =>
      normalizePrivateAccessEmailReason(reason),
    ),
  );
  if (normalizedReasons.has("participant_registration")) return "participant_registration";
  if (normalizedReasons.has("judge_registration")) return "judge_registration";
  if (normalizedReasons.has("appointment")) return "appointment";
  if (normalizedReasons.has("account_reactivated")) return "account_reactivated";
  if (normalizedReasons.has("account_created")) return "account_created";
  return "registration";
}

async function deliverPersistPrivateAccessEmails({ previousState, nextState, request } = {}) {
  const targets = collectPersistPrivateEmailTargets(previousState, nextState);
  if (!targets.length) {
    return [];
  }

  const notifications = [];
  targets.forEach((target) => {
    const user = (nextState?.users || []).find(
      (entry) => normalizeEmail(entry.email) === normalizeEmail(target.email),
    );
    if (!user) {
      return;
    }
    notifications.push({
      user,
      reason: pickPersistEmailReason(target.reasons),
      tournamentId: String(target.tournamentIds[0] || "").trim(),
    });
  });

  const results = [];
  for (const notification of notifications) {
    // eslint-disable-next-line no-await-in-loop
    const result = await sendPrivateAccessEmail({
      state: nextState,
      user: notification.user,
      request,
      reason: notification.reason,
      tournamentId: notification.tournamentId,
      force: false,
    });
    results.push(result);
  }
  return results;
}

function buildRecoveryRequest(state, email, note = "", extraFields = {}) {
  const knownAccount = (state.users || []).some((user) => user.email === email);
  const submittedAt = nowText();
  const submittedAtKey = Date.now();
  const existing = (state.recoveryRequests || []).find(
    (request) => request.email === email && request.status === "open",
  );

  if (existing) {
    existing.note = note || existing.note;
    existing.knownAccount = knownAccount;
    existing.submittedAt = submittedAt;
    existing.submittedAtKey = submittedAtKey;
    Object.assign(existing, extraFields);
    return existing;
  }

  const entry = {
    id: createId("recovery"),
    email,
    note,
    knownAccount,
    submittedAt,
    submittedAtKey,
    status: "open",
    resolvedAt: "",
    resolvedBy: "",
    ...extraFields,
  };
  state.recoveryRequests.unshift(entry);
  return entry;
}

const app = express();

app.use(compression({ threshold: 1024 }));

app.use((request, response, next) => {
  const startedAt = Date.now();
  response.once("finish", () => {
    const elapsedMs = Date.now() - startedAt;
    const metrics = getRuntimeMetrics();
    if (elapsedMs >= SLOW_REQUEST_MS || metrics.memory.rssMb >= MEMORY_WARNING_MB) {
      console.warn("JADE runtime warning", {
        method: request.method,
        path: request.path,
        elapsedMs,
        ...metrics,
      });
    }
  });
  next();
});

app.use((request, response, next) => {
  const { allowed } = applyBrowserCorsHeaders(request, response);
  if (request.method === "OPTIONS") {
    response.status(allowed ? 204 : 403).end();
    return;
  }
  next();
});

app.use(createApiConcurrencyGate(API_CONCURRENCY, API_QUEUE_LIMIT));
app.use(express.json({ limit: MAX_BODY_SIZE }));

app.get("/api", async (_request, response) => {
  try {
    const client = await pool.connect();
    try {
      const workspace = await readWorkspaceRecord(client);
      sendJson(response, 200, {
        ok: true,
        initialized: Boolean(workspace?.state),
        storage: "postgres",
        workspaceId: WORKSPACE_ID,
        revision: normalizeWorkspaceRevision(workspace?.revision),
      });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(error);
    sendError(response, 500, "backend_unavailable", "JADE backend could not reach the database.");
  }
});

app.get("/api/health", async (_request, response) => {
  try {
    await pool.query("select 1");
    sendJson(response, 200, {
      ok: true,
      status: "healthy",
      ...getRuntimeMetrics(),
    });
  } catch (error) {
    console.error(error);
    sendError(response, 500, "backend_unhealthy", "JADE backend health check failed.");
  }
});

app.use(
  express.static(FRONTEND_DIR, {
    index: false,
    extensions: false,
  }),
);

app.get("/", (_request, response) => {
  response.sendFile(FRONTEND_ENTRY);
});

app.post("/api", async (request, response) => {
  const action = String(request.body?.action || "").trim();

  try {
    if (request.body?.sessionToken) {
      const client = await pool.connect();
      try {
        const session = await getSession(client, request.body.sessionToken);
        if (session?.access_scope?.role === "judge" || (session?.access_scope?.role === "member" && session.access_scope.accessTokenHash)) {
          if (session.access_scope.role === "judge" && !["get_state","get_revision","patch_tournament"].includes(action)) throw Object.assign(new Error("This judge link only permits tournament and ballot actions."), {statusCode:403});
          const workspace = await readWorkspaceRecord(client);
          const user = workspace?.state.users.find(u=>u.email===session.email);
          if (!user?.active || hashSessionToken(user.privateAccessToken) !== session.access_scope.accessTokenHash) throw Object.assign(new Error("This private link was revoked. Request a new link."),{statusCode:401,code:"invalid_session"});
        }
      } finally { client.release(); }
    }

    if (action === "private_entry_command") {
      const token = String(request.body?.privateToken || "");
      const result = await withTransaction(async client => {
        const workspace = await readWorkspaceRecord(client, {forUpdate:true});
        applyPrivateEntryCommand(workspace.state, token, request.body?.command || {});
        const saved = await writeWorkspaceState(client, workspace.state, {expectedRevision:workspace.revision});
        return {...saved, state:publicWorkspace(saved.state, token)};
      });
      sendStatePayload(response, 200, result);
      return;
    }
    if (action === "bootstrap") {
      const client = await pool.connect();
      try {
        const workspace = await readWorkspaceRecord(client);
        sendJson(response, 200, {
          ok: true,
          initialized: Boolean(workspace?.state),
          state: publicWorkspace(workspace?.state, String(request.body?.privateToken || "")),
          revision: normalizeWorkspaceRevision(workspace?.revision),
        });
        return;
      } finally {
        client.release();
      }
    }

    if (action === "sign_in") {
      const email = normalizeEmail(request.body?.email);
      const password = String(request.body?.password || "");

      const result = await withTransaction(async (client) => {
        const workspace = await readWorkspaceRecord(client);
        const state = workspace?.state;
        if (!state) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        const user = state.users.find((entry) => entry.email === email);
        if (!user) {
          const error = new Error("No account exists for that email address.");
          error.statusCode = 404;
          error.code = "account_not_found";
          throw error;
        }

        if (!user.active) {
          const error = new Error("This account has been disabled by the manager.");
          error.statusCode = 403;
          error.code = "account_disabled";
          throw error;
        }

        const passwordCheck = verifyUserPassword(user, password);
        if (!passwordCheck.ok) {
          const error = new Error("Incorrect password.");
          error.statusCode = 401;
          error.code = "invalid_password";
          throw error;
        }

        const needsPasswordUpgrade = passwordCheck.needsUpgrade;
        if (needsPasswordUpgrade) {
          Object.assign(user, buildSecurePasswordRecord(password));
        }

        user.lastLoginAt = nowText();
        let revision = workspace.revision;
        if (needsPasswordUpgrade) {
          const nextWorkspace = await writeWorkspaceState(client, state, {
            expectedRevision: workspace.revision,
          });
          revision = nextWorkspace.revision;
        }
        const accountAccess = getAuthenticatedAccountAccess(state, email);
        const sessionToken = await issueSession(client, email, accountAccess.sessionScope);
        return {
          state: accountAccess.state,
          revision,
          sessionToken,
        };
      });

      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "initialize") {
      const email = normalizeEmail(request.body?.email);
      const password = String(request.body?.password || "");
      const incomingState = request.body?.state;

      assertWorkspaceContract(incomingState, "initialize payload", {
        allowMissingVersion: true,
      });

      const result = await withTransaction(async (client) => {
        const existingWorkspace = await readWorkspaceRecord(client);
        if (existingWorkspace?.state) {
          const error = new Error("The shared backend workspace has already been initialized.");
          error.statusCode = 409;
          error.code = "workspace_already_initialized";
          throw error;
        }

        // The parsed request body is already isolated to this request. Normalize
        // it in place instead of creating another full workspace-sized object.
        const nextState = ensureWorkspaceState(incomingState, { clone: false });
        const user = nextState.users.find((entry) => entry.email === email);

        if (!user) {
          const error = new Error("The manager account could not be found in the uploaded workspace.");
          error.statusCode = 404;
          error.code = "account_not_found";
          throw error;
        }

        if (!isSystemAdmin(nextState, email)) {
          const error = new Error("Only a System Manager can initialize the shared backend workspace.");
          error.statusCode = 403;
          error.code = "forbidden";
          throw error;
        }

        const passwordCheck = verifyUserPassword(user, password);
        if (!passwordCheck.ok) {
          const error = new Error("Incorrect password.");
          error.statusCode = 401;
          error.code = "invalid_password";
          throw error;
        }

        if (passwordCheck.needsUpgrade) {
          Object.assign(user, buildSecurePasswordRecord(password));
        }

        user.lastLoginAt = nowText();
        const savedWorkspace = await writeWorkspaceState(client, nextState);
        const sessionToken = await issueSession(client, email);
        return {
          state: savedWorkspace.state,
          revision: savedWorkspace.revision,
          sessionToken,
        };
      });

      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "sign_up") {
      const name = String(request.body?.name || "").trim();
      const email = normalizeEmail(request.body?.email);
      const password = String(request.body?.password || "");

      const result = await withTransaction(async (client) => {
        const workspace = await readWorkspaceRecord(client);
        const state = workspace?.state;
        if (!state) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        if (state.appSettings?.auth?.allowSelfSignup === false) {
          const error = new Error("Self sign-up is currently disabled.");
          error.statusCode = 403;
          error.code = "signup_disabled";
          throw error;
        }

        const minimumPasswordLength = Number(
          state.appSettings?.auth?.minimumPasswordLength || 12,
        );

        if (password.length < minimumPasswordLength) {
          const error = new Error(
            "Password must be at least " + minimumPasswordLength + " characters long.",
          );
          error.statusCode = 422;
          error.code = "password_too_short";
          throw error;
        }

        const shouldBootstrapManager = !hasSystemAdminAccounts(state);
        const existingUser = state.users.find((user) => user.email === email) || null;
        let targetUser = null;
        if (existingUser) {
          if (!existingUser.active) {
            const error = new Error("This account has been disabled by the manager.");
            error.statusCode = 403;
            error.code = "account_disabled";
            throw error;
          }
          if (canClaimRegisteredAccount(existingUser)) {
            Object.assign(existingUser, buildSecurePasswordRecord(password), {
              name: name || existingUser.name,
              globalRole: shouldBootstrapManager ? "manager" : existingUser.globalRole,
              createdSource: "self_signup",
              createdBy: normalizeEmail(email),
              lastLoginAt: nowText(),
            });
            targetUser = existingUser;
          } else {
            const error = new Error("An account with that email already exists.");
            error.statusCode = 409;
            error.code = "account_exists";
            throw error;
          }
        } else {
          const user = buildUser(name, email, shouldBootstrapManager ? "manager" : "member", password, {
            createdSource: "self_signup",
            createdBy: normalizeEmail(email),
          });
          user.lastLoginAt = nowText();
          state.users.push(user);
          targetUser = user;
        }

        if (!targetUser) {
          targetUser = state.users.find((user) => user.email === email) || null;
        }

        const notifications = [];
        if (targetUser) {
          notifications.push(
            await sendPrivateAccessEmail({
              state,
              user: targetUser,
              request,
              reason: "sign_up",
            }),
          );
        }

        const nextWorkspace = await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        const accountAccess = getAuthenticatedAccountAccess(nextWorkspace.state, email);
        const sessionToken = await issueSession(client, email, accountAccess.sessionScope);
        return {
          state: accountAccess.state,
          revision: nextWorkspace.revision,
          sessionToken,
          notifications,
        };
      });

      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "register_debater") {
      const tournamentId = String(request.body?.tournamentId || "").trim();
      const name = String(request.body?.name || "").trim();
      const email = normalizeEmail(request.body?.email);
      const password = String(request.body?.password || "");
      const institution = String(request.body?.institution || "").trim();
      const teamName = String(request.body?.teamName || "").trim();
      const teammates = Array.isArray(request.body?.teammates)
        ? request.body.teammates.map((entry) => ({
            name: String(entry?.name || "").trim(),
            email: normalizeEmail(entry?.email),
          }))
        : [{
            name: String(request.body?.teammateName || "").trim(),
            email: normalizeEmail(request.body?.teammateEmail),
          }].filter((entry) => entry.name || entry.email);
      const notes = String(request.body?.notes || "").trim();

      const result = await withTransaction(async (client) => {
        const workspace = await readWorkspaceRecord(client, { forUpdate: true });
        const state = workspace?.state;
        if (!state) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        const tournament =
          (state.tournaments || []).find((entry) => String(entry.id || "").trim() === tournamentId) ||
          null;
        if (!tournament) {
          const error = new Error("Choose a tournament before registering.");
          error.statusCode = 404;
          error.code = "tournament_not_found";
          throw error;
        }

        const availability = getTournamentRegistrationAvailability(tournament, "debater");
        if (!availability.open) {
          const error = new Error(availability.reason);
          error.statusCode = 409;
          error.code = "registration_closed";
          throw error;
        }

        if (!name || !email || !institution || !teamName) {
          const error = new Error(
            "Tournament, name, email, institution, and team name are required.",
          );
          error.statusCode = 422;
          error.code = "missing_registration_fields";
          throw error;
        }

        const requiredTeammates = getRegistrationTeamSize(tournament) - 1;
        const rosterEmails = [email, ...teammates.map((entry) => entry.email)];
        if (teammates.length !== requiredTeammates ||
            teammates.some((entry) => !entry.name || !entry.email) ||
            new Set(rosterEmails).size !== rosterEmails.length) {
          const error = new Error("Enter a name and a unique email for all " +
            getRegistrationTeamSize(tournament) + " team members, including yourself.");
          error.statusCode = 422;
          error.code = "invalid_team_roster";
          throw error;
        }
        const rosterConflict = getTournamentRegistrationRosterConflict(tournament, teamName, institution, rosterEmails);
        if (rosterConflict) {
          const error = new Error(rosterConflict);
          error.statusCode = 409;
          error.code = "team_roster_conflict";
          throw error;
        }

        const registeredUser = ensureRegistrationUser(state, {
          name,
          email,
          password,
          createdSource: "self_signup",
          createdBy: email,
          requirePassword: true,
          markLoggedIn: true,
        });

        const teammateUsers = teammates.map((teammate) =>
          ensureRegistrationUser(state, {
            name: teammate.name,
            email: teammate.email,
            createdSource: "registered",
            createdBy: email,
            requirePassword: false,
            markLoggedIn: false,
          }));

        const team = upsertTournamentRegistrationTeam(tournament, teamName, institution, notes);
        upsertTournamentParticipantRegistration(tournament, {
          name,
          email,
          institution,
          team,
          teamName,
        });

        for (const teammate of teammates) {
          upsertTournamentParticipantRegistration(tournament, {
            name: teammate.name,
            email: teammate.email,
            institution,
            team,
            teamName,
          });
        }

        rememberUserTournamentHistory(state, email, tournamentId);
        teammates.forEach((teammate) => rememberUserTournamentHistory(state, teammate.email, tournamentId));
        addTournamentAuditEntry(
          tournament,
          email,
          "Registered " +
            name +
            " for " +
            tournament.name +
            (teamName ? " under team " + teamName + "." : "."),
        );

        const notificationEmails = [registeredUser, ...teammateUsers].filter(Boolean).map((user) => user.email);

        const savedWorkspace = await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        const accountAccess = getAuthenticatedAccountAccess(savedWorkspace.state, email);
        const sessionToken = await issueSession(client, email, accountAccess.sessionScope);
        return {
          state: savedWorkspace.state,
          revision: savedWorkspace.revision,
          sessionToken,
          notificationEmails,
        };
      });

      await deliverCommittedRegistrationEmails(result, request, "participant_registration", tournamentId);
      result.state = getAuthenticatedAccountAccess(result.state, email).state;
      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "register_judge") {
      const tournamentId = String(request.body?.tournamentId || "").trim();
      const name = String(request.body?.name || "").trim();
      const email = normalizeEmail(request.body?.email);
      const password = String(request.body?.password || "");
      const institution = String(request.body?.institution || "").trim();
      const affiliationType = String(request.body?.affiliationType || "").trim();
      const notes = String(request.body?.notes || "").trim();

      const result = await withTransaction(async (client) => {
        const workspace = await readWorkspaceRecord(client, { forUpdate: true });
        const state = workspace?.state;
        if (!state) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        const tournament =
          (state.tournaments || []).find((entry) => String(entry.id || "").trim() === tournamentId) ||
          null;
        if (!tournament) {
          const error = new Error("Choose a tournament before registering.");
          error.statusCode = 404;
          error.code = "tournament_not_found";
          throw error;
        }

        const availability = getTournamentRegistrationAvailability(tournament, "judge");
        if (!availability.open) {
          const error = new Error(availability.reason);
          error.statusCode = 409;
          error.code = "registration_closed";
          throw error;
        }

        if (!name || !email) {
          const error = new Error("Tournament, name, and email are required.");
          error.statusCode = 422;
          error.code = "missing_registration_fields";
          throw error;
        }

        if (
          normalizeJudgeAffiliationType(affiliationType, institution) === "institutional" &&
          !institution
        ) {
          const error = new Error(
            "Institutionally affiliated judges must enter an institution.",
          );
          error.statusCode = 422;
          error.code = "missing_institution";
          throw error;
        }

        const registeredUser = ensureRegistrationUser(state, {
          name,
          email,
          password,
          createdSource: "self_signup",
          createdBy: email,
          requirePassword: true,
          markLoggedIn: true,
        });

        upsertTournamentJudgeRegistration(tournament, {
          name,
          email,
          institution,
          affiliationType,
          notes,
        });

        rememberUserTournamentHistory(state, email, tournamentId);
        addTournamentAuditEntry(
          tournament,
          email,
          "Registered judge " + name + " for " + tournament.name + ".",
        );

        const notificationEmails = [registeredUser].filter(Boolean).map((user) => user.email);

        const savedWorkspace = await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        const accountAccess = getAuthenticatedAccountAccess(savedWorkspace.state, email);
        const sessionToken = await issueSession(client, email, accountAccess.sessionScope);
        return {
          state: savedWorkspace.state,
          revision: savedWorkspace.revision,
          sessionToken,
          notificationEmails,
        };
      });

      await deliverCommittedRegistrationEmails(result, request, "judge_registration", tournamentId);
      result.state = getAuthenticatedAccountAccess(result.state, email).state;
      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "access_link") {
      const token = String(request.body?.token || "").trim();

      const result = await withTransaction(async (client) => {
        const workspace = await readWorkspaceRecord(client, {forUpdate:true});
        const state = workspace?.state;
        if (!state) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        const user = getUserByAccessToken(state, token);
        if (!user) {
          const error = new Error("That private access URL is no longer valid.");
          error.statusCode = 404;
          error.code = "invalid_access_link";
          throw error;
        }

        if (!user.active) {
          const error = new Error("This private access URL belongs to a disabled account.");
          error.statusCode = 403;
          error.code = "account_disabled";
          throw error;
        }

        const tournamentId = String(request.body?.tournamentId || "").trim();
        const systemAdmin = isSystemAdmin(state,user.email);
        if (systemAdmin && !tournamentId) throw Object.assign(new Error("Use your password to sign in to this account."),{statusCode:403,code:"password_sign_in_required"});

        user.lastLoginAt = nowText();
        user.lastPrivateAccessAt = nowText();

        const nextWorkspace = await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        const scopedState = tournamentId ? judgeWorkspace(nextWorkspace.state, user.email, tournamentId) : null;
        const memberScope = systemAdmin ? null : {role:"member",email:user.email,accessTokenHash:hashSessionToken(token)};
        const sessionToken = await issueSession(client, user.email, tournamentId ? {role:"judge",tournamentId,accessTokenHash:hashSessionToken(token)} : memberScope);
        return {
          state: scopedState || (memberScope ? memberWorkspace(nextWorkspace.state,user.email,{includeJudgeWorkspaces:false}) : nextWorkspace.state),
          revision: nextWorkspace.revision,
          sessionToken,
          userEmail: user.email,
        };
      });

      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "send_private_link_email") {
      const sessionToken = String(request.body?.sessionToken || "").trim();
      const targetEmail = normalizeEmail(request.body?.email);
      const reason = String(request.body?.reason || "manual_resend").trim();
      const tournamentId = String(request.body?.tournamentId || "").trim();
      const portal = normalizePrivateAccessPortal(request.body?.portal || "");
      const force = Boolean(request.body?.force);

      const result = await withTransaction(async (client) => {
        const session = await getSession(client, sessionToken);
        if (!session) {
          const error = new Error("Your backend session has expired. Please sign in again.");
          error.statusCode = 401;
          error.code = "invalid_session";
          throw error;
        }

        const workspace = await readWorkspaceRecord(client);
        const state = workspace?.state;
        if (!state) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        const actorEmail = normalizeEmail(session.email);
        const actor = state.users.find((entry) => normalizeEmail(entry.email) === actorEmail);
        if (!actor || !actor.active) {
          const error = new Error("This account is no longer allowed to access JADE.");
          error.statusCode = 403;
          error.code = "account_disabled";
          throw error;
        }

        const canManageAll = isSystemAdmin(state, actorEmail);
        if (!canManageAll && targetEmail !== actorEmail) {
          const error = new Error("You can only send your own private URL email.");
          error.statusCode = 403;
          error.code = "forbidden_target_email";
          throw error;
        }

        const targetUser = state.users.find(
          (entry) => normalizeEmail(entry.email) === normalizeEmail(targetEmail),
        );
        if (!targetUser) {
          const error = new Error("That account could not be found.");
          error.statusCode = 404;
          error.code = "account_not_found";
          throw error;
        }

        const notification = await sendPrivateAccessEmail({
          state,
          user: targetUser,
          request,
          reason,
          tournamentId,
          force,
          portal,
        });

        let savedWorkspace = {
          state,
          revision: workspace.revision,
        };

        if (notification.status === "sent") {
          savedWorkspace = await writeWorkspaceState(client, state, {
            expectedRevision: workspace.revision,
          });
        }

        return {
          state: getAuthenticatedAccountAccess(savedWorkspace.state, actorEmail).state,
          revision: savedWorkspace.revision,
          delivered: notification.status === "sent",
          skipped: notification.status === "skipped_cooldown",
          reason: notification.reason,
          cooldownRemainingSeconds: Number(notification.cooldownRemainingSeconds || 0),
          notifications: [notification],
        };
      });

      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "get_state") {
      const sessionToken = String(request.body?.sessionToken || "").trim();

      const result = await withTransaction(async (client) => {
        const session = await getSession(client, sessionToken);
        if (!session) {
          const error = new Error("Your backend session has expired. Please sign in again.");
          error.statusCode = 401;
          error.code = "invalid_session";
          throw error;
        }

        const workspace = await readWorkspaceRecord(client);
        const state = workspace?.state;
        if (!state) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        const user = state.users.find((entry) => entry.email === normalizeEmail(session.email));
        if (!user || !user.active) {
          const error = new Error("This account is no longer allowed to access JADE.");
          error.statusCode = 403;
          error.code = "account_disabled";
          throw error;
        }

        return {
          state: session.access_scope?.role === "judge" ? judgeWorkspace(state, session.email, session.access_scope.tournamentId) : session.access_scope?.role === "member" ? memberWorkspace(state, session.email,{includeJudgeWorkspaces:!session.access_scope.accessTokenHash}) : state,
          revision: workspace.revision,
        };
      });

      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "get_revision") {
      const sessionToken = String(request.body?.sessionToken || "").trim();

      const result = await withTransaction(async (client) => {
        const session = await getSession(client, sessionToken);
        if (!session) {
          const error = new Error("Your backend session has expired. Please sign in again.");
          error.statusCode = 401;
          error.code = "invalid_session";
          throw error;
        }

        const revision = await readWorkspaceRevision(client);
        if (!revision) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        return {
          revision,
        };
      });

      sendJson(response, 200, {
        ok: true,
        initialized: true,
        revision: normalizeWorkspaceRevision(result.revision),
      });
      return;
    }

    if (action === "patch_tournament") {
      const result = await withTransaction(async (client) => {
        const session = await getSession(client, String(request.body?.sessionToken || ""));
        if (!session) throw Object.assign(new Error("Sign in again."), {statusCode:401, code:"invalid_session"});
        const workspace = await readWorkspaceRecord(client, {forUpdate:true});
        const current = workspace?.state;
        const user = current?.users.find(entry => entry.email === normalizeEmail(session.email));
        if (!user?.active) throw Object.assign(new Error("Account unavailable."), {statusCode:403});
        if (session.access_scope?.role === "judge" && session.access_scope.tournamentId !== request.body?.tournamentId) throw Object.assign(new Error("This link belongs to a different tournament."),{statusCode:403});
        const index = current.tournaments.findIndex(entry => entry.id === request.body?.tournamentId);
        if (index < 0) throw Object.assign(new Error("Tournament not found."), {statusCode:404});
        if (session.access_scope?.role === "member" && isSystemAdmin(current,session.email)) throw Object.assign(new Error("Your account access changed. Sign in again to refresh permissions."),{statusCode:401,code:"invalid_session"});
        if (session.access_scope?.role === "member") {
          const tournament=current.tournaments[index], actor=normalizeEmail(session.email);
          const staffKeys=["managerEmails","tabManagerEmails","tabDirectorEmails","caTeamEmails","tournamentDirectorEmails","convenorEmails","registrationOfficerEmails","financeOfficerEmails","equityOfficerEmails"];
          const canManage=normalizeEmail(tournament.ownerEmail)===actor || staffKeys.some(key=>(tournament.permissions?.[key] || []).some(value=>normalizeEmail(value)===actor));
          const isJudge=(tournament.judges || []).some(entry=>normalizeEmail(entry.email)===actor);
          if (!canManage && !(isJudge && !session.access_scope.accessTokenHash)) throw Object.assign(new Error("This account cannot edit tournament records."),{statusCode:403});
        }
        // Keep the workspace shell and copy only the edited tournament. The
        // database row is request-local, so unrelated tournament records can
        // be shared safely while the scoped patch is applied.
        const next = {...current,tournaments:[...current.tournaments]};
        try { next.tournaments[index] = applyTournamentChanges(current.tournaments[index], request.body?.changes); }
        catch (error) { error.statusCode = error.code === "edit_conflict" ? 409 : 422; throw error; }
        if (next.tournaments[index].id !== current.tournaments[index].id) throw Object.assign(new Error("Tournament identity cannot change."), {statusCode:422});
        assertDrawReleaseIntegrity(current.tournaments[index], next.tournaments[index]);
        assertScoringPersistAuthorization(current, next, session.email, session.access_scope?.role === "judge");
        const hasChanges = JSON.stringify(next.tournaments[index]) !== JSON.stringify(current.tournaments[index]);
        const saved = hasChanges
          ? await writeWorkspaceState(client, next, {expectedRevision:workspace.revision, clone:false, returnState:false})
          : {revision:workspace.revision};
        const updatedTournament = next.tournaments[index];
        const tournament = session.access_scope?.role === "judge"
          ? judgeWorkspace(next,session.email,session.access_scope.tournamentId).tournaments.find(entry => entry.id === updatedTournament.id)
          : session.access_scope?.role === "member"
            ? memberWorkspace(next,session.email,{includeJudgeWorkspaces:!session.access_scope.accessTokenHash}).tournaments.find(entry => entry.id === updatedTournament.id)
            : updatedTournament;
        return {revision:saved.revision,tournament};
      });
      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "persist") {
      const sessionToken = String(request.body?.sessionToken || "").trim();
      const incomingState = request.body?.state;
      const expectedRevision = normalizeWorkspaceRevision(request.body?.expectedRevision);

      if (!expectedRevision) {
        sendError(response, 409, "missing_revision", "Load the latest shared workspace before saving an edit.");
        return;
      }

      assertWorkspaceContract(incomingState, "persist payload");
      if (incomingState.readOnlyProjection) throw Object.assign(new Error("This view cannot replace the shared workspace."), {statusCode:403});

      const result = await withTransaction(async (client) => {
        const session = await getSession(client, sessionToken);
        if (!session) {
          const error = new Error("Your backend session has expired. Please sign in again.");
          error.statusCode = 401;
          error.code = "invalid_session";
          throw error;
        }

        const workspace = await readWorkspaceRecord(client, {forUpdate:true});
        const currentState = workspace?.state;
        if (!currentState) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        // Express has already created an isolated request object. Normalizing
        // that object in place avoids another complete workspace clone during
        // every autosave.
        const nextState = ensureWorkspaceState(incomingState, { clone: false });
        const user = currentState.users.find((entry) => entry.email === normalizeEmail(session.email));
        if (!user || !user.active) {
          const error = new Error("This account is no longer allowed to access JADE.");
          error.statusCode = 403;
          error.code = "account_disabled";
          throw error;
        }

        if (session.access_scope?.role === "member") {
          const projectedUser=(incomingState.users || []).find(entry=>normalizeEmail(entry.email)===normalizeEmail(session.email));
          if (!projectedUser) throw Object.assign(new Error("The account preference update is invalid."),{statusCode:403});
          const nextState=structuredClone(currentState);
          const target=nextState.users.find(entry=>normalizeEmail(entry.email)===normalizeEmail(session.email));
          const landing=String(projectedUser.preferredLandingView || "").trim().slice(0,64);
          if (landing) target.preferredLandingView=landing;
          for (const key of ["pinnedTournamentIds","archivedTournamentIds","deletedTournamentIds"]) {
            target[key]=normalizeStringList(projectedUser[key],key==="pinnedTournamentIds" ? 12 : 200);
          }
          const saved=await writeWorkspaceState(client,nextState,{expectedRevision});
          return {revision:saved.revision,notifications:[],state:memberWorkspace(saved.state,session.email,{includeJudgeWorkspaces:!session.access_scope.accessTokenHash})};
        }
        if (session.access_scope) throw Object.assign(new Error("This account must save changes through its tournament records."),{statusCode:403,code:"patch_required"});
        assertScoringPersistAuthorization(currentState, nextState, session.email);

        const notifications = await deliverPersistPrivateAccessEmails({
          previousState: currentState,
          nextState,
          request,
        });

        const savedWorkspace = await writeWorkspaceState(client, nextState, {
          expectedRevision,
          normalized: true,
          returnState: false,
        });
        return {
          revision: savedWorkspace.revision,
          notifications,
        };
      });

      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "patch_workspace") {
      const result = await withTransaction(async (client) => {
        const session = await getSession(client, String(request.body?.sessionToken || ""));
        if (!session) throw Object.assign(new Error("Sign in again."), {statusCode:401, code:"invalid_session"});
        const workspace = await readWorkspaceRecord(client, {forUpdate:true});
        const current = workspace?.state;
        const actor = normalizeEmail(session.email);
        const user = current?.users.find(entry => normalizeEmail(entry.email) === actor);
        if (!user?.active) throw Object.assign(new Error("Account unavailable."), {statusCode:403});
        if (session.access_scope || !isSystemAdmin(current, actor)) {
          throw Object.assign(new Error("Only System Managers can edit shared workspace settings."), {statusCode:403, code:"forbidden_workspace_patch"});
        }
        let next;
        try {
          next = applyTournamentChanges(current, request.body?.changes);
        } catch (error) {
          error.statusCode = error.code === "edit_conflict" ? 409 : 422;
          throw error;
        }
        assertWorkspaceContract(next, "workspace patch");
        assertScoringPersistAuthorization(current, next, actor);
        if (JSON.stringify(next) === JSON.stringify(current)) return {revision:workspace.revision, notifications:[]};
        const notifications = await deliverPersistPrivateAccessEmails({previousState:current,nextState:next,request});
        const saved = await writeWorkspaceState(client, next, {expectedRevision:workspace.revision, clone:false, returnState:false});
        return {revision:saved.revision, notifications};
      });
      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "request_password_reset") {
      const email = normalizeEmail(request.body?.email);
      const note = String(request.body?.note || "").trim();

      const result = await withTransaction(async (client) => {
        const workspace = await readWorkspaceRecord(client);
        const state = workspace?.state;
        if (!state) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        if (!email) {
          const error = new Error("Enter the email address linked to your account.");
          error.statusCode = 422;
          error.code = "missing_email";
          throw error;
        }

        const user =
          (state.users || []).find((entry) => normalizeEmail(entry.email) === email) || null;
        const token = user?.active === false ? "" : createPasswordResetToken();
        const tokenHash = token ? hashPasswordResetToken(token) : "";
        const expiresAtKey = token ? Date.now() + PASSWORD_RESET_EXPIRY_MS : 0;
        const recoveryRequest = buildRecoveryRequest(state, email, note, {
          selfService: true,
          resetTokenHash: tokenHash,
          resetTokenExpiresAtKey: expiresAtKey,
          resetTokenExpiresAt: expiresAtKey ? new Date(expiresAtKey).toISOString() : "",
          resetSentAt: "",
          resetEmailStatus: "",
        });

        let notification = {
          email,
          status: "skipped",
          message: "If the account exists, a reset email will be sent.",
        };
        if (user && token) {
          notification = await sendPasswordResetEmail({ request, user, token });
          recoveryRequest.resetSentAt = nowText();
          recoveryRequest.resetEmailStatus = notification.status;
        }

        await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        return { accepted: true };
      });

      sendJson(response, 200, { ok: true, accepted: Boolean(result.accepted) });
      return;
    }

    if (action === "reset_password_with_token") {
      const token = String(request.body?.token || "").trim();
      const password = String(request.body?.password || "");

      const result = await withTransaction(async (client) => {
        const workspace = await readWorkspaceRecord(client);
        const state = workspace?.state;
        if (!state) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        const minimumPasswordLength = Number(state.appSettings?.auth?.minimumPasswordLength || 12);
        if (password.length < minimumPasswordLength) {
          const error = new Error(
            "Password must be at least " + minimumPasswordLength + " characters long.",
          );
          error.statusCode = 422;
          error.code = "password_too_short";
          throw error;
        }

        const tokenHash = hashPasswordResetToken(token);
        const recoveryRequest =
          (state.recoveryRequests || []).find(
            (entry) =>
              entry?.status === "open" &&
              String(entry?.resetTokenHash || "").trim() &&
              String(entry?.resetTokenHash || "").trim() === tokenHash,
          ) || null;

        if (!recoveryRequest) {
          const error = new Error("This reset link is invalid or has already been used.");
          error.statusCode = 404;
          error.code = "invalid_reset_token";
          throw error;
        }

        if (Number(recoveryRequest.resetTokenExpiresAtKey || 0) < Date.now()) {
          recoveryRequest.status = "expired";
          recoveryRequest.resolvedAt = nowText();
          recoveryRequest.resolvedBy = "system";
          recoveryRequest.resetTokenHash = "";
          const error = new Error("This reset link has expired. Please request a new one.");
          error.statusCode = 410;
          error.code = "reset_token_expired";
          throw error;
        }

        const user =
          (state.users || []).find(
            (entry) => normalizeEmail(entry.email) === normalizeEmail(recoveryRequest.email),
          ) || null;
        if (!user || user.active === false) {
          const error = new Error("This account is not available for password reset.");
          error.statusCode = 403;
          error.code = "account_unavailable";
          throw error;
        }

        Object.assign(user, buildSecurePasswordRecord(password));
        user.passwordUpdatedAt = nowText();
        recoveryRequest.status = "resolved";
        recoveryRequest.resolvedAt = nowText();
        recoveryRequest.resolvedBy = normalizeEmail(user.email);
        recoveryRequest.resetTokenHash = "";
        recoveryRequest.resetTokenExpiresAtKey = 0;
        recoveryRequest.resetTokenExpiresAt = "";

        await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        return { reset: true };
      });

      sendJson(response, 200, { ok: true, reset: Boolean(result.reset) });
      return;
    }

    sendError(response, 400, "unknown_action", "The requested JADE backend action is not supported.");
  } catch (error) {
    console.error(error);
    sendError(
      response,
      Number(error.statusCode || 500),
      error.code || "backend_error",
      error.message || "JADE backend request failed.",
    );
  }
});

let httpServer = null;
let sessionCleanupTimer = null;
let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}; closing JADE Hummingbird cleanly.`);

  const forceExitTimer = setTimeout(() => {
    console.error("JADE Hummingbird shutdown timed out.");
    process.exit(1);
  }, 10000);
  forceExitTimer.unref();

  if (httpServer) {
    await new Promise((resolve) => httpServer.close(resolve));
  }
  if (sessionCleanupTimer) clearInterval(sessionCleanupTimer);
  await pool.end();
  clearTimeout(forceExitTimer);
  process.exit(0);
}

process.once("SIGTERM", () => {
  shutdown("SIGTERM").catch((error) => {
    console.error(error);
    process.exit(1);
  });
});
process.once("SIGINT", () => {
  shutdown("SIGINT").catch((error) => {
    console.error(error);
    process.exit(1);
  });
});

ensureStorageSchema()
  .then(() => compactOversizedEmbeddedAssets())
  .then(() => {
    sessionCleanupTimer = setInterval(() => {
      pool.query("delete from jade_sessions where expires_at <= now()")
        .catch((error) => console.error("Expired session cleanup failed:", error.message));
    }, 15 * 60 * 1000);
    sessionCleanupTimer.unref?.();
    httpServer = app.listen(PORT, () => {
      console.log("JADE backend listening on http://127.0.0.1:" + PORT + "/api");
      console.log("JADE app available at http://127.0.0.1:" + PORT + "/");
    });
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
