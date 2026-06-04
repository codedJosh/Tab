import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import dotenv from "dotenv";
import express from "express";
import { Pool } from "pg";

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
const PRIVATE_LINK_EMAIL_COOLDOWN_MINUTES = Math.max(
  0,
  Number(process.env.PRIVATE_LINK_EMAIL_COOLDOWN_MINUTES || 10) || 10,
);
const PRIVATE_LINK_EMAIL_COOLDOWN_MS = PRIVATE_LINK_EMAIL_COOLDOWN_MINUTES * 60 * 1000;
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
const PASSWORD_HASH_VERSION = "pbkdf2-sha256-v1";
const PASSWORD_HASH_ITERATIONS = 210000;
const PASSWORD_SALT_BYTES = 16;
const MAX_BODY_SIZE = "30mb";
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

if (!DATABASE_URL) {
  throw new Error("Missing DATABASE_URL for JADE backend.");
}

if (!JADE_SESSION_SECRET) {
  throw new Error("Missing JADE_SESSION_SECRET for JADE backend.");
}

const shouldUseSsl =
  DATABASE_SSL === "true" ||
  (DATABASE_SSL !== "false" &&
    !/localhost|127\.0\.0\.1/i.test(DATABASE_URL));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: shouldUseSsl ? { rejectUnauthorized: false } : false,
});

async function ensureStorageSchema() {
  const client = await pool.connect();
  try {
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

function teamsLookEquivalent(left, right) {
  if (!left || !right) {
    return false;
  }

  const leftId = String(left.id || "").trim();
  const rightId = String(right.id || "").trim();
  if (leftId && rightId && leftId === rightId) {
    return true;
  }

  const leftName = normalizeTextKey(left.name);
  const rightName = normalizeTextKey(right.name);
  const leftInstitution = normalizeTextKey(left.institution);
  const rightInstitution = normalizeTextKey(right.institution);
  const leftDisplay = normalizeTextKey(
    [left.institution, left.name].filter(Boolean).join(" "),
  );
  const rightDisplay = normalizeTextKey(
    [right.institution, right.name].filter(Boolean).join(" "),
  );

  return Boolean(
    (leftName && rightName && leftName === rightName && leftInstitution === rightInstitution) ||
      (leftDisplay && rightDisplay && leftDisplay === rightDisplay),
  );
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

function ensureWorkspaceState(state) {
  const next = state && typeof state === "object" ? clone(state) : {};
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
      if (String(password || "").length < minimumPasswordLength) {
        const error = new Error(
          "Password must be at least " + minimumPasswordLength + " characters long.",
        );
        error.statusCode = 422;
        error.code = "password_too_short";
        throw error;
      }

      const passwordCheck = verifyUserPassword(existingUser, password);
      if (!passwordCheck.ok) {
        if (canClaimRegisteredAccount(existingUser)) {
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
  const existingTeam =
    (Array.isArray(tournament.teams) ? tournament.teams : []).find((team) =>
      teamsLookEquivalent(team, candidate),
    ) || null;

  if (existingTeam) {
    tournament.teams = (tournament.teams || []).map((team) =>
      team.id === existingTeam.id
        ? {
            ...team,
            institution: team.institution || normalizedInstitution,
            notes: team.notes || notes,
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

async function readWorkspaceRecord(client) {
  const result = await client.query(
    "select state, revision from jade_workspaces where id = $1 limit 1",
    [WORKSPACE_ID],
  );
  if (!result.rows[0]?.state) {
    return null;
  }
  return {
    state: ensureWorkspaceState(result.rows[0].state),
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
  const normalized = ensureWorkspaceState(state);
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
        returning state, revision
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
        returning state, revision
      `,
      params,
    );
  }

  const savedState = ensureWorkspaceState(result.rows[0]?.state || normalized);
  const revision = normalizeWorkspaceRevision(result.rows[0]?.revision) || 1;
  await client.query(
    `
      insert into jade_workspace_history (workspace_id, revision, state)
      values ($1, $2, $3::jsonb)
      on conflict (workspace_id, revision) do nothing
    `,
    [WORKSPACE_ID, revision, JSON.stringify(savedState)],
  );
  return {
    state: savedState,
    revision,
  };
}

async function purgeExpiredSessions(client) {
  await client.query("delete from jade_sessions where expires_at <= now()");
}

async function issueSession(client, email) {
  const token = createSessionToken();
  const tokenHash = hashSessionToken(token);
  const id = createId("session");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

  await client.query(
    `
      insert into jade_sessions (id, workspace_id, email, token_hash, expires_at)
      values ($1, $2, $3, $4, $5)
    `,
    [id, WORKSPACE_ID, normalizeEmail(email), tokenHash, expiresAt],
  );

  return token;
}

async function getSession(client, token) {
  await purgeExpiredSessions(client);

  const tokenHash = hashSessionToken(token);
  const result = await client.query(
    `
      select id, workspace_id, email, expires_at
      from jade_sessions
      where token_hash = $1 and workspace_id = $2
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

function resolveRequestOrigin(request) {
  const originHeader = String(request?.headers?.origin || "").trim();
  if (originHeader) {
    try {
      const parsed = new URL(originHeader);
      return parsed.origin;
    } catch (error) {
      // Ignore invalid origin headers.
    }
  }

  const forwardedProto = String(request?.headers?.["x-forwarded-proto"] || "")
    .split(",")[0]
    .trim();
  const forwardedHost = String(request?.headers?.["x-forwarded-host"] || "")
    .split(",")[0]
    .trim();
  const host = forwardedHost || String(request?.headers?.host || "").trim();
  if (host) {
    const protocol = forwardedProto || request?.protocol || "https";
    return protocol + "://" + host;
  }

  const refererHeader = String(request?.headers?.referer || "").trim();
  if (refererHeader) {
    try {
      const parsed = new URL(refererHeader);
      return parsed.origin;
    } catch (error) {
      // Ignore invalid referer headers.
    }
  }

  return "https://jadehummingbird.org";
}

function resolvePublicDashboardUrl(request) {
  const candidate = PUBLIC_APP_URL || resolveRequestOrigin(request);
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
  const baseUrl = resolvePublicDashboardUrl(request);
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
  if (targetToken) {
    url.searchParams.set("access", targetToken);
  }
  return url.toString();
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
    portal: portalKey,
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

function buildRecoveryRequest(state, email, note = "") {
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
    return;
  }

  state.recoveryRequests.unshift({
    id: createId("recovery"),
    email,
    note,
    knownAccount,
    submittedAt,
    submittedAtKey,
    status: "open",
    resolvedAt: "",
    resolvedBy: "",
  });
}

const app = express();

app.use((request, response, next) => {
  const origin = request.headers.origin || "*";
  response.setHeader("Access-Control-Allow-Origin", origin);
  response.setHeader("Vary", "Origin");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type, Accept");
  response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (request.method === "OPTIONS") {
    response.status(204).end();
    return;
  }
  next();
});

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
    if (action === "bootstrap") {
      const client = await pool.connect();
      try {
        const workspace = await readWorkspaceRecord(client);
        sendJson(response, 200, {
          ok: true,
          initialized: Boolean(workspace?.state),
          state: workspace?.state || null,
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

        if (passwordCheck.needsUpgrade) {
          Object.assign(user, buildSecurePasswordRecord(password));
        }

        user.lastLoginAt = nowText();
        const nextWorkspace = await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        const sessionToken = await issueSession(client, email);
        return {
          state: nextWorkspace.state,
          revision: nextWorkspace.revision,
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

        const nextState = ensureWorkspaceState(incomingState);
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
        const sessionToken = await issueSession(client, email);
        return {
          state: nextWorkspace.state,
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
      const teammateName = String(request.body?.teammateName || "").trim();
      const teammateEmail = normalizeEmail(request.body?.teammateEmail);
      const notes = String(request.body?.notes || "").trim();

      const result = await withTransaction(async (client) => {
        const workspace = await readWorkspaceRecord(client);
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

        const registeredUser = ensureRegistrationUser(state, {
          name,
          email,
          password,
          createdSource: "self_signup",
          createdBy: email,
          requirePassword: true,
          markLoggedIn: true,
        });

        let teammateUser = null;
        if (teammateEmail) {
          teammateUser = ensureRegistrationUser(state, {
            name: teammateName || teammateEmail,
            email: teammateEmail,
            createdSource: "registered",
            createdBy: email,
            requirePassword: false,
            markLoggedIn: false,
          });
        }

        const team = upsertTournamentRegistrationTeam(tournament, teamName, institution, notes);
        upsertTournamentParticipantRegistration(tournament, {
          name,
          email,
          institution,
          team,
          teamName,
        });

        if (teammateName || teammateEmail) {
          upsertTournamentParticipantRegistration(tournament, {
            name: teammateName || teammateEmail,
            email: teammateEmail,
            institution,
            team,
            teamName,
          });
        }

        rememberUserTournamentHistory(state, email, tournamentId);
        rememberUserTournamentHistory(state, teammateEmail, tournamentId);
        addTournamentAuditEntry(
          tournament,
          email,
          "Registered " +
            name +
            " for " +
            tournament.name +
            (teamName ? " under team " + teamName + "." : "."),
        );

        const notifications = [];
        if (registeredUser) {
          notifications.push(
            await sendPrivateAccessEmail({
              state,
              user: registeredUser,
              request,
              reason: "participant_registration",
              tournamentId,
            }),
          );
        }
        if (teammateUser) {
          notifications.push(
            await sendPrivateAccessEmail({
              state,
              user: teammateUser,
              request,
              reason: "participant_registration",
              tournamentId,
            }),
          );
        }

        const savedWorkspace = await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        const sessionToken = await issueSession(client, email);
        return {
          state: savedWorkspace.state,
          revision: savedWorkspace.revision,
          sessionToken,
          notifications,
        };
      });

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
        const workspace = await readWorkspaceRecord(client);
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

        const notifications = [];
        if (registeredUser) {
          notifications.push(
            await sendPrivateAccessEmail({
              state,
              user: registeredUser,
              request,
              reason: "judge_registration",
              tournamentId,
            }),
          );
        }

        const savedWorkspace = await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        const sessionToken = await issueSession(client, email);
        return {
          state: savedWorkspace.state,
          revision: savedWorkspace.revision,
          sessionToken,
          notifications,
        };
      });

      sendStatePayload(response, 200, result);
      return;
    }

    if (action === "access_link") {
      const token = String(request.body?.token || "").trim();

      const result = await withTransaction(async (client) => {
        const workspace = await readWorkspaceRecord(client);
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

        user.lastLoginAt = nowText();
        user.lastPrivateAccessAt = nowText();

        const nextWorkspace = await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        const sessionToken = await issueSession(client, user.email);
        return {
          state: nextWorkspace.state,
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
          state: savedWorkspace.state,
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
          state,
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

    if (action === "persist") {
      const sessionToken = String(request.body?.sessionToken || "").trim();
      const incomingState = request.body?.state;
      const expectedRevision = normalizeWorkspaceRevision(request.body?.expectedRevision);

      assertWorkspaceContract(incomingState, "persist payload");

      const result = await withTransaction(async (client) => {
        const session = await getSession(client, sessionToken);
        if (!session) {
          const error = new Error("Your backend session has expired. Please sign in again.");
          error.statusCode = 401;
          error.code = "invalid_session";
          throw error;
        }

        const workspace = await readWorkspaceRecord(client);
        const currentState = workspace?.state;
        if (!currentState) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        const nextState = ensureWorkspaceState(incomingState);
        const user = nextState.users.find((entry) => entry.email === normalizeEmail(session.email));
        if (!user || !user.active) {
          const error = new Error("This account is no longer allowed to access JADE.");
          error.statusCode = 403;
          error.code = "account_disabled";
          throw error;
        }

        const notifications = await deliverPersistPrivateAccessEmails({
          previousState: currentState,
          nextState,
          request,
        });

        const savedWorkspace = await writeWorkspaceState(client, nextState, {
          expectedRevision: expectedRevision || workspace.revision,
        });
        return {
          state: savedWorkspace.state,
          revision: savedWorkspace.revision,
          notifications,
        };
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

        buildRecoveryRequest(state, email, note);
        const savedWorkspace = await writeWorkspaceState(client, state, {
          expectedRevision: workspace.revision,
        });
        return {
          state: savedWorkspace.state,
          revision: savedWorkspace.revision,
        };
      });

      sendStatePayload(response, 200, result);
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

ensureStorageSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log("JADE backend listening on http://127.0.0.1:" + PORT + "/api");
      console.log("JADE app available at http://127.0.0.1:" + PORT + "/");
    });
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
