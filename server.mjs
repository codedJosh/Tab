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
const WORKSPACE_ID = String(process.env.JADE_WORKSPACE_ID || "primary").trim() || "primary";
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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function nowText() {
  return new Date().toLocaleString("en-US", {
    timeZone: "America/Jamaica",
  });
}

function normalizeEmail(value = "") {
  return String(value || "").trim().toLowerCase();
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

function createId(prefix) {
  return prefix + "-" + crypto.randomBytes(4).toString("hex");
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeTimestampKey(value, fallbackText = "") {
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 0) {
    return Math.round(numeric);
  }
  const parsed = Date.parse(String(fallbackText || "").trim());
  return Number.isFinite(parsed) && parsed > 0 ? parsed : Date.now();
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
    pinnedTournamentIds: Array.isArray(user.pinnedTournamentIds)
      ? Array.from(new Set(user.pinnedTournamentIds.map((value) => String(value || "").trim()).filter(Boolean))).slice(0, 12)
      : [],
    registeredTournamentIds: normalizeStringList(user.registeredTournamentIds, 200),
    themePreset: String(user.themePreset || "jade_classic").trim() || "jade_classic",
    preferredLandingView:
      String(user.preferredLandingView || "overview").trim() || "overview",
  };
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
  next.appSettings = next.appSettings && typeof next.appSettings === "object" ? next.appSettings : {};
  next.users = Array.isArray(next.users) ? next.users.map((user) => normalizeUserRecord(user)) : [];
  next.recoveryRequests = Array.isArray(next.recoveryRequests) ? next.recoveryRequests : [];
  next.tournaments = Array.isArray(next.tournaments) ? next.tournaments : [];
  return synchronizeUserTournamentHistory(next);
}

function mergeRecordArrays(currentItems = [], incomingItems = [], getKey, mergeRecord) {
  const catalog = new Map();

  (Array.isArray(currentItems) ? currentItems : []).forEach((item) => {
    const key = String(getKey(item) || "").trim();
    if (key) {
      catalog.set(key, clone(item));
    }
  });

  (Array.isArray(incomingItems) ? incomingItems : []).forEach((item) => {
    const key = String(getKey(item) || "").trim();
    if (!key) {
      return;
    }
    const existing = catalog.get(key);
    catalog.set(key, mergeRecord ? mergeRecord(existing, item) : clone(item));
  });

  return Array.from(catalog.values());
}

function getParticipantMergeKey(participant = {}) {
  const id = String(participant.id || "").trim();
  if (id) return id;
  const email = normalizeEmail(participant.email);
  if (email) return "email:" + email;
  return (
    "participant:" +
    String(participant.name || "").trim().toLowerCase() +
    "|" +
    String(participant.teamName || "").trim().toLowerCase()
  );
}

function getJudgeMergeKey(judge = {}) {
  return String(judge.id || "").trim() || "email:" + normalizeEmail(judge.email);
}

function getTeamMergeKey(team = {}) {
  const id = String(team.id || "").trim();
  if (id) return id;
  return (
    "team:" +
    String(team.name || "").trim().toLowerCase() +
    "|" +
    String(team.institution || "").trim().toLowerCase()
  );
}

function getAuditMergeKey(entry = {}) {
  return (
    String(entry.id || "").trim() ||
    "audit:" + String(entry.at || "").trim() + "|" + String(entry.message || "").trim()
  );
}

function getDrawMergeKey(entry = {}) {
  return (
    String(entry.id || "").trim() ||
    "draw:" +
      String(entry.round || "").trim() +
      "|" +
      String(entry.room || "").trim().toLowerCase() +
      "|" +
      String(entry.matchup || "").trim().toLowerCase()
  );
}

function getJudgeAllocationMergeKey(entry = {}) {
  return (
    String(entry.id || "").trim() ||
    "allocation:" +
      String(entry.drawId || "").trim() +
      "|" +
      normalizeEmail(entry.judgeEmail)
  );
}

function getStandingMergeKey(entry = {}) {
  return (
    String(entry.id || "").trim() ||
    "standing:" + normalizeTextKey(entry.name)
  );
}

function getNoticeMergeKey(entry = {}) {
  return (
    String(entry.id || "").trim() ||
    "notice:" + String(entry.createdAt || "").trim() + "|" + String(entry.title || "").trim()
  );
}

function getFeedbackLedgerMergeKey(entry = {}) {
  return (
    String(entry.id || "").trim() ||
    "feedback:" + String(entry.createdAt || "").trim() + "|" + String(entry.note || "").trim()
  );
}

function getRoundControlMergeKey(entry = {}) {
  return "round-control:" + String(entry.round || "").trim();
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
      registeredTournamentIds: normalizeStringList(
        [
          ...(user.registeredTournamentIds || []),
          ...Array.from(historyByEmail.get(user.email) || []),
        ],
        200,
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
      registeredTournamentIds: normalizeStringList(
        [
          ...(user.registeredTournamentIds || []),
          ...Array.from(historyByEmail.get(user.email) || []),
        ],
        200,
      ),
    }),
  );

  return next;
}

function mergeTournamentRecords(currentTournament = {}, incomingTournament = {}) {
  const currentPermissions = normalizeTournamentPermissions(currentTournament?.permissions || {});
  const incomingPermissions = normalizeTournamentPermissions(incomingTournament?.permissions || {});
  const mergedPermissions = {
    ...currentPermissions,
    ...incomingPermissions,
  };
  TOURNAMENT_PERMISSION_KEYS.forEach((key) => {
    mergedPermissions[key] = normalizePermissionEmailList(
      [
        ...(currentPermissions[key] || []),
        ...(incomingPermissions[key] || []),
      ],
      key === "debaterEmails" ? 800 : 400,
    );
  });
  return {
    ...clone(currentTournament || {}),
    ...clone(incomingTournament || {}),
    config: {
      ...(currentTournament?.config || {}),
      ...(incomingTournament?.config || {}),
    },
    publication: {
      ...(currentTournament?.publication || {}),
      ...(incomingTournament?.publication || {}),
    },
    permissions: mergedPermissions,
    settings: {
      ...(currentTournament?.settings || {}),
      ...(incomingTournament?.settings || {}),
    },
    registration: normalizeTournamentRegistrationSettings({
      ...(currentTournament?.registration || {}),
      ...(incomingTournament?.registration || {}),
    }),
    teams: mergeRecordArrays(
      currentTournament?.teams || [],
      incomingTournament?.teams || [],
      getTeamMergeKey,
      (existing, incoming) => ({
        ...(existing || {}),
        ...clone(incoming),
      }),
    ),
    participants: mergeRecordArrays(
      currentTournament?.participants || [],
      incomingTournament?.participants || [],
      getParticipantMergeKey,
      (existing, incoming) => ({
        ...(existing || {}),
        ...clone(incoming),
      }),
    ),
    judges: mergeRecordArrays(
      currentTournament?.judges || [],
      incomingTournament?.judges || [],
      getJudgeMergeKey,
      (existing, incoming) => ({
        ...(existing || {}),
        ...clone(incoming),
      }),
    ),
    auditLog: mergeRecordArrays(
      currentTournament?.auditLog || [],
      incomingTournament?.auditLog || [],
      getAuditMergeKey,
      (existing, incoming) => ({
        ...(existing || {}),
        ...clone(incoming),
      }),
    ),
    standings: mergeRecordArrays(
      currentTournament?.standings || [],
      incomingTournament?.standings || [],
      getStandingMergeKey,
      (existing, incoming) => ({
        ...(existing || {}),
        ...clone(incoming),
      }),
    ),
    draw: mergeRecordArrays(
      currentTournament?.draw || [],
      incomingTournament?.draw || [],
      getDrawMergeKey,
      (existing, incoming) => ({
        ...(existing || {}),
        ...clone(incoming),
      }),
    ),
    judgeAllocations: mergeRecordArrays(
      currentTournament?.judgeAllocations || [],
      incomingTournament?.judgeAllocations || [],
      getJudgeAllocationMergeKey,
      (existing, incoming) => ({
        ...(existing || {}),
        ...clone(incoming),
      }),
    ),
    notices: mergeRecordArrays(
      currentTournament?.notices || [],
      incomingTournament?.notices || [],
      getNoticeMergeKey,
      (existing, incoming) => ({
        ...(existing || {}),
        ...clone(incoming),
      }),
    ),
    feedbackLedger: mergeRecordArrays(
      currentTournament?.feedbackLedger || [],
      incomingTournament?.feedbackLedger || [],
      getFeedbackLedgerMergeKey,
      (existing, incoming) => ({
        ...(existing || {}),
        ...clone(incoming),
      }),
    ),
    roundControls: mergeRecordArrays(
      currentTournament?.roundControls || [],
      incomingTournament?.roundControls || [],
      getRoundControlMergeKey,
      (existing, incoming) => ({
        ...(existing || {}),
        ...clone(incoming),
      }),
    ),
  };
}

function mergeWorkspaceState(currentState, incomingState) {
  const current = ensureWorkspaceState(currentState);
  const incoming = ensureWorkspaceState(incomingState);
  const merged = {
    ...current,
    ...incoming,
    appSettings: {
      ...(current.appSettings || {}),
      ...(incoming.appSettings || {}),
    },
    users: mergeRecordArrays(
      current.users || [],
      incoming.users || [],
      (user) => normalizeEmail(user?.email),
      (existing, nextUser) => {
        const existingUser = normalizeUserRecord(existing || {});
        const incomingUser = normalizeUserRecord(nextUser || {});
        return normalizeUserRecord({
          ...existingUser,
          ...incomingUser,
          id: existingUser.id || incomingUser.id,
          email: incomingUser.email || existingUser.email,
          name: incomingUser.name || existingUser.name,
          passwordHash: incomingUser.passwordHash || existingUser.passwordHash,
          passwordSalt: incomingUser.passwordSalt || existingUser.passwordSalt,
          passwordVersion: incomingUser.passwordVersion || existingUser.passwordVersion,
          passwordIterations:
            incomingUser.passwordIterations || existingUser.passwordIterations,
          createdAt: existingUser.createdAt || incomingUser.createdAt,
          createdAtKey: existingUser.createdAtKey || incomingUser.createdAtKey,
          createdSource:
            existingUser.createdSource &&
            existingUser.createdSource !== "registered" &&
            incomingUser.createdSource === "registered"
              ? existingUser.createdSource
              : incomingUser.createdSource || existingUser.createdSource,
          createdBy: existingUser.createdBy || incomingUser.createdBy,
          privateAccessToken:
            existingUser.privateAccessToken || incomingUser.privateAccessToken,
          privateAccessIssuedAt:
            existingUser.privateAccessIssuedAt || incomingUser.privateAccessIssuedAt,
          lastPrivateAccessAt:
            incomingUser.lastPrivateAccessAt || existingUser.lastPrivateAccessAt,
          pinnedTournamentIds: normalizeStringList(
            [
              ...(existingUser.pinnedTournamentIds || []),
              ...(incomingUser.pinnedTournamentIds || []),
            ],
            12,
          ),
          registeredTournamentIds: normalizeStringList(
            [
              ...(existingUser.registeredTournamentIds || []),
              ...(incomingUser.registeredTournamentIds || []),
            ],
            200,
          ),
        });
      },
    ),
    recoveryRequests: mergeRecordArrays(
      current.recoveryRequests || [],
      incoming.recoveryRequests || [],
      (request) =>
        String(request?.id || "").trim() ||
        "recovery:" + normalizeEmail(request?.email) + "|" + String(request?.submittedAtKey || "").trim(),
      (_existing, request) => clone(request),
    ),
    tournaments: mergeRecordArrays(
      current.tournaments || [],
      incoming.tournaments || [],
      (tournament) => String(tournament?.id || "").trim(),
      (existing, nextTournament) => mergeTournamentRecords(existing, nextTournament),
    ),
  };

  return synchronizeUserTournamentHistory(merged);
}

function rememberUserTournamentHistory(state, email, tournamentId) {
  const normalizedEmail = normalizeEmail(email);
  const normalizedTournamentId = String(tournamentId || "").trim();
  if (!normalizedEmail || !normalizedTournamentId) {
    return;
  }

  state.users = (state.users || []).map((user) =>
    normalizeEmail(user.email) === normalizedEmail
      ? normalizeUserRecord({
          ...user,
          registeredTournamentIds: normalizeStringList(
            [...(user.registeredTournamentIds || []), normalizedTournamentId],
            200,
          ),
        })
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
  response.status(statusCode).json(payload);
}

function sendError(response, statusCode, code, message) {
  sendJson(response, statusCode, {
    ok: false,
    code,
    error: message,
    message,
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

async function readWorkspaceState(client) {
  const result = await client.query(
    "select state from jade_workspaces where id = $1 limit 1",
    [WORKSPACE_ID],
  );
  return result.rows[0]?.state ? ensureWorkspaceState(result.rows[0].state) : null;
}

async function writeWorkspaceState(client, state) {
  const normalized = ensureWorkspaceState(state);
  const result = await client.query(
    `
      insert into jade_workspaces (id, state, updated_at)
      values ($1, $2::jsonb, now())
      on conflict (id)
      do update set state = excluded.state, updated_at = now()
      returning state
    `,
    [WORKSPACE_ID, JSON.stringify(normalized)],
  );
  return ensureWorkspaceState(result.rows[0]?.state || normalized);
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
      const state = await readWorkspaceState(client);
      sendJson(response, 200, {
        ok: true,
        initialized: Boolean(state),
        storage: "postgres",
        workspaceId: WORKSPACE_ID,
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
        const state = await readWorkspaceState(client);
        sendJson(response, 200, {
          ok: true,
          initialized: Boolean(state),
          state: state || null,
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
        const state = await readWorkspaceState(client);
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
        const nextState = await writeWorkspaceState(client, state);
        const sessionToken = await issueSession(client, email);
        return {
          state: nextState,
          sessionToken,
        };
      });

      sendJson(response, 200, {
        ok: true,
        initialized: true,
        sessionToken: result.sessionToken,
        state: result.state,
      });
      return;
    }

    if (action === "initialize") {
      const email = normalizeEmail(request.body?.email);
      const password = String(request.body?.password || "");
      const incomingState = request.body?.state;

      const result = await withTransaction(async (client) => {
        const existingState = await readWorkspaceState(client);
        if (existingState) {
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
        const savedState = await writeWorkspaceState(client, nextState);
        const sessionToken = await issueSession(client, email);
        return {
          state: savedState,
          sessionToken,
        };
      });

      sendJson(response, 200, {
        ok: true,
        initialized: true,
        sessionToken: result.sessionToken,
        state: result.state,
      });
      return;
    }

    if (action === "sign_up") {
      const name = String(request.body?.name || "").trim();
      const email = normalizeEmail(request.body?.email);
      const password = String(request.body?.password || "");

      const result = await withTransaction(async (client) => {
        const state = await readWorkspaceState(client);
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
        }

        const nextState = await writeWorkspaceState(client, state);
        const sessionToken = await issueSession(client, email);
        return {
          state: nextState,
          sessionToken,
        };
      });

      sendJson(response, 200, {
        ok: true,
        initialized: true,
        sessionToken: result.sessionToken,
        state: result.state,
      });
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
        const state = await readWorkspaceState(client);
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

        ensureRegistrationUser(state, {
          name,
          email,
          password,
          createdSource: "self_signup",
          createdBy: email,
          requirePassword: true,
          markLoggedIn: true,
        });

        if (teammateEmail) {
          ensureRegistrationUser(state, {
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

        const savedState = await writeWorkspaceState(client, state);
        const sessionToken = await issueSession(client, email);
        return {
          state: savedState,
          sessionToken,
        };
      });

      sendJson(response, 200, {
        ok: true,
        initialized: true,
        sessionToken: result.sessionToken,
        state: result.state,
      });
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
        const state = await readWorkspaceState(client);
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

        ensureRegistrationUser(state, {
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

        const savedState = await writeWorkspaceState(client, state);
        const sessionToken = await issueSession(client, email);
        return {
          state: savedState,
          sessionToken,
        };
      });

      sendJson(response, 200, {
        ok: true,
        initialized: true,
        sessionToken: result.sessionToken,
        state: result.state,
      });
      return;
    }

    if (action === "access_link") {
      const token = String(request.body?.token || "").trim();

      const result = await withTransaction(async (client) => {
        const state = await readWorkspaceState(client);
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

        const nextState = await writeWorkspaceState(client, state);
        const sessionToken = await issueSession(client, user.email);
        return {
          state: nextState,
          sessionToken,
          userEmail: user.email,
        };
      });

      sendJson(response, 200, {
        ok: true,
        initialized: true,
        state: result.state,
        sessionToken: result.sessionToken,
        userEmail: result.userEmail,
      });
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

        const state = await readWorkspaceState(client);
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
        };
      });

      sendJson(response, 200, {
        ok: true,
        initialized: true,
        state: result.state,
      });
      return;
    }

    if (action === "persist") {
      const sessionToken = String(request.body?.sessionToken || "").trim();
      const incomingState = request.body?.state;

      const result = await withTransaction(async (client) => {
        const session = await getSession(client, sessionToken);
        if (!session) {
          const error = new Error("Your backend session has expired. Please sign in again.");
          error.statusCode = 401;
          error.code = "invalid_session";
          throw error;
        }

        const currentState = await readWorkspaceState(client);
        if (!currentState) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        const nextState = mergeWorkspaceState(currentState, incomingState);
        const user = nextState.users.find((entry) => entry.email === normalizeEmail(session.email));
        if (!user || !user.active) {
          const error = new Error("This account is no longer allowed to access JADE.");
          error.statusCode = 403;
          error.code = "account_disabled";
          throw error;
        }

        const savedState = await writeWorkspaceState(client, nextState);
        return {
          state: savedState,
        };
      });

      sendJson(response, 200, {
        ok: true,
        initialized: true,
        state: result.state,
      });
      return;
    }

    if (action === "request_password_reset") {
      const email = normalizeEmail(request.body?.email);
      const note = String(request.body?.note || "").trim();

      const result = await withTransaction(async (client) => {
        const state = await readWorkspaceState(client);
        if (!state) {
          const error = new Error("The shared backend workspace has not been initialized yet.");
          error.statusCode = 409;
          error.code = "workspace_not_initialized";
          throw error;
        }

        buildRecoveryRequest(state, email, note);
        const savedState = await writeWorkspaceState(client, state);
        return {
          state: savedState,
        };
      });

      sendJson(response, 200, {
        ok: true,
        initialized: true,
        state: result.state,
      });
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

app.listen(PORT, () => {
  console.log("JADE backend listening on http://127.0.0.1:" + PORT + "/api");
  console.log("JADE app available at http://127.0.0.1:" + PORT + "/");
});
