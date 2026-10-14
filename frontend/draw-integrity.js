const normalizeEmail = (value) => String(value || "").trim().toLowerCase();
const normalizeTextKey = (value) => String(value || "")
  .trim()
  .toLowerCase()
  .replace(/[^a-z0-9]+/g, " ")
  .trim();

function slotKey(slot) {
  return String(slot?.teamId || "").trim() ||
    String(slot?.entryId || "").trim() ||
    normalizeTextKey(slot?.teamName || slot?.shortLabel || slot?.label);
}

function defaultSlotInstitution(tournament, slot) {
  if (slot?.institution) return String(slot.institution).trim();
  const teamName = normalizeTextKey(slot?.teamName || slot?.shortLabel || slot?.label);
  let candidates = (tournament?.teams || []).filter((entry) => slot?.teamId
    ? String(entry.id) === String(slot.teamId)
    : normalizeTextKey(entry.name) === teamName);
  if (slot?.institution) {
    const institution = normalizeTextKey(slot.institution);
    candidates = candidates.filter((entry) => normalizeTextKey(entry.institution) === institution);
  }
  if (candidates.length === 1 && candidates[0]?.institution) return String(candidates[0].institution).trim();
  const participantIds = new Set((slot?.participantIds || []).map(String));
  const institutions = Array.from(new Set((tournament?.participants || [])
    .filter((entry) => participantIds.has(String(entry.id)))
    .map((entry) => String(entry.institution || "").trim())
    .filter(Boolean)));
  return institutions.length === 1 ? institutions[0] : "";
}

function defaultSlotLabel(slot, index) {
  return String(slot?.shortLabel || slot?.teamName || slot?.label || slot?.entryId || `Entry ${index + 1}`).trim();
}

function normalizeRole(value) {
  const role = String(value || "panelist").trim().toLowerCase().replace(/[ _-]+/g, "");
  return role === "chair" || role === "chairjudge" ? "chair" : "panelist";
}

export function evaluateDrawEntryConflicts(tournament, drawEntry, options = {}) {
  if (!drawEntry) return [];
  const issues = [];
  const slots = Array.isArray(drawEntry.slots) ? drawEntry.slots : [];
  const keys = slots.map(slotKey).filter(Boolean);
  const getInstitution = options.getSlotInstitution || defaultSlotInstitution;
  const getLabel = options.getSlotLabel || defaultSlotLabel;
  const institutions = new Map();

  slots.forEach((slot, index) => {
    const institution = String(getInstitution(tournament, slot) || "").trim();
    if (institution) institutions.set(institution, (institutions.get(institution) || 0) + 1);
  });
  institutions.forEach((count, institution) => {
    if (count > 1) issues.push({
      tone: "danger",
      label: "Institution clash",
      detail: institution + " appears " + count + " times in this room.",
      code: "INSTITUTION_REPEATED_IN_ROOM",
      blocksPublication: true,
    });
  });

  (tournament?.draw || []).filter((entry) => Number(entry.round || 0) < Number(drawEntry.round || 0))
    .forEach((previousEntry) => {
      const previousKeys = (previousEntry.slots || []).map(slotKey).filter(Boolean);
      const overlap = keys.filter((key) => previousKeys.includes(key));
      if (overlap.length >= 2) issues.push({
        tone: "warning",
        label: "Repeat matchup",
        detail: "This room repeats " + overlap.length + " entry matchups from Round " +
          previousEntry.round + " • " + previousEntry.room + ".",
        code: "REPEAT_MATCHUP",
        blocksPublication: false,
      });
    });

  const roomAllocations = (tournament?.judgeAllocations || []).filter((allocation) =>
    String(allocation.drawId || "") === String(drawEntry.id || ""),
  );
  roomAllocations.forEach((allocation) => {
    const email = normalizeEmail(allocation.judgeEmail);
    const judge = (tournament?.judges || []).find((entry) => normalizeEmail(entry.email) === email);
    const judgeInstitution = String(judge?.institution || "").trim();
    if (judgeInstitution) {
      const matchingSlots = slots.map((slot, index) => ({
        institution: getInstitution(tournament, slot),
        label: getLabel(slot, index),
      })).filter((entry) => normalizeTextKey(entry.institution) === normalizeTextKey(judgeInstitution));
      if (matchingSlots.length) issues.push({
        tone: "danger",
        label: "Judge conflict",
        detail: (judge?.name || allocation.judgeEmail) + " shares " + judgeInstitution + " with " +
          Array.from(new Set(matchingSlots.map((entry) => entry.label))).join(", ") + ".",
        code: "JUDGE_INSTITUTION_CLASH",
        blocksPublication: true,
      });
    }

    (tournament?.judgeAllocations || []).filter((previousAllocation) =>
      normalizeEmail(previousAllocation.judgeEmail) === email &&
      Number(previousAllocation.round || 0) < Number(drawEntry.round || 0),
    ).forEach((previousAllocation) => {
      const previousEntry = (tournament?.draw || []).find((entry) => String(entry.id) === String(previousAllocation.drawId));
      const previousKeys = (previousEntry?.slots || []).map(slotKey).filter(Boolean);
      const overlap = keys.filter((key) => previousKeys.includes(key));
      if (overlap.length) issues.push({
        tone: "warning",
        label: "Judge repeat exposure",
        detail: (judge?.name || allocation.judgeEmail) + " has already seen " + overlap.length +
          " of these entries earlier in the tournament.",
        code: "JUDGE_REPEAT_EXPOSURE",
        blocksPublication: false,
      });
    });
  });

  const allocationsByJudge = new Map();
  roomAllocations.forEach((allocation) => {
    const email = normalizeEmail(allocation.judgeEmail);
    if (!email) return;
    if (!allocationsByJudge.has(email)) allocationsByJudge.set(email, []);
    allocationsByJudge.get(email).push(allocation);
  });
  allocationsByJudge.forEach((allocations) => {
    if (allocations.length < 2) return;
    const judge = (tournament?.judges || []).find((entry) => normalizeEmail(entry.email) === normalizeEmail(allocations[0].judgeEmail));
    const roles = allocations.map((allocation) => options.getRoleLabel
      ? options.getRoleLabel(allocation.panelRole)
      : normalizeRole(allocation.panelRole) === "chair" ? "Chair" : "Panelist");
    issues.push({
      tone: "danger",
      label: "Duplicate judge assignment",
      detail: (judge?.name || allocations[0].judgeEmail) + " is assigned more than once in this room (" + roles.join(", ") + ").",
      code: "JUDGE_ASSIGNED_TWICE_IN_ROOM",
      blocksPublication: true,
    });
  });

  const roundEntries = (tournament?.draw || []).filter((entry) => Number(entry.round || 0) === Number(drawEntry.round || 0));
  const currentEntryId = String(drawEntry.id || "");
  const assignmentsByJudge = new Map();
  (tournament?.judgeAllocations || []).forEach((allocation) => {
    const assignedEntry = roundEntries.find((entry) => String(entry.id || "") === String(allocation.drawId || ""));
    const email = normalizeEmail(allocation.judgeEmail);
    if (!assignedEntry || !email) return;
    if (!assignmentsByJudge.has(email)) assignmentsByJudge.set(email, []);
    assignmentsByJudge.get(email).push({ entry: assignedEntry, allocation });
  });
  assignmentsByJudge.forEach((assignments, email) => {
    const distinctEntryIds = Array.from(new Set(assignments.map(({ entry }) => String(entry.id || ""))));
    if (distinctEntryIds.length < 2) return;
    const canonicalEntryId = distinctEntryIds.slice().sort()[0];
    if (currentEntryId !== canonicalEntryId) return;
    const judge = (tournament?.judges || []).find((entry) => normalizeEmail(entry.email) === email);
    const details = assignments
      .slice()
      .sort((left, right) => String(left.entry.id).localeCompare(String(right.entry.id)))
      .map(({ entry, allocation }) => {
        const role = normalizeRole(allocation.panelRole || allocation.role);
        return String(entry.room || "Unnamed room") + " (" + (role === "chair" ? "Chair" : "Wing") + ")";
      });
    issues.push({
      tone: "danger",
      label: "Judge assigned to multiple rooms",
      detail: (judge?.name || email) + " is assigned to " + details.join(" and ") + " in Round " + drawEntry.round + ".",
      code: "JUDGE_ASSIGNED_MULTIPLE_ROOMS_IN_ROUND",
      blocksPublication: true,
    });
  });

  return Array.from(new Map(issues.map((issue) => [issue.code + "::" + issue.detail, issue])).values());
}
