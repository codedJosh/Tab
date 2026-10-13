import { privateVisibility } from "../../frontend/public-workspace.js";
import { tournamentChanges } from "../../frontend/tournament-patch.js";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import vm from "node:vm";
import { resolveRoundStructure, registrationTeamSize, unassignedParticipants } from "../../frontend/tournament-rules.js";

// Run the actual frontend domain functions without starting the browser UI.
export function loadFrontendDomain() {
  const storage = { getItem: () => null, setItem() {}, removeItem() {} };
  const context = vm.createContext({
    privateVisibility, tournamentChanges, resolveRoundStructure, registrationTeamSize, unassignedParticipants, console, URL, crypto: webcrypto, TextEncoder, TextDecoder, structuredClone,
    setTimeout, clearTimeout,
    window: {
      location: { href: "http://localhost/", protocol: "http:" },
      localStorage: storage, sessionStorage: storage,
      matchMedia: () => ({ matches: false }), setTimeout, clearTimeout,
    },
    document: { querySelector: () => null },
    navigator: {},
    btoa: (value) => Buffer.from(value, "binary").toString("base64"),
    atob: (value) => Buffer.from(value, "base64").toString("binary"),
  });
  const source = readFileSync(new URL("../../frontend/app.js", import.meta.url), "utf8");
  vm.runInContext(source.replace(/^import .*"\.\/(?:tournament-rules|tournament-patch|public-workspace)\.js";\n/gm, "").replace(/\n      boot\(\);\s*$/, ""), context);
  return {
    run: (code) => vm.runInContext(code, context),
    set: (key, value) => { context[key] = value; },
  };
}
