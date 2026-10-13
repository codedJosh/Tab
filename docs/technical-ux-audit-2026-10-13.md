# JADE Hummingbird technical and UX audit

**Reviewed:** 13 October 2026  
**Scope:** Source review and automated tests in this repository. Production data and deployment were not changed.

## Confirmed deficiencies

| Severity | Finding and evidence | Root cause | Resolution |
| --- | --- | --- | --- |
| Critical | Public sign-up and tournament registration responses could return the shared workspace, including unrelated private records. New self-service sessions were unscoped. | Account-facing routes returned the database workspace instead of the existing member projection and did not apply the member session scope consistently. | Sign-in, sign-up, debater/judge registration, and private-link email responses now use an account-scoped projection. Non-admin sessions carry the member scope. Password reset request/completion return acknowledgements only. |
| High | Password-reset and private-access URLs could use a request's `Origin`, forwarded host, or referrer. A reset request could therefore create a token link on an attacker-controlled host. | Email URL generation trusted browser-controlled request headers. | Links now use configured `PUBLIC_APP_URL` or JADE's canonical HTTPS domain. |
| High | The API reflected arbitrary browser origins in its CORS response. | The CORS middleware copied any supplied `Origin`. | Browser origins are restricted to JADE's canonical domains, local development, and the configured app origin. Unknown-origin preflight requests receive 403. |
| Medium | Every authenticated request deleted expired session rows before checking the presented session. | Session validation combined authentication lookup with table-wide cleanup. | Session lookup filters expired rows; a background cleanup runs every 15 minutes and is cleared during shutdown. |
| Medium | Institution standings included registered teams with no results, did not enforce the three-team qualification threshold, and recomputed points as 3 per win and 1 per loss even when another scoring profile applied. | Board aggregation used registration totals and a hard-coded scoring formula. | Only teams with recorded results count; institutions need results from at least three teams. Average points use the team's official standing points, preserving the tournament scoring profile. |
| Low | The noticeboard heading, quick-add institution form, and workspace navigation alignment differed from neighboring components (the three screenshots attached to the request). | These components lacked local sizing/alignment rules consistent with the current workspace styles. | Added targeted heading sizing, a compact responsive institution form, and consistent left alignment for navigation links. |

## Implementation

- `server.mjs`: scoped account responses and sessions; removed workspace data from password-reset responses; canonicalized email URLs; restricted CORS; moved expired-session cleanup off the request path.
- `frontend/app.js`: counted institution participation from completed results, applied the three-team threshold, used official points, and added screenshot-targeted classes.
- `frontend/styles.css`: adjusted noticeboard title scale, institution form sizing/alignment, and navigation alignment, including a narrow-screen form layout.
- `scripts/server-registration.test.mjs`: added checks for safe email origins, allowed CORS origins, session lookup cost, scoped sessions, and state-free self-service responses.
- `scripts/registration-integrity.test.mjs`: added checks for institution qualification, result-based participation, and scoring-profile preservation.
- `README.md`: documented `PUBLIC_APP_URL` and the email-link host rule.

## Verification

- `node scripts/check.mjs` — passed server/frontend syntax and shared-contract checks.
- `node --test scripts/*.test.mjs` — 46 passed, 0 failed.
- `git diff --check` — passed.

The stale-autosave test intentionally logs a simulated `stale_revision` error while asserting that stale state is preserved; the test passes.

## Remaining recommendations and limits

- The repository persists the application workspace as a single JSONB state record. The transaction and merge tests cover important concurrency cases, but they do not substitute for a live PostgreSQL load test with simultaneous registrations, ballot submissions, and manager edits. A normalized relational migration would be a separate, higher-risk project.
- The automated tests exercise domain logic and route-source contracts; there was no live database, email provider, or production deployment available for end-to-end testing.
- The live website could not be visually verified in this pass because the available fetch showed only its startup placeholder. The screenshot fixes are source-checked but still need a rendered browser preview at desktop and mobile widths.
- The deployment's actual `PUBLIC_APP_URL`, CORS behavior behind its hosting proxy, and private-link flows for each role should be checked in staging before release.
- Accessibility checks with keyboard navigation and a screen reader, and a full tournament simulation from registration through published standings, remain outstanding.

No production data was edited, and no deployment or push was performed.
