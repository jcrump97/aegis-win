<!-- Title: start with the type tag, like the commits: (feat), (fix), (doc), (chore), (test), (refactor), (security), (perf). -->

## What this changes

<!-- What it does and why. Link the ADR section or the issue (Fixes #N). -->

## Checklist (AGENTS.md §2 and §3)

- [ ] `npm run ci` passes, and every commit adds or updates a test.
- [ ] `documentation/AUDIT_LEDGER.md` has a row for each commit, and the specs in `documentation/` match the code.
- [ ] **Caller audit:** no existing function gained a side effect, or every caller is listed below and wants it.
- [ ] **Two actors:** if both the app and an MCP agent can reach this, a test has them act in sequence.
- [ ] A `(fix)` commit has a test that fails without the fix.
- [ ] The PIN is not logged, serialized, sent to an LLM, or returned over MCP or `invoke`.
- [ ] Reviewed by a person or a fresh AI session that did not write it (`/review-pr <number>` in Claude Code).
- [ ] No AI attribution in the commits or in this description.

## Found and not fixed here

<!-- Issue numbers for anything found and left for later, or "None". On a bug-fix PR (title starts with (fix) or (security)), review findings are fixed in this PR instead; list only those the maintainer sent to an issue, which the author files before merge. -->
