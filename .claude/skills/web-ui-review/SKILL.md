---
name: web-ui-review
description: Frontend code quality checklist and review automation scripts for PRs touching UI, components, styles, and browser interactions
allowed-tools: Bash, Grep, Read
---

# Frontend Review

## Code Quality Checklist

Based on the project's review standard, adapted for frontend (HTML/CSS/JavaScript/TypeScript/React/Vue/etc.) codebases. Each item is tagged with a review role.

### 1. Functional Correctness
- [ ] [Staff Eng] All required features from the issue/task are implemented
- [ ] [Staff Eng] No uncaught exceptions, console errors, or warnings during execution
- [ ] [Staff Eng] Error boundaries and fallback UI handle component failures gracefully
- [ ] [Staff Eng] No logic errors that pass CI but would fail in production (race conditions in async state, stale closures, incorrect memoization)
- [ ] [Staff Eng] No completeness gaps — no missing expected behaviors or edge cases; actively flag any that are found

### 2. Code Design
- [ ] [Staff Eng] No duplicate functionality already present in the codebase (check shared utils, hooks, and component libraries before adding new ones)
- [ ] [Staff Eng] Each component/function does exactly one thing
- [ ] [Lang] TypeScript types are correct and narrow (no `any` escapes without justification) — **automate**: `bash .claude/skills/frontend-review/scripts/check_types.sh <files>`
- [ ] [Eng Manager] Component boundaries, data flow (props vs state vs context vs store), and side-effect locations are explicitly defined — no hidden assumptions
- [ ] [Eng Manager] Edge cases and boundary conditions are clearly specified and enforced (empty states, loading states, error states, overflowing content)
- [ ] [Lang] Follows established frontend patterns (component composition, custom hooks, state management conventions — no ad-hoc assembly)

### 3. Code Style
- [ ] [Lang] Variables and classes use noun/noun-phrase names; functions and event handlers start with a verb (`handleClick`, `fetchUser`, `renderItem`)
- [ ] [Lang] Format with project formatter (Prettier/Biome) before committing — **automate**: `bash .claude/skills/frontend-review/scripts/check_style.sh <files>`
- [ ] [Lang] Run linter (ESLint/Biome) on **only the files changed in this PR** and resolve all reported issues in those files (do not fix pre-existing issues in untouched files) — **automate**: `bash .claude/skills/frontend-review/scripts/check_style.sh <files>`
- [ ] [Lang] Run spell-checker on code — **automate**: `bash .claude/skills/frontend-review/scripts/check_spelling.sh <files>`
- [ ] [Lang] CSS/styles follow project conventions (CSS Modules, Tailwind, styled-components, etc.); no inline styles unless justified

### 4. Testing & Regression Prevention
- [ ] [QA] New/modified components and functions are covered by tests
- [ ] [QA] Tests validate both expected and unexpected inputs (props, user events, API responses, edge cases)
- [ ] [QA] Every bug fix is accompanied by a regression test that would have caught it — the same bug must never recur
- [ ] [QA] Aim for 80%+ coverage on changed code — **automate**: `bash .claude/skills/frontend-review/scripts/check_coverage.sh <module>`

### 5. Security
- [ ] [Lang] Run security audit on dependencies and confirm no known vulnerabilities — **automate**: `bash .claude/skills/frontend-review/scripts/check_security.sh`
- [ ] [CSO] Only raise a security warning when confidence is >= 8/10 and independently verified — zero false positives
- [ ] [CSO] Every identified vulnerability (XSS, CSRF, open redirect, prototype pollution, etc.) includes a concrete exploit scenario explaining how an attacker would actually abuse it in a real environment
- [ ] [Lang] No `dangerouslySetInnerHTML`, `eval()`, `document.write()`, or `innerHTML` assignments without explicit sanitization and justification
- [ ] [Lang] User input is sanitized before rendering; URLs are validated before navigation

### 6. UI/UX Design & Visual Standards
- [ ] [Senior Designer] No crude or unnatural "AI-generated artifacts (AI Slop)" in the interface — visual and interaction quality must meet professional human-design standards
- [ ] [Senior Designer] Visual hierarchy is clear — typography scale, spacing, and color usage follow the design system
- [ ] [Senior Designer] Component styling is consistent with the rest of the application (no orphan styles or one-off overrides)
- [ ] [Senior Designer] Responsive design works across target breakpoints (mobile, tablet, desktop) — use `/playwright-cli` to check at multiple viewport sizes

### 7. Interaction & Usability Quality
- [ ] [Designer Who Codes] No residual UI defects, layout breakages, or visual anomalies in the implemented interface code — use `/playwright-cli` to inspect the live page in a real browser
- [ ] [QA Engineer] In a real browser environment (via `/playwright-cli`), all dynamic interactions — button clicks, form inputs, and page navigation — function correctly with no broken behaviors
- [ ] [QA Engineer] Focus management and keyboard navigation work correctly (Tab order, Enter/Space activation, Escape to dismiss)
- [ ] [QA Engineer] Form validation provides immediate, clear feedback; submit/reset behave correctly

### 8. Accessibility
- [ ] [Lang] Semantic HTML elements are used (`button` not `div[onClick]`, `nav`, `main`, `section`, `article`)
- [ ] [Lang] All interactive elements are keyboard-accessible
- [ ] [Lang] Images have meaningful `alt` text; decorative images use `alt=""`
- [ ] [Lang] Color contrast meets WCAG AA (4.5:1 for text, 3:1 for large text) — use `/playwright-cli` to inspect elements in a real browser
- [ ] [Lang] ARIA attributes are used correctly and only when native HTML semantics are insufficient

### 9. Performance
- [ ] [Staff Eng] No unnecessary re-renders (check memoization, dependency arrays, key props)
- [ ] [Staff Eng] Large lists use virtualization; heavy computations are deferred or memoized
- [ ] [Staff Eng] Images and assets are optimized (lazy loading, proper sizing, modern formats)
- [ ] [Staff Eng] Bundle impact is considered — no large library added for trivial functionality — **automate**: `bash .claude/skills/frontend-review/scripts/check_bundle.sh`

### 10. Debugging Standards
- [ ] [Debugger] No fix is applied without a systematic root-cause investigation: trace data flow and test hypotheses before touching code
- [ ] [Debugger] If three consecutive fix attempts fail, stop and escalate rather than continuing to patch blindly

### 11. PR Preparation
- [ ] [Staff Eng] Commit message follows conventional commit format and passes sentence-quality checks — **automate**: `bash .claude/skills/frontend-review/scripts/check_commit.sh`
- [ ] [Staff Eng] PR title and description reference the relevant issue
- [ ] [QA] Screenshots or screen recordings attached for any visual changes
- [ ] [Lang] If any public API (exported components, hooks, utils) changed: update documentation and confirm no downstream consumers break

## Review Workflow

### Phase 1 — Understand

1. Read the changed files and their surrounding context (parent components, shared hooks, related modules, style files)
2. Understand the feature's intent from the linked issue, branch name, and commit messages. **Ask questions if unclear.**
3. Identify how the changes fit into the existing component tree and state management architecture

### Phase 2 — Plan

4. Produce a **test plan blueprint** based on the Code Quality Checklist
5. Present the blueprint to the user for review. **Wait for user confirmation before executing any tests.**

### Phase 3 — Automated checks

6. Run all automated checks: `bash .claude/skills/frontend-review/scripts/run_all.sh <changed-files-or-dir>`
7. Fix failures and re-run until all checks pass. If a tooling dependency is missing, install and retry up to **3 attempts**; after that, **skip** and record for the final summary.

### Phase 4 — Browser & manual review

8. Use `/playwright-cli` to verify visual and interaction quality (Sections 6, 7, 8)
9. Review remaining checklist items that require manual judgment

### Phase 5 — Finalize

10. Mark the review as complete only when all checks pass
11. Present a **single consolidated table** — one row per check with result and issue description. **Only show issues.** Include a **Skipped Tests** section for any checks skipped due to tooling errors. End by asking the user if they want any issues fixed.

See [examples/summary.md](examples/summary.md) for the expected output format.
