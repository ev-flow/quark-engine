---
name: code-review
description: Code quality checklist and review automation scripts for quark-engine PRs
allowed-tools: Bash, Grep, Read
---

# Code Review

## Code Quality Checklist

Based on the project's review standard. Each item is tagged with a review role.

### 1. Functional Correctness
- [ ] [Staff Eng] All required features from the issue/task are implemented
- [ ] [Staff Eng] No uncaught exceptions or warnings during execution
- [ ] [Staff Eng] Exception handling catches and reports all error conditions
- [ ] [Staff Eng] No logic errors that pass CI but would fail in production (look for deep bugs that automated tests cannot catch)
- [ ] [Staff Eng] No completeness gaps — no missing expected behaviors or edge cases; actively flag any that are found

### 2. Code Design
- [ ] [Staff Eng] No duplicate functionality already present in the codebase (check `quark/utils/tools.py` and `BaseApkinfo` before adding helpers)
- [ ] [Staff Eng] Each function does exactly one thing
- [ ] [Lang] Function signatures have correct input/output types (use type annotations consistent with existing code)
- [ ] [Eng Manager] Architecture, data flow, and boundaries are explicitly defined — all hidden assumptions must be surfaced
- [ ] [Eng Manager] Edge cases and boundary conditions are clearly specified and enforced
- [ ] [Lang] Follows backend & API design patterns (REST, database, cache layer conventions — no ad-hoc assembly)
- [ ] [QA] Run SonarLint and resolve all detected issues

### 3. Code Style
- [ ] [Lang] Variables and classes use noun/noun-phrase names; functions start with a verb
- [ ] [Lang] Format with `black --line-length 79 quark/` before committing — **automate**: `bash .claude/skills/code-review/scripts/check_style.sh <files>`
- [ ] [Lang] Run `pylint` on **only the files changed in this PR** and resolve all reported issues in those files (do not fix pre-existing issues in untouched files — it creates noise and defocuses the PR) — **automate**: `bash .claude/skills/code-review/scripts/check_style.sh <files>`
- [ ] [Lang] Run spell-checker on code — **automate**: `bash .claude/skills/code-review/scripts/check_spelling.sh <files>`
- [ ] [Lang] No lines exceed 79 characters
- [ ] [Lang] All functions and variables have complete, correct type hints — **automate**: `bash .claude/skills/code-review/scripts/check_types.sh <files>`

### 4. Testing & Regression Prevention
- [ ] [QA] New/modified functions are covered by tests
- [ ] [QA] Tests validate both expected and unexpected inputs
- [ ] [QA] Every bug fix is accompanied by a regression test that would have caught it — the same bug must never recur
- [ ] [QA] Aim for 100% coverage on changed code; replace any yolo/vibe-coded patches with proper tests — **automate**: `bash .claude/skills/code-review/scripts/check_coverage.sh <module>`

### 5. Security
- [ ] [Lang] Run language-level security scan (e.g., `bandit` for Python) and confirm no vulnerabilities — **automate**: `bash .claude/skills/code-review/scripts/check_security.sh <files>`
- [ ] [CSO] Only raise a security warning when confidence is ≥ 8/10 and independently verified — zero false positives
- [ ] [CSO] Every identified vulnerability (OWASP Top 10 or STRIDE) includes a concrete exploit scenario explaining how an attacker would actually abuse it in a real environment

### 6. Debugging Standards
- [ ] [Debugger] No fix is applied without a systematic root-cause investigation: trace data flow and test hypotheses before touching code
- [ ] [Debugger] If three consecutive fix attempts fail, stop and escalate rather than continuing to patch blindly

### 7. PR Preparation
- [ ] [Staff Eng] Commit message follows conventional commit format and passes sentence-quality checks — **automate**: `bash .claude/skills/code-review/scripts/check_commit.sh`
- [ ] [Staff Eng] If the commit borrows ideas or code from an open-source project: the commit title or body must name the referenced project and state its license (e.g. `Inspired by androguard (Apache-2.0)`). Also include the following notice: "If the project authors prefer we not adapt their work, they may open an issue and we will remove the relevant code."
- [ ] [Staff Eng] PR title and description reference the relevant issue
- [ ] [QA] Smoke test counts updated if behavior counts changed (see `@.claude/skills/workflows.md` → Updating Smoke Test Counts)
- [ ] [Lang] If any `quark.script` public API changed: update `docs/source/quark_script.rst` and compile docs locally to confirm no errors

## Review Automation Scripts

Bundled scripts in `.claude/skills/code-review/scripts/` automate the checklist items marked with **automate** above.

**Prerequisites:** `pip install black pylint mypy codespell bandit pytest-cov` (or use `uvx` for one-off runs).

### Review workflow

#### Phase 1 — Understand

1. Read the changed files and their surrounding context (callers, callees, related modules)
2. Understand the feature's intent from the linked issue, branch name, and commit messages. **Ask questions if unclear.**
3. Identify how the changes fit into the existing architecture (e.g., does a new method in `TableObject` affect all callers in `PyEval`?)
4. Check whether the change duplicates, conflicts with, or misuses existing patterns in the codebase

#### Phase 2 — Plan

5. Produce a **test plan blueprint** based on the Code Quality Checklist:
   - List every test item (automated scripts and manual checks), with a brief description of what each verifies
   - Present the blueprint to the user for review
   - **Wait for user confirmation before executing any tests**

#### Phase 3 — Automated checks

6. Run all automated checks with a **30-minute timeout** (the full test suite can be slow):
   ```
   bash .claude/skills/code-review/scripts/run_all.sh <changed-files-or-dir>
   ```
   Use `timeout_ms: 1800000` when invoking this via the Bash tool.
7. Fix failures and re-run until all checks pass. If a failure is due to a missing dependency, install and retry up to **3 attempts**; after that, **skip** the check and record it for the final summary.

#### Phase 4 — Manual review

9. Review checklist items without an **automate** marker — these require manual judgment, informed by the context gathered in Phase 1

#### Phase 5 — Finalize

10. Mark the review as complete only when both automated and manual checks pass
11. In the final summary, include a **Skipped Tests** section listing any checks skipped due to unresolvable tooling errors, with error details

## Summary Format

Present the review result as a **single consolidated table**. Each row is one check (automated or manual) with its result and issue description.

**Only show issues.** Do not include a "What's Good" section. End by asking the user if they want any issues fixed.

See [examples/summary.md](examples/summary.md) for the expected output format.
