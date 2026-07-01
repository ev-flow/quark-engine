---
name: dependency-update-pr-validator
description: Validates dependabot dependency-update PRs against quark-engine's CI and drafts a merge/escalate recommendation. Use when asked to review, validate, or triage a dependabot PR on ev-flow/quark-engine, or when the user references issue 18z/QuarkHQ#3.
version: 1.0.0
allowed-tools: >-
  bash(gh pr view:*),
  bash(gh pr checks:*),
  bash(gh run list:*),
  bash(gh run view:*),
  bash(gh api:*),
  bash(.claude/skills/dependency-update-pr-validator/scripts/*.sh)
---
# Dependency Update PR Validator

## Why this exist

Dependabot spam near-identical PRs at `ev-flow/quark-engine` (one per dep bump). Hand-review each — CI really pass? new version really tested? — repetitive, easy rubber-stamp. Skill automate check, spit recommendation for human act on. Origin ask: [18z/QuarkHQ#3](https://github.com/18z/QuarkHQ/issues/3).

**Skill never write GitHub.** Never call `gh pr comment`, `gh pr merge`, `gh pr review`. Every output draft for human read/edit/post self — PRs live upstream (`ev-flow/quark-engine`), not user fork, so post/merge there = visible shared-state action, need human loop every time.

## Core insight: green CI ≠ target version tested

Repo declare deps two places, drift apart:

- `setup.py` — consumed by `pip install ".[QuarkAgent]"` in `pytest.yml`.
- `Pipfile` / `Pipfile.lock` — **no workflow consume this.** Nothing run `pipenv install`.

History lesson (fixed, but why `check_workflow_pin.sh` still exists): `pytest.yml` used to have a standalone line hardcoding `langchain==0.2.11 langchain-core==0.2.23 langchain-openai==0.1.17`, totally ignoring `setup.py`. Dependabot bump `langchain-core` in `setup.py` → still all-green CI, cuz CI quietly kept testing the old hardcoded version, never the bump. Fixed by installing `.[QuarkAgent]` extras instead (commit `9d119c4`) — but **any** workflow step could grow a new hardcoded pin like this again for some other package, so still check for it, don't assume it's gone forever.

Separate, still-live gotcha: unpinned transitive deps (e.g. `idna`, `requests`) often float to latest at install regardless of which file dependabot touch, and float version frequent already at-or-above target — legit pass, not coincidence to suspect.

Lesson: **don't guess from which file PR changed.** Always check direct (a) what version actually install in CI run, (b) does some workflow step hardcode this exact package to older version. Two simple greps — trust over filename.

## Workflow

Run each step, **print result before next step** — slow part dig CI logs, so show cheap facts (package, current/target version, CI pass/fail) first, not hold all for one final report.

### Step 1 — Parse PR (cheap, do first)

```bash
bash .claude/skills/dependency-update-pr-validator/scripts/run_checkpoint.sh <repo> <pr_number>
```

Print PR title, package name, current version, target version, all CI checks passed (treat `skipping` as fine — e.g. `kali-package.yml` only run on push to master, always skip on PR; not failure).

Show checkpoint to user now.

### Step 2 — If `setup.py` changed: confirm new pin actually installable

Run whenever `setup.py` among PR's changed files (check `changed_files` from Step 1) — **regardless CI pass/fail**. Static check of PR's own diff, not what CI happen test — CI failure Step 3 don't make this irrelevant — PR can fail CI for unrelated reason *and* be independently broken here, want catch both.

```bash
bash .claude/skills/dependency-update-pr-validator/scripts/check_pip_resolution.sh <repo> <head_ref> <package>
```

Dependabot PR usually bump one pin inside requirements list (e.g. `quarkAgentRequirements` in `setup.py`) while leave sibling pins same list untouched. Combo can be mutually unsatisfiable — `pip install` for those exact pinned versions together raise `ResolutionImpossible` — even when CI fully green, cuz CI's hardcoded install step (Step 4) test own separate versions, never actually try install what `setup.py` now declare. Stronger, more definitive reason block merge than `is_covered`: if real users can't even `pip install` result, don't matter what CI tested. If check report `pip_resolution=conflict`, recommendation **always** "Needs human review," regardless what CI/is_covered say.

### Step 3 — If any check failed: find real root cause, don't just report "CI failed"

Red check on dependabot PR frequent **not caused by bump at all**. Two pattern seen practice (see [examples/escalation_comment.md](examples/escalation_comment.md) for full writeups):

- **Environment flake** — test fixture fail download valid file (e.g. `zipfile.BadZipFile: File is not a zip file` fetching sample APK). Unrelated any dependency.
- **Stale-branch baseline drift** — `smoke_test.yml`'s hardcoded expected behavior-counts (e.g. "Ahmyth.apk should show 39 behaviors") no longer match cuz master gain new detection rules after dependabot branch cut. Also unrelated bump.

Find actual cause:

```bash
gh run view <failing_run_id> --repo <repo> --log-failed
```

Read failure, classify "look like real regression from bump" vs "look unrelated" (give reasoning — e.g. failing package test-only tool, can't plausibly affect malware-detection counts), stop here (skip Step 4 — no successful build log read version from). Always escalation regardless classification — only diff what tell human, and Step 2's finding (if any) still apply on top.

### Step 4 — If CI passed: check what actually installed

```bash
bash .claude/skills/dependency-update-pr-validator/scripts/check_actual_version.sh <repo> <head_ref> <package>
```

Find `pytest.yml` ("build") run for PR's branch, grep log for package's `Successfully installed` line — one place reflect what pip genuinely resolve+test, regardless which declaration file PR touch. Script also emit `proof_url` (link to the `build` job page) — link this in table row as "Found in CI log", not just bare version, so human verify same place without re-running anything.

Then check workflow hardcode package to stale version (explains "No" result, when exist):

```bash
bash .claude/skills/dependency-update-pr-validator/scripts/check_workflow_pin.sh <package>
```

Then compute is_covered:

```bash
bash .claude/skills/dependency-update-pr-validator/scripts/compare_versions.sh <actual_version> <target_version>
```

### Step 5 — Print result table, then ask before posting anything

Always finish **one markdown table English**, exact field order, regardless which branch taken:

```
| Field | Value |
|---|---|
| Package | <package> |
| Current version | <current> |
| Target version | <target> |
| CI checks | <✅ All passed / ❌ N failing, with a short reason> |
| Actual installed version | <version ([Found in CI log](proof_url)) using `proof_url` from `check_actual_version.sh`; if no `proof_url` line, plain version; if CI failed first, "Not verified (CI failed first)"> |
| Actual ≥ Target | <✅ Yes / ❌ No / — Not verified> |
```

Right after table, add prose explain *why* — quote hardcoded pin line if `check_workflow_pin.sh` found one, quote `pip install` conflict if `check_pip_resolution.sh` reported one, or give root-cause classification from Step 3 if CI failed — then one line: **Recommendation: Ready to merge.** or **Recommendation: Needs human review.** `pip_resolution=conflict` result always force "Needs human review," even CI passed and is_covered Yes. See [examples/ready_to_merge.md](examples/ready_to_merge.md) and [examples/escalation_comment.md](examples/escalation_comment.md) full worked examples this exact format.

Then **ask user**, every time, post this as comment on PR? — e.g. "Would you like me to post this as a comment on PR #923?". Only call `gh pr comment <pr> --repo <repo> --body "..."` if yes say. Never post auto, never call `gh pr merge` regardless recommendation — merge human's call after read this.

Present draft to user. Don't post anywhere.

## Scripts reference

| Script | Purpose |
|---|---|
| `scripts/run_checkpoint.sh <repo> <pr>` | Step 1: package, current/target version, CI pass/fail |
| `scripts/parse_pr.sh <repo> <pr>` | Just dependabot body/diff parse part step 1 |
| `scripts/check_ci.sh <repo> <pr>` | Just CI-checks part step 1 |
| `scripts/check_pip_resolution.sh <repo> <head_ref> <package>` | Step 2 (only if `setup.py` changed, regardless CI outcome): bumped pin pip-installable alongside sibling pins same requirements list? |
| `scripts/check_actual_version.sh <repo> <head_ref> <package>` | Step 4: actual installed version from pytest.yml build log, plus `proof_url` link to that job |
| `scripts/check_workflow_pin.sh <package>` | Step 4: workflow hardcode package to older version? |
| `scripts/compare_versions.sh <actual> <target>` | Step 4: is_covered (PEP 440 version comparison) |

All scripts default to real PR repo when pass `ev-flow/quark-engine`
as `<repo>` — that's where every dependabot PR this project live, not user fork.

## Validated against

Logic walked manual against five real dependabot PRs before write down here — keep as sanity check if change logic:

| PR | Package | Outcome |
|---|---|---|
| [#923](https://github.com/ev-flow/quark-engine/pull/923) | idna | Ready to merge — CI green, actual version match target, no pin found |
| [#922](https://github.com/ev-flow/quark-engine/pull/922) | langchain-core | Needs human — CI green but `pytest.yml:53` pin older version; target never install. Also: `pip install` for post-PR `setup.py` (`langchain==0.2.11 langchain-core==1.3.3 langchain-openai==0.1.17`) raise `ResolutionImpossible` — broken regardless CI |
| [#921](https://github.com/ev-flow/quark-engine/pull/921) | langchain | Needs human — CI red, root cause unrelated sample-download flake. Also independently fail `check_pip_resolution.sh`: `langchain==0.3.30` conflict untouched sibling pin `langchain-core==0.2.23` — broken even after clean re-run |
| [#906](https://github.com/ev-flow/quark-engine/pull/906) | pytest (Pipfile.lock) | Needs human — CI red, but root cause smoke-test baseline drift from stale branch, unrelated pytest |
| [#893](https://github.com/ev-flow/quark-engine/pull/893) | requests (Pipfile.lock) | Ready to merge — CI green, actual version (resolved transitively) exceed target, no pin found |

`check_pip_resolution.sh` step (and `ResolutionImpossible` finding for #922 above) added after eval comparison vs baseline agent without this skill — it independently ran `pip install` on post-PR `setup.py`, caught more definitive, CI-independent reason block PR. See `evals/` this skill dir for eval set validated against.
