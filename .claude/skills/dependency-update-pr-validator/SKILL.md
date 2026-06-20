---
name: dependency-update-pr-validator
description: Validates dependabot dependency-update PRs against quark-engine's CI and drafts a merge/escalate recommendation. Use when asked to review, validate, or triage a dependabot PR on ev-flow/quark-engine, or when the user references issue 18z/QuarkHQ#3.
version: 1.0.0
allowed-tools: bash(gh:*), bash(.claude/skills/dependency-update-pr-validator/scripts/*.sh)
---

# Dependency Update PR Validator

## Why this exists

Dependabot opens a steady stream of near-identical, high-volume PRs against
`ev-flow/quark-engine` (one per dependency bump). Reviewing each one by hand
— does CI actually pass, does it actually test the new version — is
repetitive and easy to rubber-stamp. This skill automates that check and
produces a recommendation for a human to act on. See
[18z/QuarkHQ#3](https://github.com/18z/QuarkHQ/issues/3) for the original
ask.

**This skill never writes to GitHub.** It never calls `gh pr comment`,
`gh pr merge`, or `gh pr review`. Every output is a draft for a human to
read, edit, and post themselves — these PRs live in the upstream repo
(`ev-flow/quark-engine`), not the user's fork, so posting or merging there
is a visible, shared-state action that needs a human in the loop every
time.

## The core insight: green CI does not mean the target version was tested

This repo declares dependencies in two independent places that drift apart:

- `setup.py` — actually consumed by `pip install .` in `pytest.yml`.
- `Pipfile` / `Pipfile.lock` — **not consumed by any current workflow.**
  No workflow runs `pipenv install`.

On top of that, `pytest.yml` has a standalone line that hardcodes some
versions outright, e.g. (as of this writing):

```
python -m pip install langchain==0.2.11 langchain-core==0.2.23 langchain-openai==0.1.17 --upgrade
```

That line ignores `setup.py` entirely. A dependabot PR that bumps
`langchain-core` in `setup.py` will still show all-green CI — CI just
silently kept testing the old pinned version. Conversely, fully unpinned
transitive deps (e.g. `idna`, `requests`) often float to whatever's latest
at install time regardless of which file dependabot touched, and that
floating version is frequently already at-or-above the dependabot target —
which is a legitimate pass, not a coincidence to be suspicious of.

The lesson: **don't infer anything from which file the PR changed.**
Always directly check (a) what version actually got installed in the CI
run, and (b) whether some workflow step hardcodes this exact package to an
older version. Those two checks are simple greps; trust them over the
filename.

## Workflow

Run each step and **print its result before moving to the next one** —
the slow part is digging through CI logs, so show the cheap facts
(package, before/target version, CI pass/fail) first rather than holding
everything for one final report.

### Step 1 — Parse the PR (cheap, do this first)

```bash
bash .claude/skills/dependency-update-pr-validator/scripts/run_checkpoint.sh <repo> <pr_number>
```

This prints the PR title, package name, before version, target version,
and whether every CI check passed (treating `skipping` as fine — e.g.
`kali-package.yml` only runs on push to master, so it's always skipped on
a PR; that is not a failure).

Show this checkpoint to the user immediately.

### Step 2 — If `setup.py` was changed: confirm the new pin is actually installable

Run this whenever `setup.py` is among the PR's changed files (check
`changed_files` from Step 1) — **regardless of CI pass/fail**. This is a
static check of the PR's own diff, not of what CI happened to test, so a
CI failure in Step 3 doesn't make it irrelevant — a PR can fail CI for an
unrelated reason *and* be independently broken here, and you want to catch
both.

```bash
bash .claude/skills/dependency-update-pr-validator/scripts/check_pip_resolution.sh <repo> <head_ref> <package>
```

A dependabot PR usually bumps one pin inside a requirements list (e.g.
`quarkAgentRequirements` in `setup.py`) while leaving its sibling pins in
the same list untouched. That combination can be mutually unsatisfiable —
`pip install` for those exact pinned versions together raises
`ResolutionImpossible` — even when CI is fully green, because CI's
hardcoded install step (Step 4) tests its own separate versions and never
actually tries to install what `setup.py` now declares. This is a
stronger, more definitive reason to block a merge than `is_covered`: if
real users can't even `pip install` the result, it doesn't matter what CI
tested. If this check reports `pip_resolution=conflict`, the recommendation
is **always** "Needs human review," regardless of what CI/is_covered says.

### Step 3 — If any check failed: find the real root cause, don't just report "CI failed"

A red check on a dependabot PR is frequently **not caused by the bump at
all**. Two patterns observed in practice (see
[examples/escalation_comment.md](examples/escalation_comment.md) for full
writeups):

- **Environment flake** — a test fixture fails to download a valid file
  (e.g. `zipfile.BadZipFile: File is not a zip file` while fetching a
  sample APK). Unrelated to any dependency.
- **Stale-branch baseline drift** — `smoke_test.yml`'s hardcoded expected
  behavior-counts (e.g. "Ahmyth.apk should show 39 behaviors") no longer
  match because master gained new detection rules after the dependabot
  branch was cut. Also unrelated to the dependency bump.

To find the actual cause:

```bash
gh run view <failing_run_id> --repo <repo> --log-failed
```

Read the failure, classify it as "looks like a real regression from this
bump" vs. "looks unrelated" (give your reasoning — e.g. the failing
package is a test-only tool that can't plausibly affect malware-detection
counts), and stop here (skip Step 4 — there's no successful build log to
read a version out of). This is always an escalation regardless of
classification — only difference is what you tell the human, and Step 2's
finding (if any) still applies on top of it.

### Step 4 — If CI passed: check what was actually installed

```bash
bash .claude/skills/dependency-update-pr-validator/scripts/check_actual_version.sh <repo> <head_ref> <package>
```

This finds the `pytest.yml` ("build") run for the PR's branch and greps
its log for the package's `Successfully installed` line — the one place
that reflects what pip genuinely resolved and tested, regardless of which
declaration file the PR touched.

Then check whether a workflow hardcodes this package to a stale version
(this is what explains a "No" result, when there is one):

```bash
bash .claude/skills/dependency-update-pr-validator/scripts/check_workflow_pin.sh <package>
```

Then compute is_covered:

```bash
bash .claude/skills/dependency-update-pr-validator/scripts/compare_versions.sh <actual_version> <target_version>
```

### Step 5 — Print the result table, then ask before posting anything

Always finish with **one markdown table in English**, in this exact field
order, regardless of which branch you took:

```
| Field | Value |
|---|---|
| Package | <package> |
| Before version | <before> |
| Target version | <target> |
| CI checks | <✅ All passed / ❌ N failing, with a short reason> |
| Actual installed version | <version, or "Not verified (CI failed first)"> |
| Is covered (actual ≥ target) | <✅ Yes / ❌ No / — Not verified> |
```

Right after the table, add whatever prose is needed to explain *why* —
quote the hardcoded pin line if `check_workflow_pin.sh` found one, quote
the `pip install` conflict if `check_pip_resolution.sh` reported one, or
give the root-cause classification from Step 3 if CI failed — then one
line: **Recommendation: Ready to merge.** or **Recommendation: Needs human
review.** A `pip_resolution=conflict` result always forces "Needs human
review," even if CI passed and is_covered is Yes. See
[examples/ready_to_merge.md](examples/ready_to_merge.md) and
[examples/escalation_comment.md](examples/escalation_comment.md) for full
worked examples in this exact format.

Then **ask the user**, every time, whether to post this as a comment on
the PR — e.g. "Would you like me to post this as a comment on PR #923?".
Only call `gh pr comment <pr> --repo <repo> --body "..."` if they say yes.
Never post automatically, and never call `gh pr merge` regardless of the
recommendation — merging is the human's call to make after reading this.

Present the draft to the user. Do not post it anywhere.

## Scripts reference

| Script | Purpose |
|---|---|
| `scripts/run_checkpoint.sh <repo> <pr>` | Step 1: package, before/target version, CI pass/fail |
| `scripts/parse_pr.sh <repo> <pr>` | Just the dependabot body/diff parsing part of step 1 |
| `scripts/check_ci.sh <repo> <pr>` | Just the CI-checks part of step 1 |
| `scripts/check_pip_resolution.sh <repo> <head_ref> <package>` | Step 2 (only if `setup.py` changed, regardless of CI outcome): is the bumped pin pip-installable alongside its sibling pins in the same requirements list? |
| `scripts/check_actual_version.sh <repo> <head_ref> <package>` | Step 4: actual installed version from the pytest.yml build log |
| `scripts/check_workflow_pin.sh <package>` | Step 4: does a workflow hardcode this package to an older version? |
| `scripts/compare_versions.sh <actual> <target>` | Step 4: is_covered (PEP 440 version comparison) |

All scripts default to the real PR repo when you pass `ev-flow/quark-engine`
as `<repo>` — that's where every dependabot PR for this project lives, not
the user's fork.

## Validated against

This logic was walked through manually against five real dependabot PRs
before being written down here — keep these as a sanity check if you
change the logic:

| PR | Package | Outcome |
|---|---|---|
| [#923](https://github.com/ev-flow/quark-engine/pull/923) | idna | Ready to merge — CI green, actual version matches target, no pin found |
| [#922](https://github.com/ev-flow/quark-engine/pull/922) | langchain-core | Needs human — CI green but `pytest.yml:53` pins an older version; target never installed. Also: `pip install` for the post-PR `setup.py` (`langchain==0.2.11 langchain-core==1.3.3 langchain-openai==0.1.17`) raises `ResolutionImpossible` — broken regardless of CI |
| [#921](https://github.com/ev-flow/quark-engine/pull/921) | langchain | Needs human — CI red, root cause is an unrelated sample-download flake. Also independently fails `check_pip_resolution.sh`: `langchain==0.3.30` conflicts with the untouched sibling pin `langchain-core==0.2.23` — broken even after a clean re-run |
| [#906](https://github.com/ev-flow/quark-engine/pull/906) | pytest (Pipfile.lock) | Needs human — CI red, but root cause is smoke-test baseline drift from a stale branch, unrelated to pytest |
| [#893](https://github.com/ev-flow/quark-engine/pull/893) | requests (Pipfile.lock) | Ready to merge — CI green, actual version (resolved transitively) exceeds target, no pin found |

The `check_pip_resolution.sh` step (and the `ResolutionImpossible` finding
for #922 above) was added after an eval comparison against a baseline
agent without this skill — it independently ran `pip install` on the
post-PR `setup.py` and caught a more definitive, CI-independent reason to
block the PR. See `evals/` in this skill directory for the eval set this
was validated against.
