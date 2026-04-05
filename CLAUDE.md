# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Quark Engine

Quark Engine is an Android malware analysis tool built around a **five-stage detection theory**. It analyzes APK files by matching behavioral rules (pairs of Android API calls) against Dalvik bytecode to score the likelihood of malicious behavior.

## Commands

### Install for development
```bash
pip install -e ".[QuarkAgent]"
# or with pipenv:
pipenv install --dev
```

### Run tests
```bash
pytest tests/                          # all tests
pytest tests/evaluator/test_pyeval.py  # specific module
pytest -k "test_function_name"         # single test by name
```

Tests download real APK samples from GitHub on first run (cached by pytest fixtures in `conftest.py`).

### Testing patterns
- **Fixtures**: module-scoped `apkinfo` fixtures download real APK samples via `conftest.py`; function-scoped fixtures build objects from them
- **Mocking**: use `unittest.mock.patch` for external calls; prefer real APK fixtures for integration coverage
- **Regression**: every bug fix must include a regression test that would have caught the bug

### Lint / format
```bash
black quark/
```

### Run the CLI
```bash
quark -a <apk_file> -s                          # summary report
quark -a <apk_file> -d                          # detail report
quark -a <apk_file> -r <rules_dir> -o out.json  # JSON output
freshquark                                       # download latest rules
```

## Architecture

### Core analysis pipeline (`quark/core/`)

**`Quark`** (`core/quark.py`) — the main analysis engine. Implements the five-stage theory:
1. Permission exists in APK
2. Both target APIs exist in the APK
3. Both APIs are called by the same parent method
4. The APIs are called in sequence
5. Register values are passed between the two API calls

**`BaseApkinfo`** (`core/interface/baseapkinfo.py`) — abstract interface for APK parsing. Four concrete implementations:
- `AndroguardImp` (`core/apkinfo.py`) — default, uses androguard library
- `RizinImp` (`core/rzapkinfo.py`) — uses Rizin disassembler
- `R2Imp` (`core/r2apkinfo.py`) — uses Radare2
- `ShurikenImp` (`core/shurikenapkinfo.py`) — uses Shuriken

**`PyEval`** (`evaluator/pyeval.py`) — a Dalvik bytecode interpreter. Simulates register state as instructions execute, enabling Stage 5 (data-flow) analysis. Handles `invoke-*`, `move-result-*`, `const-*`, `iget/iput`, `array-*`, and cast instructions. Tracks values as `RegisterObject` → `ValueNode` (either `Primitive` or `MethodCall`).

**`QuarkAnalysis`** (`core/analysis.py`) — result accumulator passed through analysis stages; holds per-level results, call graphs, and report tables.

### Rules

Rules are JSON files with two API descriptors and a crime description:
```json
{
  "crime": "Send Location via SMS",
  "permission": ["android.permission.SEND_SMS"],
  "api": [
    {"class": "...", "method": "...", "descriptor": "..."},
    {"class": "...", "method": "...", "descriptor": "..."}
  ],
  "score": 4,
  "label": ["location", "collection"]
}
```

Default rules live in `~/.quark/rules/` (downloaded by `freshquark`). The `quark/rules/` directory in the repo holds only one sample rule.

### Script API (`quark/script/`)

`quark/script/__init__.py` exposes a high-level Python API (`quark.script`) for writing custom analysis scripts. Key entry points:
- `runQuarkAnalysis(apkPath, rule)` — run one rule against one APK
- `Ruleset` / `DefaultRuleset` — lazy-loading rule collections
- `Method`, `Activity`, `Application` — wrapper classes for APK components

### Struct objects (`quark/core/struct/`)

- `MethodObject` — wraps a method with class name, method name, descriptor
- `BytecodeObject` — a single decoded Dalvik instruction
- `RegisterObject` — represents a Dalvik register value during PyEval simulation
- `RuleObject` — parsed JSON rule
- `ValueNode` / `MethodCall` / `Primitive` — data-flow value graph nodes

### Agent (`quark/agent/`)

LangChain-based AI agent (`quark-agent` CLI). Requires the `QuarkAgent` extras (`langchain`, `langchain-openai`). Optional feature, separate from the core analysis.

## Commit Conventions

Write commit messages as simple English sentences:

- **Simple sentence structure**: use one of the five basic English sentence patterns
- **Simple vocabulary**: choose common, widely understood words
- **Precise wording**: every word must express the meaning clearly and completely
- **Concise**: remove any word that does not add meaning
- **Grammatically correct**: verify subject-verb agreement, tense, and article usage
- **Correct punctuation**: no trailing periods in the subject line

## Gotchas

Project-specific facts that defy reasonable assumptions:

1. **`__slots__` required on struct objects** — `RegisterObject`, `TableObject`, and other structs in `quark/core/struct/` use `__slots__`. Adding a new instance attribute without updating `__slots__` causes `AttributeError`. (#879)
2. **Mutating a list while iterating it** — caused bug #868. Use `list(iterable)` or collect changes then apply.
3. **Infinite recursion in `iterativeResolve`** — add loop-detection guards (see commit `5bf7c63`).
4. **Register count assumptions** — do not hard-code register limits; large-method APKs can have many registers.

## Skills

Focused skills in `.claude/skills/` provide detailed guidance for specific scenarios:

- **`code-review.md`** — code quality checklist and review automation scripts (use when reviewing PRs)

## Key design decisions

- **Pluggable backends**: pass `core_library="rizin"` (or `"r2"`, `"shuriken"`) to `Quark()` to swap the APK parser without changing analysis logic.
- **`MAX_SEARCH_LAYER = 3`** in `core/quark.py` limits call-graph traversal depth for Stage 3–5.
- `PyEval` is stateless per-method invocation; `Quark` creates a new `PyEval` instance per APK via `apkinfo`.
- Tests rely on real APK downloads; the `conftest.py` in `tests/` manages sample caching.
