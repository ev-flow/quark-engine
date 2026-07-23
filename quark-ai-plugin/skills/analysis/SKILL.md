---
name: analysis
description: Run Quark Engine analysis on an APK file — produces summary, detail, JSON, web, call graph, behavior map, and classification reports.
version: 1.0.0
allowed-tools: Bash
---

# Run Quark Analysis

Use this skill when the user wants to analyze an APK file with Quark Engine. The skill maps the user's analysis request to the correct `quark` CLI flags, runs the command, and presents the output.

## Step 0 — Verify Quark is installed

```bash
quark --version
```

If this fails, stop and tell the user: "Quark not found — run `pip install quark-engine` and try again."

## Step 1 — Identify the APK

Ask the user for the APK path if not provided. Confirm it exists:

```bash
test -f "<apk_path>" && echo "OK" || echo "NOT FOUND"
```

If not found, stop and ask the user to provide the correct path.

## Step 2 — Identify the analysis type

Map the user's request to one of the modes below.

### Report modes

| User intent | Flags to pass to run_analysis.sh | Output |
|-------------|----------------------------------|--------|
| Summary overview | `-s` | Terminal table of matched rules and confidence |
| Detail per rule | `-d` | Verbose output for each rule |
| JSON report | `-o report.json` | JSON file in the current directory |
| Web report | `-s -w report.html` | HTML file — **`-s` required**, silently produces nothing without it |
| Call graph (PNG) | `-s -g png` | PNG saved in `call_graph_image/` — **`-s` required** |
| Call graph (JSON) | `-s -g json` | JSON saved in `call_graph_image/` — **`-s` required** |
| Behavior map | `-l max` | Report grouped by behavior label |
| Rules classification | `-c` | Rules grouped by category |

### Modifiers (combine with a report mode)

| Need | Flag | Note |
|------|------|------|
| Use a specific rules directory | `-r <rules_dir>` | Must be a **directory**, not a single JSON file |
| Run a single rule file | `-s <rule.json>` | Replaces the default rules directory |
| Filter by confidence | `-t <value>` | Allowed values: `20`, `40`, `60`, `80`, `100` |

### Utility modes (work without rules installed)

| User intent | Flags | Output |
|-------------|-------|--------|
| List all classes and methods | `-i all` | Every class, method, and descriptor in the APK |
| List Android API calls only | `-i native` | Only native Android SDK methods |
| List declared permissions | `-p` | Permissions declared in the manifest |

### `-C` comparison mode — requires user interaction

`-C` opens an interactive terminal dialog that the user must control. Do **not** try to invoke it automatically. Instead, tell the user:

> Label comparison requires interactive input. Run this directly in your terminal:
> ```
> quark -a "<apk_path>" -C
> ```

## Step 3 — Check rules directory (report modes only)

Skip this step for utility modes (`-i`, `-p`).

```bash
test -d ~/.quark-engine/quark-rules/rules && echo "OK" || echo "MISSING"
```

If missing: "Rules directory not found — run `freshquark` to download the latest rules, then try again."

## Step 4 — Run the analysis

Before running, print the exact command for the user:

```
Running: quark -a "<apk_path>" <flags>
```

Then run it:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/skills/analysis/scripts/run_analysis.sh" "<apk_path>" <flags>
```

**Examples:**

```bash
# Summary report
bash "${CLAUDE_PLUGIN_ROOT}/skills/analysis/scripts/run_analysis.sh" "sample.apk" -s

# JSON report to file
bash "${CLAUDE_PLUGIN_ROOT}/skills/analysis/scripts/run_analysis.sh" "sample.apk" -o report.json

# Call graph PNG (requires -s)
bash "${CLAUDE_PLUGIN_ROOT}/skills/analysis/scripts/run_analysis.sh" "sample.apk" -s -g png

# List native APIs only (no rules needed)
bash "${CLAUDE_PLUGIN_ROOT}/skills/analysis/scripts/run_analysis.sh" "sample.apk" -i native

# Summary with a custom rules directory
bash "${CLAUDE_PLUGIN_ROOT}/skills/analysis/scripts/run_analysis.sh" "sample.apk" -s -r ~/my-rules/

# Run a single rule file
bash "${CLAUDE_PLUGIN_ROOT}/skills/analysis/scripts/run_analysis.sh" "sample.apk" -s path/to/rule.json
```

## Step 5 — Present output and offer next steps

Print the raw quark output verbatim first — do not summarize or paraphrase it. Example of what this looks like for a summary report:

```
[!] WARNING: Low Risk
[*] Total Score: 1.9
+------------+------------------------------------------------------------+------------+
| Filename   | Rule                                                       | Confidence |
+------------+------------------------------------------------------------+------------+
| 00002.json | Open the camera and take picture                           | 100%       |
| 00010.json | Read sensitive data(SMS, CALLLOG) and put it into JSON     | 100%       |
...
+------------+------------------------------------------------------------+------------+
```

After the raw output, provide analysis and offer next steps:

- **(a)** Re-run with a different format or a specific rule file
- **(b)** Generate a new Quark rule for a suspicious behavior seen in the output — use the **`/quark:rule-gen`** skill
- **(c)** Export to JSON: re-run with `-o report.json` for downstream processing
- **(d)** View call graph: re-run with `-s -g png` to visualize which methods triggered a rule
