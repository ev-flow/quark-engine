# Quark Engine — Claude Code Plugin

Bundles two Quark Engine skills for Claude Code:

- **`/quark:analysis`** — run APK malware analysis (summary, detail, JSON, web, call graph, behavior map, classification).
- **`/quark:rule-gen`** — generate a Quark detection rule from a behavior description and decompiled code, validated against a real APK.

Plugin skills are always namespaced as `/<plugin>:<skill>`, so the invocation names are `/quark:analysis` and `/quark:rule-gen`.

## Prerequisites

Quark Engine must be installed and on your `PATH`:

```bash
pip install quark-engine
freshquark          # download the latest detection rules
```

## Install (global — works in any project, gets updates)

Add the marketplace straight from GitHub, then install. No clone needed.

Inside Claude Code:

```
/plugin marketplace add ev-flow/quark-engine
/plugin install quark@quark-engine
```

`/plugin marketplace add` reads `.claude-plugin/marketplace.json` at the repo root
(default branch). Installed at **user scope**, so `/quark:analysis` and
`/quark:rule-gen` are available in **every** project, not just this repo.

Start a new Claude Code session, then verify:

```
/plugin list
```

You should see `quark@quark-engine` enabled.

> `/plugin` has no bare `install <path>` form. A plugin is always installed through
> a marketplace — the two commands above are that flow.

## Update

Maintainer bumps `version` in `quark-ai-plugin/.claude-plugin/plugin.json` and
pushes. Users then run:

```
/plugin marketplace update quark-engine
/plugin update quark@quark-engine
```

`version` gates updates: users only receive a new version when the maintainer bumps
it. (Omit `version` in `plugin.json` and every commit becomes a new version instead.)

## Layout

The marketplace catalog lives at the **repo root**; the plugin itself lives in
`quark-ai-plugin/` (this is `${CLAUDE_PLUGIN_ROOT}` once installed).

```
<repo root>/
├── .claude-plugin/
│   └── marketplace.json           # marketplace catalog (quark-engine) → source ./quark-ai-plugin
└── quark-ai-plugin/               # the plugin = ${CLAUDE_PLUGIN_ROOT}
    ├── .claude-plugin/
    │   └── plugin.json            # plugin manifest (quark)
    ├── README.md
    └── skills/
        ├── analysis/
        │   ├── SKILL.md
        │   └── scripts/run_analysis.sh
        └── rule-gen/
            ├── SKILL.md
            └── scripts/validate_rule.sh
```

## Local install (development / testing)

To install from a local clone instead of GitHub:

```bash
git clone https://github.com/ev-flow/quark-engine
cd quark-engine
```
```
/plugin marketplace add .
/plugin install quark@quark-engine
```

## Uninstall

```
/plugin uninstall quark@quark-engine
/plugin marketplace remove quark-engine
```
