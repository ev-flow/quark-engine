---
name: quark-rule-gen
description: Generate a Quark Engine detection rule from a behavior description and decompiled code. Validates the rule against a real APK before outputting it.
version: 1.0.0
allowed-tools: bash(.claude/skills/quark-rule-gen/scripts/validate_rule.sh)
---

# Generate Quark Rule

Use this skill when the user wants to create a Quark rule that detects a specific malicious behavior. The skill guides you through identifying the right API pair, formatting Dalvik descriptors correctly, and validating that the rule actually matches the target APK.

## Step 0 — Verify Quark is installed

```bash
quark --version
```

If this fails, stop and tell the user: "Quark not found — run `pip install quark-engine` and try again."

## Step 1 — Get behavior description

Ask the user to describe the behavior they want to detect in plain English.
Example: "Send the device's GPS location via SMS to a remote number."

## Step 2 — Get code reference (required before proceeding)

A decompiled code snippet is required to identify the correct class names, method names, and descriptors. Without it, any generated rule is a guess and the retry loop has no new information.

**If the user provides a code snippet:** proceed to Step 3.

**If no snippet is available:** extract relevant method listings from the APK:

```bash
# Preferred: native APIs only, filtered by suspected package
quark -i native -a "<apk_path>" | grep "<suspected_package>"

# Fallback: all methods (large output — use grep to filter)
quark -i all -a "<apk_path>" | grep "<suspected_package>"
```

Ask the user which package namespace to search for, or search for the most likely Android SDK classes for the described behavior (e.g., `SmsManager`, `LocationManager`, `TelephonyManager`).

## Step 3 — Identify the API pair

From the code snippet, identify **exactly two** Android API calls that together characterize the behavior:
- Both calls must appear in the same execution context
- Together, they must describe the malicious intent (e.g., "get location" + "send SMS")
- Neither call alone is sufficient — the pair is what makes it malicious

## Step 4 — Format Dalvik descriptors

Quark rules use **Dalvik bytecode descriptor syntax**. Getting this wrong causes the rule to silently return zero results.

**Class names:**
- Format: `L` + package path (with `/` separators) + `;`
- Example: `Landroid/telephony/SmsManager;`

**Method descriptors:**
- Format: `(param1param2...)ReturnType`
- **No spaces between parameters** — the parser uses type boundaries
- Reference type params end with `;`, primitive params are single chars
- Example (two reference params, void return): `(Ljava/lang/String;Landroid/content/Context;)V`
- Wrong (space breaks parsing): `(Ljava/lang/String; Landroid/content/Context;)V`

**Primitive types:**

| Java type | Dalvik |
|-----------|--------|
| void | `V` |
| int | `I` |
| boolean | `Z` |
| byte | `B` |
| long | `J` |
| byte[] | `[B` |

**Verified example rule** (`sendLocation_SMS.json`):

```json
{
  "crime": "Send Location via SMS",
  "permission": [
    "android.permission.SEND_SMS",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION"
  ],
  "api": [
    {
      "class": "Landroid/telephony/TelephonyManager;",
      "method": "getCellLocation",
      "descriptor": "()Landroid/telephony/CellLocation;"
    },
    {
      "class": "Landroid/telephony/SmsManager;",
      "method": "sendTextMessage",
      "descriptor": "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V"
    }
  ],
  "score": 4,
  "label": ["location", "collection"]
}
```

## Step 5 — Assign score and labels

**Score** (1–8) — reflects the deepest evidence you observed in the sample:

| Score | Stage evidence |
|-------|---------------|
| 1–2 | Both APIs exist in the APK; no co-occurrence confirmed yet |
| 3–4 | API pair co-occurs in the same parent method (Stage 3) |
| 5–6 | API pair is called in the defined sequence (Stage 4) |
| 7–8 | Data flow (register sharing) confirmed between the two API calls (Stage 5) |

Assign the score that reflects what you *observed*, not your intent. A freshly generated rule validated only at Stage 3 → score 3–4.

**Labels** — use canonical labels from the existing rules repo:

`collection`, `sms`, `network`, `file`, `command`, `control`, `reflection`,
`telephony`, `accessibility service`, `record`, `wifi`, `location`, `screen`,
`calllog`, `camera`, `applications`, `http`, `calendar`, `socket`, `evasion`

Invent a new label only if none of the above apply — document it in your PR.

## Step 6 — Generate and save the rule

Write the rule JSON to a temp file:

```bash
cat > /tmp/quark_candidate_rule.json << 'EOF'
{
  "crime": "...",
  "permission": ["..."],
  "api": [
    {"class": "...", "method": "...", "descriptor": "..."},
    {"class": "...", "method": "...", "descriptor": "..."}
  ],
  "score": 4,
  "label": ["..."]
}
EOF
```

## Step 7 — Validate the rule

```bash
bash .claude/skills/quark-rule-gen/scripts/validate_rule.sh "<apk_path>" /tmp/quark_candidate_rule.json
```

**If behaviors detected (exit 0):** proceed to Step 8.

**If zero behaviors (exit 1):** return to Step 3 with the code snippet still in context. Revise the API pair or descriptor — common causes of zero results:
- Wrong class name (missing `L` prefix or `;` suffix)
- Space in descriptor between parameters
- Method not found at this class level (may be in a parent class)
- Wrong method name (check the snippet again)

Maximum 3 attempts total. If still zero after 3 tries, tell the user what was tried and ask them to provide a more specific code snippet or a different API pair.

## Step 8 — Output the final rule

Present the validated rule JSON and suggest a filename:

```
<crime_in_snake_case>.json
```

Example: `send_location_via_sms.json`

Tell the user: "Place this file in your rules directory (`~/.quark-engine/quark-rules/rules/` for the default set, or a custom directory passed with `-r`)."
