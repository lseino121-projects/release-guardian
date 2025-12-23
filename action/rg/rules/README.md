# Release Guardian Rules (Semgrep)

This directory contains **repo-local Semgrep rules** used by Release Guardian.

These rules are intentionally:
- **Deterministic** (versioned with the repo)
- **Auditable** (policy changes happen via PRs)
- **Extensible** (teams can add/modify rules over time)

Release Guardian treats these rules as a **policy pack** (v1: repo-level).
Org-level policy packs are a planned roadmap item.

---

## Directory layout

### Recommended structure:

action/rg/rules/
├── javascript/
├── python/
├── terraform/
├── docker/
└── README.md


Add more folders over time as needed (go/, java/, k8s/, etc.).

---

## Rule requirements (v1)

Each YAML file may contain one or more Semgrep rules.

### Required fields

Every rule **must** include:

- `id`  
- `message`  
- `severity`  
- `metadata.rg_hint` (used in PR comments)

Example:

```yaml
rules:
  - id: action.rg.rules.python.rg.python.subprocess-popen-shell-true
    message: Avoid shell=True in subprocess calls.
    severity: ERROR
    metadata:
      rg_hint: "Avoid shell=True. Use subprocess.run([...], shell=False) and validate inputs."
      category: security
      technology: [python]
    patterns:
      - pattern: subprocess.Popen(..., shell=True, ...)
      
```

Severity mapping

Release Guardian normalizes severities into:

critical

high

medium

low

Semgrep uses INFO | WARNING | ERROR (and sometimes tool-specific conventions).
In v1, prefer:

ERROR → high

WARNING → medium

INFO → low

If you want “critical” for code findings, mark it via metadata:

metadata:
  rg_severity: critical


(If rg_severity is missing, Release Guardian will fall back to the normalized severity.)

Hints (RG metadata)

Hints are designed to be copy/paste actionable 1-liners in PR comments.

Put them in:

metadata:
  rg_hint: "One sentence: what to do instead."


Good hints:

tell the safer API or pattern

avoid vague advice

avoid long paragraphs

Examples:

✅ “Use subprocess.run([...], shell=False) and validate inputs.”

✅ “Prefer execFile/spawn with args array; never pass user input to a shell.”

❌ “Be careful with command injection.”

Naming conventions
File names

Use lowercase + domain prefix:

rg.js.child-process-exec.yaml

rg.python.subprocess-popen-shell-true.yaml

rg.tf.public-ingress.yaml

rg.docker.latest-tag.yaml

Rule IDs

Use a stable, globally unique ID:

action.rg.rules.<domain>.<filename-with-dots>


Example:

action.rg.rules.javascript.rg.js.child-process-exec

How to add a rule

Create a YAML under the correct folder

Give it an id using the convention

Add:

message

severity

metadata.rg_hint

Run locally:

semgrep scan --config action/rg/rules --json --quiet


Open a PR and verify the PR comment includes:

the finding

the hint

correct severity badge

Testing rules safely

Put intentionally insecure examples under:

examples/unsafe/


These files are for testing rules only.
They should be excluded from scans in production runs.

(See CONTRIBUTING.md for how to run “unsafe test mode”.)

## Roadmap

Planned improvements (not required for v1):

Org-level policy packs (central rules across many repos)

Automatic hints from Semgrep metadata

Rule linting / validation in CI

Suppressions with expiration + justification


---

## One tiny tweak you should do next
Since you mentioned exclusions:

✅ Add Semgrep exclude flags in your `run_semgrep()` command (or semgrep wrapper) so you can ignore:

- `examples/unsafe/**`
- `.rg/**`
- `node_modules/**` (if ever present)

Example Semgrep CLI args:

```bash
semgrep scan --config action/rg/rules --exclude examples/unsafe --exclude .rg --json --quiet
```