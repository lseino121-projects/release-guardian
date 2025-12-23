# Release Guardian Semgrep Rules

This directory contains repo-local Semgrep rules used by Release Guardian.

## How to add a rule

1. Create a YAML file under the appropriate language folder (e.g. `javascript/`, `python/`).
2. Add a rule with the required fields.
3. Run locally to verify the rule executes.

## Required fields

Every rule must include:

- `id`
- `languages`
- `severity`
- `message`

## Optional fields

Provide a remediation hint for PR comments:

```yaml
metadata:
  rg:
    hint: "One-line fix guidance."
```

## Naming convention

Rule IDs should follow:

```
action.rg.rules.<lang>.<category>.<name>
```

## Done criteria

- Run locally: `python -m rg.main ...`
- PR comment shows hint column for introduced Semgrep findings, without manual mapping
