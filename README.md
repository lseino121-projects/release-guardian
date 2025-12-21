# Release Guardian

**Release Guardian** is a decision engine for pull requests.

It answers one question clearly and consistently:

> **“Is the risk introduced by this PR acceptable to ship?”**

Release Guardian does not enumerate everything that is wrong in a codebase.  
It focuses on **introduced risk**, **confidence**, and **decisions at merge time**.

---

## The problem

Most security tools answer:

- “What vulnerabilities exist in this repository?”

Engineering teams actually need:

- **“What risk does *this change* introduce?”**
- **“How severe is it?”**
- **“How confident are we in that assessment?”**
- **“Should we ship?”**

Without this distinction:
- Legacy vulnerabilities permanently block delivery
- PRs become noisy and un-actionable
- Teams either ignore security or stop shipping

Release Guardian exists to fix that.

---

## What Release Guardian does

Release Guardian evaluates **introduced risk only** and produces a **clear release decision** at PR time.

It combines:
- Dependency risk (Trivy + Syft + Grype)
- Code risk (Semgrep)
- Baseline confidence (how reliable the comparison is)

Into:
- A single verdict
- A transparent explanation
- A calibrated score (RDI)

---

## Core concepts

### 1. Introduced risk (not total risk)

Release Guardian distinguishes between:

- **Pre-existing risk** — already in `main`
- **Introduced risk** — added by the current PR

Only **introduced risk** can block a release.

This prevents historical debt from freezing forward progress.

---

### 2. Unified dependency + code analysis

Introduced risk is evaluated across:

- **Dependencies**
  - SBOM generated with Syft
  - Vulnerabilities clustered across Trivy + Grype
- **Code**
  - Semgrep findings introduced by the PR only

Both are evaluated under a **single policy and severity model**.

---

### 3. Baseline confidence

If a baseline comparison is imperfect (e.g. new lockfile, unavailable ref):

- Release Guardian still produces a decision
- A **confidence penalty** is applied to the score
- The uncertainty is explicitly stated in the PR comment

This avoids false certainty while keeping teams moving.

---

### 4. RDI — Release Decision Index

Each PR receives an **RDI score (0–100)**:

- Higher = safer to ship
- Derived from:
  - Worst introduced severity
  - Volume of introduced findings
  - Risk surface (deps + code)
  - Baseline confidence

RDI is a **decision signal**, not a vanity metric.

---

### 5. Clear outcomes

Release Guardian always returns one of three outcomes:

| Verdict | Meaning |
|---|---|
| **Go** | Safe to ship |
| **Conditional** | Risk introduced, but acceptable |
| **No-Go** | Introduced risk exceeds policy |

These outcomes map directly to GitHub commit statuses.

---

## PR experience

At a glance, reviewers see:

- **Verdict + RDI score**
- **Why** the decision was made (1–2 sentences)
- **Introduced risk summary**
  - Dependency clusters introduced
  - Code findings introduced
- **Expandable details**
  - Trivy
  - Grype
  - Semgrep
- **Visual severity indicators** for instant scanning

The goal: **fast understanding, not security expertise.**

---

## Example output

**❌ No-Go — RDI 23**

- Introduced risk: deps=1 cluster / 4 advisories, code=2 findings  
- Worst = **CRITICAL** (sources: deps, code)  
- Decision: introduced risk meets/exceeds threshold (**HIGH**)  

_“Details are available below — but the decision is immediate.”_

---

## Configuration (v1)

Release Guardian is intentionally opinionated in v1: **introduced risk only**, with a **single policy gate**.

### Example GitHub workflow

```yaml
- name: Release Guardian
  uses: ./action
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    mode: enforce
    severity_threshold: high
    allow_conditional: false
```
### Inputs

| Input | Description |
|---|---|
| `mode` | `enforce` or reporting-only |
| `severity_threshold` | Minimum severity that can block a release |
| `allow_conditional` | Allow **Conditional** instead of **No-Go** |

---

## What Release Guardian is not

- ❌ A vulnerability scanner  
- ❌ A compliance checklist  
- ❌ A dashboard-first product  

Release Guardian is a **decision layer** — it turns multiple security signals into one merge-time outcome.

## Roadmap (post-v1)

Planned, but intentionally not part of v1:

- Organization-level policy packs (shared rules across repos)
- RDI trend over time (PR → main)
- “Why this matters” remediation context per finding
- Suppressions with expiration + justification
- SaaS control plane (optional)

## Philosophy

> Security should help teams ship safely — not stop shipping forever.

Release Guardian makes risk:

- Introduced  
- Visible  
- Actionable  
- Decidable 
