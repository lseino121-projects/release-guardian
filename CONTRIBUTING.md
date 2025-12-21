# Contributing to Release Guardian

Thanks for your interest in contributing! 🎉

Release Guardian is a decision engine that turns multiple security signals into a single merge-time verdict based on **introduced risk**. It prevents vulnerable code from reaching production while keeping developer velocity high.

---

## Quick Start (Local Development)

### Requirements

- **Docker** (recommended for testing the action)
- **Python 3.12+** (optional, only if running engine directly)
- **Git**

### Run the Action Locally (Recommended)

**1. Build the action image:**

```bash
docker build -t release-guardian:dev -f action/Dockerfile action
```

**2. Create a local event payload:**

Create `.rg/event.json` in your repo root:

```json
{
  "pull_request": {
    "number": 1,
    "base": { "sha": "BASE_SHA" },
    "head": { "sha": "HEAD_SHA" }
  },
  "repository": {
    "full_name": "your-org/your-repo"
  }
}
```

Replace `BASE_SHA` and `HEAD_SHA` with actual commit SHAs from your test repository.

**3. Run the action container:**

```bash
docker run --rm \
  -v "$(pwd)":/github/workspace \
  -e GITHUB_WORKSPACE=/github/workspace \
  -e GITHUB_EVENT_NAME=pull_request \
  -e GITHUB_EVENT_PATH=/github/workspace/.rg/event.json \
  -e GITHUB_REPOSITORY=local/release-guardian \
  -e GITHUB_SHA=HEAD_SHA \
  -e INPUT_GITHUB_TOKEN=dummy \
  -e INPUT_MODE=enforce \
  -e INPUT_SEVERITY_THRESHOLD=high \
  -e INPUT_ALLOW_CONDITIONAL=false \
  release-guardian:dev
```

**Note:** `INPUT_GITHUB_TOKEN` is only needed if you want the action to post statuses/comments to GitHub. For local runs, a dummy token is fine if you skip GitHub API calls.

---

### Run Only the Engine (No GitHub API)

From repo root:

```bash
python -m rg.main \
  --event-path .rg/event.json \
  --repo local/release-guardian \
  --sha HEAD_SHA \
  --mode enforce \
  --severity-threshold high \
  --allow-conditional false \
  --out-json .rg/report.json \
  --out-md .rg/comment.md
```

This generates:
- `.rg/report.json` — Structured verdict + findings
- `.rg/comment.md` — Formatted comment for PR

---

## Project Structure

```
release-guardian/
├── action/
│   ├── rg/
│   │   ├── main.py              # Entry point
│   │   ├── normalize/           # Tool output normalization
│   │   ├── rdi/                 # Risk Decision Intelligence
│   │   │   ├── policy_v1.py     # Gating logic
│   │   │   └── scorer.py        # Risk scoring
│   │   ├── rules/               # Semgrep rules (organized by language)
│   │   │   ├── python/
│   │   │   ├── javascript/
│   │   │   ├── terraform/
│   │   │   └── docker/
│   │   └── integrations/        # GitHub, Semgrep, etc.
│   ├── Dockerfile
│   └── action.yml
├── examples/
│   ├── unsafe/                  # Intentionally vulnerable test cases
│   └── safe/                    # Clean reference code
├── docs/
├── tests/
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

---

## Adding Semgrep Rules

Release Guardian uses repository-local Semgrep rules under `action/rg/rules/`.

### How to Add a New Rule

**1. Create a YAML rule file in the appropriate language folder:**

```
action/rg/rules/
├── python/          # Python-specific rules
├── javascript/      # JavaScript/TypeScript rules
├── terraform/       # Infrastructure-as-code rules
├── docker/          # Dockerfile rules
└── general/         # Language-agnostic patterns
```

**2. Ensure your rule has:**

- **Stable `id`**: Use format `release-guardian-<language>-<category>-<name>`
  ```yaml
  id: release-guardian-python-crypto-weak-hash
  ```

- **Accurate `severity`**: Must be one of:
  - `ERROR` (maps to CRITICAL)
  - `WARNING` (maps to HIGH)
  - `INFO` (maps to MEDIUM/LOW)

- **Clear metadata**:
  ```yaml
  metadata:
    cwe: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
    owasp: "A02:2021 - Cryptographic Failures"
    confidence: HIGH
    likelihood: MEDIUM
    impact: HIGH
    references:
      - https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
  ```

**3. Example rule:**

```yaml
rules:
  - id: release-guardian-python-crypto-weak-hash
    severity: WARNING
    languages:
      - python
    message: |
      Weak cryptographic hash function detected. MD5 and SHA1 are vulnerable
      to collision attacks. Use SHA256 or stronger.
    patterns:
      - pattern-either:
          - pattern: hashlib.md5(...)
          - pattern: hashlib.sha1(...)
    fix: hashlib.sha256(...)
    metadata:
      cwe: "CWE-327"
      owasp: "A02:2021"
      confidence: HIGH
      likelihood: MEDIUM
      impact: HIGH
      references:
        - https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
```

**4. Add test fixtures:**

Create examples under:
- `examples/unsafe/<language>/` — Intentionally insecure code that should trigger your rule
- `examples/safe/<language>/` — Clean code that should NOT trigger your rule

Example: `examples/unsafe/python/weak_crypto.py`
```python
import hashlib

def hash_password(password):
    # BAD: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()
```

**5. Test your rule locally:**

```bash
# Run Semgrep with your new rule
semgrep --config action/rg/rules/python/ examples/unsafe/python/

# Verify it catches the vulnerability
# Verify it doesn't false-positive on safe examples
```

---

## Normalization & Policy Changes

### Normalization

Tool output normalization lives under `action/rg/normalize/`.

Each tool has a normalizer that converts its output to a common format:

```python
# action/rg/normalize/semgrep.py
class SemgrepNormalizer:
    def normalize(self, raw_output: dict) -> List[Finding]:
        # Convert Semgrep JSON → Finding objects
        pass
```

### Introduced vs. Baseline Logic

The "introduced risk" calculation lives in `action/rg/rdi/`.

Key files:
- `action/rg/rdi/scorer.py` — Risk scoring logic
- `action/rg/rdi/policy_v1.py` — Gating policy (when to block merges)

**Example policy change:**

If you want to adjust when PRs get blocked, edit `policy_v1.py`:

```python
def should_block(findings: List[Finding], config: Config) -> bool:
    """
    Determines if PR should be blocked based on introduced findings.
    
    Current policy:
    - Block if ANY critical introduced finding
    - Block if 3+ high introduced findings
    - Block if 10+ medium introduced findings
    """
    critical = [f for f in findings if f.severity == "CRITICAL"]
    high = [f for f in findings if f.severity == "HIGH"]
    medium = [f for f in findings if f.severity == "MEDIUM"]
    
    if len(critical) > 0:
        return True
    if len(high) >= 3:
        return True
    if len(medium) >= 10:
        return True
    
    return False
```

**When changing policy:**
1. Include a clear explanation of intent in your PR
2. Provide before/after examples (screenshots or pasted output)
3. Consider impact on existing users (breaking change?)

---

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] **Tests or reproduction steps included**
  - If adding a rule, include test fixtures in `examples/`
  - If changing policy, include example PR output

- [ ] **PR comment output renders cleanly**
  - Test locally with `--out-md` flag
  - Verify markdown formatting is correct

- [ ] **No secrets/tokens committed**
  - Check with: `git diff --cached | grep -i 'token\|secret\|password'`
  - Use `.env.example` for configuration templates

- [ ] **Code follows project style**
  - Python: Follow PEP 8, use type hints
  - Use descriptive variable names
  - Add docstrings for new functions

- [ ] **Documentation updated (if needed)**
  - Update README.md if adding new features
  - Update rule documentation in `docs/rules.md`

- [ ] **Semgrep rules are deterministic**
  - Rules should have clear, reproducible patterns
  - Avoid overly broad patterns that cause false positives
  - Include `fix:` suggestions where possible

---

## Testing Guidelines

### Unit Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_policy.py

# Run with coverage
pytest --cov=rg --cov-report=html
```

### Integration Tests

```bash
# Test against real repositories
./scripts/test_real_repo.sh https://github.com/example/repo
```

### Manual Testing Workflow

1. Create a test PR in a sandbox repository
2. Add intentionally vulnerable code
3. Run Release Guardian action
4. Verify:
   - Correct findings detected
   - Accurate severity classification
   - Clean PR comment formatting
   - Proper GitHub status check

---

## Rule Writing Best Practices

### ✅ DO:
- Write specific patterns that target real vulnerabilities
- Include `fix:` suggestions when possible
- Add metadata (CWE, OWASP, references)
- Test against both vulnerable and safe code
- Use descriptive IDs: `release-guardian-python-sql-injection-format-string`

### ❌ DON'T:
- Write overly broad patterns that cause false positives
- Duplicate existing Semgrep community rules (link to them instead)
- Hardcode secrets in example code (use placeholders)
- Forget to specify `languages:`
- Use ambiguous severity levels

### Example: Good vs. Bad Rule

**❌ Bad (too broad):**
```yaml
- id: bad-eval
  pattern: eval(...)
  severity: ERROR
  message: Don't use eval
```

**✅ Good (specific, actionable):**
```yaml
- id: release-guardian-python-code-injection-eval
  patterns:
    - pattern: eval($VAR)
    - pattern-not: eval("...")  # Exclude string literals
  severity: ERROR
  languages: [python]
  message: |
    Potential code injection via eval(). User input passed to eval()
    can execute arbitrary code. Use ast.literal_eval() for safe evaluation
    of literals, or use a proper parser.
  fix: ast.literal_eval($VAR)
  metadata:
    cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"
    owasp: "A03:2021 - Injection"
```

---

## Getting Help

- **Questions?** Open a [GitHub Discussion](https://github.com/your-org/release-guardian/discussions)
- **Bug reports?** Open a [GitHub Issue](https://github.com/your-org/release-guardian/issues)
- **Security concerns?** See [SECURITY.md](./SECURITY.md)

---

## Code of Conduct

**Be respectful. Assume good intent. Keep discussions technical and constructive.**

We're all here to build better security tooling. Disagreements on approach are welcome—personal attacks are not.

---

## License

By contributing to Release Guardian, you agree that your contributions will be licensed under the same license as the project (see [LICENSE](./LICENSE)).

---

**Thank you for helping make Release Guardian better! 🚀**