# security-pipeline

Reusable GitHub Actions security pipeline. Call it from any repo's workflow — it runs four detection layers in sequence on every PR and raises a PR with new Semgrep rules whenever Claude finds a gap.

---

## Layers

| # | Tool | What it catches | Blocks PR? |
|---|------|----------------|------------|
| L1 | Gitleaks | Hardcoded secrets, credentials, tokens | Yes — any finding |
| L2 | Trivy | CVEs in dependencies, IaC misconfigs | Yes — CRITICAL/HIGH |
| L3 | Semgrep | SAST patterns (custom rules + optional external pack) | Yes — ERROR severity |
| L4 | Claude `claude-sonnet-4-6` | Logic flaws, auth bypasses, taint flows rules miss | Yes — CRITICAL/HIGH |

Each layer must pass before the next runs. If L1 finds a secret, L2–L4 never execute.

---

## How to use it

### 1. Add the caller workflow

In your repo, create `.github/workflows/security.yml`:

```yaml
name: Security

on:
  pull_request:
    branches: [main, staging, dev]
    types: [opened, synchronize, reopened]

jobs:
  security:
    uses: YOUR_ORG/security-pipeline/.github/workflows/security-pipeline.yml@main
    secrets:
      CLAUDE_API_KEY: ${{ secrets.CLAUDE_API_KEY }}
      # Optional — see "Shared rules repo" below
      SEMGREP_RULES_REPO: ${{ secrets.SEMGREP_RULES_REPO }}
      RULES_REPO_TOKEN: ${{ secrets.RULES_REPO_TOKEN }}
```

Replace `YOUR_ORG/security-pipeline` with wherever this repo lives.

### 2. Set the required secret

In your repo → **Settings → Secrets and variables → Actions**:

| Secret | Required | Value |
|--------|----------|-------|
| `CLAUDE_API_KEY` | Yes | Anthropic API key |
| `SEMGREP_RULES_REPO` | No | `org/rules-repo` — shared Semgrep rules repo |
| `RULES_REPO_TOKEN` | No | PAT with `contents:write` + `pull-requests:write` on that rules repo |

---

## What happens on a PR

```
PR opened / updated
      │
      ▼
L1 · Gitleaks ──── fail → PR blocked (secret found)
      │ pass
      ▼
L2 · Trivy ──────── fail → PR blocked (CVE/misconfig)
      │ pass
      ▼
L3 · Semgrep ────── fail → PR blocked (SAST finding)
      │ pass
      ▼
L4 · Claude ──────── fail → PR blocked (semantic finding)
      │ always runs regardless of L4 result
      ▼
Generate rules ──── finds gaps → raises a PR with new Semgrep rules
```

L4 also posts a summary comment on the PR listing every finding with severity, CWE, OWASP category, file, and line.

---

## Self-healing rules loop

After L4, the pipeline automatically generates Semgrep rules for any CRITICAL/HIGH finding not already covered by an existing rule (matched by CWE ID). Rules are generated via Claude with extended thinking in batches of 3.

Where the PR lands depends on your config:

| Config | PR destination | Path in that repo |
|--------|---------------|-------------------|
| `SEMGREP_RULES_REPO` + `RULES_REPO_TOKEN` set | Your dedicated rules repo | `custom-rules.yml` |
| Neither set | The repo that triggered the workflow | `.security/semgrep-rules.yml` |

Branch name: `security/gap-rules-YYYYMMDD-HHMMSS`

The next time L3 runs, it picks up any merged rules from the rules repo automatically.

> **Loop prevention**: PRs from branches starting with `security/` never trigger rule generation, so there is no infinite feedback loop.

---

## Shared rules repo (recommended for teams)

If multiple repos call this pipeline, point them all at a single rules repo:

```yaml
# In every caller repo's secrets:
SEMGREP_RULES_REPO: myorg/semgrep-rules
RULES_REPO_TOKEN:   <PAT>
```

The pipeline clones that repo on every L3 run and appends new rules to `custom-rules.yml` via PR. One repo accumulates rules from all your services.

---

## Custom detection rules

### Gitleaks (`scripts/gitleaks.toml`)

Six custom rules on top of the Gitleaks default set:

- `hardcoded-password-assignment` — `password = "value"` patterns
- `hardcoded-hmac-secret` — `createHmac("sha256", "literal")`
- `hardcoded-cookie-secret` — `cookieSecret = "value"`
- `hardcoded-crypto-key` — `cryptoKey = "value"`
- `hardcoded-credential-map` — `credMap["user"] = "pass"`
- `jwt-secret-inline` — `jwt.sign(payload, "literal")`

The config intentionally skips binary files and generated assets but does **not** honour allowlists embedded in target repos — those are typically demo-app noise suppressors.

### Semgrep (`scripts/config/semgrep-custom-rules.yml`)

Custom SAST rules tuned for injection, auth bypasses, secrets exposure, and insecure crypto. Claude-generated gap-fill rules are appended here (or to your external rules repo) over time.

---

## Artifacts

Every run uploads two artifacts (retained 7–14 days):

| Artifact | Contents |
|----------|----------|
| `l4-findings-<run_id>` | `/tmp/ci_findings.json` — all L4 findings with severity, CWE, file, line |
| `generated-semgrep-rules-<run_id>` | `/tmp/generated_rules.yml` — rules generated this run (also in the PR) |

---

## Repository layout

```
.github/workflows/
  security-pipeline.yml     # Reusable workflow — call this from other repos

scripts/
  ci/
    l4_claude_ci.py          # L4: diff-aware Claude analysis, PR comment, exit 1 on CRITICAL/HIGH
    generate_rules_ci.py     # Post-L4: generate Semgrep rules for gaps, raise PR
  config/
    semgrep-custom-rules.yml # Active Semgrep rule set
  prompts/
    constants.py             # SEMGREP_RULE_SYSTEM prompt used by rule generation
  gitleaks.toml              # Custom Gitleaks rules (extends default set)
```

---

## L4 analysis scope

The Claude analysis is diff-aware and scans only changed files. Limits per run:

- Max 40 files
- Max 3 000 chars per file
- Max 150 000 prompt chars total
- Skips: `node_modules`, `.git`, `__pycache__`, `dist`, `build`, `.next`, `vendor`, `target`, `bin`, `obj`, `.security-tools`

Supported extensions: `.py .js .ts .jsx .tsx .java .kt .kts .go .rb .php .cs .swift .env .yaml .yml .toml .xml .config .cfg .ini .sh .bash .sql`

Claude reports only findings with confidence ≥ 8/10. MEDIUM/LOW findings appear as advisory comments on the PR but do not block it.
