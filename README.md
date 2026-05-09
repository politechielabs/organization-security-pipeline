# security-pipeline

Reusable GitHub Actions security pipeline. Call it from any repo's workflow — it runs four detection layers in sequence on every PR and raises a PR with new Semgrep rules whenever Claude finds a gap.

---

## Layers

| # | Tool | What it catches | Blocks PR? |
|---|------|----------------|------------|
| L1 | Gitleaks | Hardcoded secrets, credentials, tokens | Yes — any finding |
| L2 | Trivy | CVEs in dependencies, IaC misconfigs | Yes — CRITICAL/HIGH |
| L3 | Semgrep | SAST patterns (custom rules + optional external pack) | Yes — ERROR severity |
| L4 | Claude `claude-sonnet-4-6` | Logic flaws, auth bypasses, taint flows rules miss | No — posts inline review comments only |

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
L4 · Claude ──────── always runs; posts inline review comments per finding
      │               never blocks the PR
      ▼
Generate rules ──── CRITICAL/HIGH gaps → raises a PR with new Semgrep rules
```

L4 uses the GitHub Pull Request Reviews API to post an **inline comment on the exact file and line** for each finding. The review is submitted as `COMMENT` (never `REQUEST_CHANGES`), so the PR is never blocked by L4. CRITICAL/HIGH findings also trigger rule generation in the same job.

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

> **Loop prevention**: PRs from branches starting with `security/` skip L4 entirely, so there is no infinite feedback loop.

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

## Local usage

Run the full pipeline locally against any directory:

```bash
# Copy .env.example → .env and fill in CLAUDE_API_KEY
python3 scripts/run_reviewer.py <target_path>

# Skip L1–L3 hard gates (useful for testing L4 + rule generation)
python3 scripts/run_reviewer.py <target_path> --force
```

Results are written to `results/raw/claude_code/<target_name>.json`.

---

## Custom detection rules

### Gitleaks (`config/gitleaks.toml`)

Six custom rules on top of the Gitleaks default set:

- `hardcoded-password-assignment` — `password = "value"` patterns
- `hardcoded-hmac-secret` — `createHmac("sha256", "literal")`
- `hardcoded-cookie-secret` — `cookieSecret = "value"`
- `hardcoded-crypto-key` — `cryptoKey = "value"`
- `hardcoded-credential-map` — `credMap["user"] = "pass"`
- `jwt-secret-inline` — `jwt.sign(payload, "literal")`

### Semgrep (`config/semgrep-custom-rules/`)

Custom SAST rules live in `config/semgrep-custom-rules/` as individual numbered YAML files (`custom_rules_1.yml`, `custom_rules_2.yml`, …). Each auto-generated run writes a new file so rule IDs never collide and Semgrep never silently skips duplicates. Also includes the full `config/community/` and `config/gitlab/` rule packs.

---

## Artifacts

Every run uploads an artifact (retained 14 days):

| Artifact | Contents |
|----------|----------|
| `generated-semgrep-rules-<run_id>` | `/tmp/generated_rules.yml` — rules generated this run (also raised as a PR) |

---

## Repository layout

```
.github/workflows/
  security-pipeline.yml       # Reusable workflow — call this from other repos

config/
  gitleaks.toml               # Custom Gitleaks rules (extends default set)
  semgrep-custom-rules/
    custom_rules_1.yml        # Initial custom Semgrep rule set
    custom_rules_2.yml        # Auto-generated gap-fill rules (run N)
    …                         # One new file per generation run
  community/                  # Semgrep community rule packs
  gitlab/                     # Semgrep GitLab rule packs

scripts/
  run_reviewer.py             # 4-layer pipeline runner (local + CI entrypoint)
  analyze_with_agent.py       # Standalone Claude-only analysis script
  prompts/
    constants.py              # SEMGREP_RULE_SYSTEM prompt for rule generation
```

---

## L4 analysis scope

Claude scans all files in the target directory (CI: full workspace; local: specified path). Limits per run:

- Max 60 files
- Max 4 000 chars per file
- Max 180 000 prompt chars total
- Skips: `node_modules`, `.git`, `__pycache__`, `dist`, `build`, `.next`, `vendor`, `target`, `bin`, `obj`, `config/`

Supported extensions: `.py .js .ts .jsx .tsx .java .kt .kts .go .rb .php .cs .swift .env .yaml .yml .toml .xml .config .cfg .ini .sh .bash .sql`

Claude reports only findings with confidence ≥ 8/10. MEDIUM/LOW findings appear as advisory in the PR comment but do not block the PR.
