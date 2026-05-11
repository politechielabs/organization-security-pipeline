# organization-security-pipeline

Reusable GitHub Actions security pipeline. Wire it into any repo in one step — it runs four detection layers in sequence on every PR, posts inline comments per finding, and auto-generates Semgrep rules whenever Claude finds a gap not covered by existing rules.

---

## Layers

| # | Tool | What it catches | Blocks PR? | PR feedback |
|---|------|----------------|------------|-------------|
| L1 | Gitleaks | Hardcoded secrets, credentials, tokens | Yes — any finding | Comment: table of leaked files + lines |
| L2 | Trivy | CVEs in dependencies, IaC misconfigs | Yes — CRITICAL/HIGH | Comment: CVE table with package, severity, fix version |
| L3 | Semgrep | SAST patterns (custom rules + community/GitLab packs) | Yes — ERROR severity | Comment: SAST findings table |
| L4 | Claude `claude-sonnet-4-6` | Logic flaws, auth bypasses, taint flows rules miss | No — advisory only | Inline review comments on exact file + line |

**Each layer only runs if the previous passed.** L1 fail → L2/L3/L4 skip. L2 fail → L3/L4 skip.

---

## Quick start — wire up a repo

### Step 1 — Add the caller workflow

In the target repo, create `.github/workflows/security.yml`:

```yaml
name: Security

on:
  pull_request:
    branches: [prod]  # only to be runned when in production 
    types: [opened, synchronize, reopened]

permissions:
  contents: write
  pull-requests: write

jobs:
  security:
    uses: politechielabs/organization-security-pipeline/.github/workflows/security-pipeline.yml@main
    secrets: inherit
```

> `secrets: inherit` passes all repo secrets through automatically. Alternatively pass them explicitly — see the secrets table below.

---

### Step 2 — Create the required secrets

Secrets live in two places depending on their purpose. Navigate to **Settings → Secrets and variables → Actions → New repository secret** in the relevant repo.

---

#### Secrets required in the **target repo** (the repo calling the pipeline)

> e.g. `politechielabs/test-security` — any repo that has the caller workflow

| Secret | Required | Description | How to get it |
|--------|----------|-------------|---------------|
| `CLAUDE_API_KEY` | **Yes** | Anthropic API key used by L4 to run Claude analysis and generate Semgrep rules | [console.anthropic.com](https://console.anthropic.com) → API Keys → Create key |
| `RULES_REPO_TOKEN` | **Yes** (if using a shared rules repo) | GitHub PAT with `contents:write` + `pull-requests:write` scope on the pipeline/rules repo. Used by L4 to push generated Semgrep rules as a PR | GitHub → Settings → Developer Settings → Personal access tokens → Fine-grained → select the pipeline repo → allow Contents (write) + Pull requests (write) |
| `PIPELINE_TOKEN` | No | Alternative token name some org setups use in place of `RULES_REPO_TOKEN`. Set whichever name your L4 job references | Same as above |

> The caller workflow uses `secrets: inherit` — all of the above are automatically forwarded to the reusable pipeline. You do **not** need to list them explicitly unless you want to override values.

---

#### Secrets required in the **pipeline repo** (`organization-security-pipeline`)

> These are only needed if you run the pipeline locally or trigger it directly on the pipeline repo itself (not typical for most users).

| Secret | Required | Description | How to get it |
|--------|----------|-------------|---------------|
| `CLAUDE_API_KEY` | **Yes** (for local/direct runs) | Same Anthropic API key as above | [console.anthropic.com](https://console.anthropic.com) |
| `GITHUB_TOKEN` | Auto-provided | GitHub automatically injects this — no action needed. Used for posting PR comments and reading PR metadata | Automatic |

---

#### Full secrets checklist

Before running the pipeline for the first time, verify all of these are set in the **target repo**:

```
✅ CLAUDE_API_KEY       → Anthropic key (required for L4)
✅ RULES_REPO_TOKEN     → PAT with write access to the pipeline repo (required for gap-rule PRs)
✅ GITHUB_TOKEN         → Auto-injected by GitHub (no setup needed)
```

To verify secrets are present: **target repo → Settings → Secrets and variables → Actions** — you should see `CLAUDE_API_KEY` and `RULES_REPO_TOKEN` listed (values are hidden but presence is shown).

> **If `RULES_REPO_TOKEN` is missing**: L4 will still run Claude analysis and post inline review comments, but the gap-rule PR step will fail silently (the job has `continue-on-error: true`).  
> **If `CLAUDE_API_KEY` is missing**: The entire L4 job will crash with an authentication error from the Anthropic API.

---

### Step 3 — Configure branch protection (recommended)

So that L1/L2/L3 failures actually block merging:

1. Go to **Settings → Branches → Add branch protection rule**
2. Branch name pattern: `main` (or your default branch)
3. Enable **Require status checks to pass before merging**
4. Search for and add these required checks:
   - `security / L1 · Gitleaks — Secrets`
   - `security / L2 · Trivy — SCA / CVE`
   - `security / L3 · Semgrep — SAST`
5. Enable **Require branches to be up to date before merging**
6. Save

> L4 (`security / L4 · Claude`) is intentionally excluded — it is advisory only and must never block merging.

---

### Step 4 — (Optional) Point gap rules at a shared rules repo

When Claude finds a CRITICAL/HIGH vulnerability not covered by an existing Semgrep rule, it auto-generates a rule and raises a PR. By default that PR goes into the repo that triggered the workflow. To collect rules centrally across all repos:

1. Create (or designate) a shared rules repo, e.g. `your-org/semgrep-rules`
2. Generate a GitHub PAT with `contents:write` + `pull-requests:write` scope on that repo
3. Add it as `RULES_REPO_TOKEN` in every caller repo's secrets
4. In the caller workflow, set the env variable (or pass as a secret):

```yaml
jobs:
  security:
    uses: politechielabs/organization-security-pipeline/.github/workflows/security-pipeline.yml@main
    secrets:
      CLAUDE_API_KEY: ${{ secrets.CLAUDE_API_KEY }}
      RULES_REPO_TOKEN: ${{ secrets.RULES_REPO_TOKEN }}
```

Gap-fill rule PRs will then land in `your-org/semgrep-rules` under `config/semgrep-custom-rules/custom_rules_<timestamp>.yml`.

---

### Step 5 — Open a PR and watch it run

Push a branch, open a pull request. The pipeline triggers automatically. You will see:

- **Checks tab** — four status checks appear (`L1 · Gitleaks`, `L2 · Trivy`, `L3 · Semgrep`, `L4 · Claude`)
- **PR comments** — L1/L2/L3 post a summary comment if they find anything
- **PR review** — L4 posts inline review comments on the exact line of each finding
- **New PR** (if Claude found gaps) — a `security/gap-rules-YYYYMMDD-HHMMSS` branch with generated Semgrep rules

---

## What happens on a PR

```
PR opened / updated
      │
      ▼
L1 · Gitleaks ──── fail → PR blocked + comment (leaked file:line table)
      │ pass only
      ▼
L2 · Trivy ──────── fail → PR blocked + comment (CVE table: package / severity / fix version)
      │ pass only
      ▼
L3 · Semgrep ────── fail → PR blocked + comment (SAST findings table)
      │ pass only
      ▼
L4 · Claude ──────── posts inline review comments per finding (never blocks)
      │
      ▼
Rule generation ─── CRITICAL/HIGH gaps → raises PR with new Semgrep rules
```

> L3 and L4 are skipped entirely when L1 or L2 fails — no wasted CI time.
> Only L1, L2, and L3 can block merging. L4 is advisory only.

---

## PR feedback per layer

### L1 — secret found

```
🔴 L1 · Gitleaks — PR Blocked

Found 1 secret(s) hardcoded in the repository.

| Rule                          | File     | Line |
|-------------------------------|----------|------|
| hardcoded-password-assignment | config.py | 12  |

Action required: Remove the exposed secret(s), rotate any leaked credentials, and re-push.
```

### L2 — CVE found

```
❌ L2 · Trivy — PR Blocked

Found 2 CRITICAL and 16 HIGH CVEs in dependencies.

| Package | Severity  | CVE            | Fix Available |
|---------|-----------|----------------|---------------|
| Django  | 🔴 CRITICAL | CVE-2024-42005 | 4.2.15        |
| Pillow  | 🟠 HIGH    | CVE-2026-25990 | 12.1.1        |

Action required: Update the packages listed above to the fixed versions.
```

### L3 — SAST finding

```
❌ L3 · Semgrep — PR Blocked

Found 3 SAST finding(s) in changed files.

| Rule                   | File   | Line | Message                          |
|------------------------|--------|------|----------------------------------|
| tainted-sql-string     | api.py | 16   | User input in SQL query          |
| path-traversal-open    | api.py | 24   | User input in file open()        |
| os-system-injection    | api.py | 33   | User input in os.system()        |

Action required: Fix the issues above before this PR can be merged.
```

### L4 — Claude inline review

Claude posts an inline review comment on the exact line with severity, CWE, OWASP category, and a remediation suggestion. For findings in files outside the PR diff (e.g. unchanged files Claude scanned), findings appear in the review body instead.

---

## Self-healing rules loop

After L4 runs, the pipeline automatically generates Semgrep rules for any CRITICAL/HIGH finding not already covered by an existing rule (matched by CWE ID). Rules are generated via Claude in batches of 3.

| Config | PR destination | File path |
|--------|----------------|-----------|
| `RULES_REPO_TOKEN` set | Shared rules repo | `config/semgrep-custom-rules/custom_rules_<timestamp>.yml` |
| Not set | Caller repo | `config/semgrep-custom-rules/custom_rules_<timestamp>.yml` |

Branch name: `security/gap-rules-YYYYMMDD-HHMMSS`

The next time L3 runs, merged rules are picked up automatically.

> **Loop prevention**: PRs from branches starting with `security/` skip L4 entirely — no infinite feedback loop.

---

## Local usage

Run the full pipeline locally against any directory:

```bash
# 1. Clone this repo
git clone https://github.com/politechielabs/organization-security-pipeline.git
cd organization-security-pipeline

# 2. Create a .env file
cp .env.example .env
# Edit .env and set CLAUDE_API_KEY=sk-ant-...

# 3. Install dependencies
pip install anthropic pyyaml python-dotenv semgrep==1.122.0

# 4. Install tools: gitleaks + trivy (must be on PATH)
#    macOS:  brew install gitleaks trivy
#    Linux:  see https://github.com/gitleaks/gitleaks and https://trivy.dev

# 5. Run against a target directory
python3 scripts/run_reviewer.py /path/to/your/repo

# Skip L1–L3 gates (test L4 + rule generation only)
python3 scripts/run_reviewer.py /path/to/your/repo --force
```

Results are written to `results/raw/claude_code/<target_name>.json`.

---

## Custom detection rules

### Gitleaks (`config/gitleaks.toml`)

Custom rules on top of the Gitleaks default set:

| Rule ID | Pattern caught |
|---------|---------------|
| `hardcoded-password-assignment` | `password = "value"` |
| `hardcoded-hmac-secret` | `createHmac("sha256", "literal")` |
| `hardcoded-cookie-secret` | `cookieSecret = "value"` |
| `hardcoded-crypto-key` | `cryptoKey = "value"` |
| `hardcoded-credential-map` | `credMap["user"] = "pass"` |
| `jwt-secret-inline` | `jwt.sign(payload, "literal")` |

### Semgrep (`config/semgrep-custom-rules/`)

Rules live as individual numbered YAML files (`custom_rules_1.yml`, `custom_rules_2.yml`, …). Each auto-generated run writes a new file — rule IDs never collide and Semgrep never silently skips duplicates.

Also includes the full `config/community/` and `config/gitlab/` rule packs (scanned on L3 in addition to custom rules).

To add your own rules: create `config/semgrep-custom-rules/custom_rules_N.yml` following the existing format.

---

## Artifacts

Every run uploads these artifacts (retained 14 days):

| Artifact | Contents |
|----------|----------|
| `gitleaks-sarif-<run_id>` | Filesystem + git history SARIF from L1 |
| `trivy-sarif-<run_id>` | Dependency CVE SARIF from L2 |
| `semgrep-sarif-<run_id>` | SAST findings SARIF from L3 |
| `generated-semgrep-rules-<run_id>` | New rules generated by L4 (also raised as a PR) |

---

## Repository layout

```
.github/workflows/
  security-pipeline.yml         # Reusable workflow — call this from other repos

config/
  gitleaks.toml                  # Custom Gitleaks rules (extends default set)
  trivy-comprehensive.yaml       # Trivy scan config
  semgrep-custom-rules/
    custom_rules_1.yml           # Initial custom Semgrep rule set
    custom_rules_<timestamp>.yml # Auto-generated gap-fill rules (one per L4 run)
  community/                     # Semgrep community rule packs
  gitlab/                        # Semgrep GitLab rule packs

scripts/
  run_reviewer.py                # 4-layer pipeline runner (local + CI entrypoint)
  analyze_with_agent.py          # Standalone Claude-only analysis script
  prompts/
    constants.py                 # SEMGREP_RULE_SYSTEM prompt for rule generation
```

---

## L4 analysis scope

Claude scans all files in the target directory. Per-run limits:

| Limit | Value |
|-------|-------|
| Max files | 60 |
| Max chars per file | 4 000 |
| Max total prompt chars | 180 000 |
| Min confidence to report | 8 / 10 |

Skipped directories: `node_modules`, `.git`, `__pycache__`, `dist`, `build`, `.next`, `vendor`, `target`, `bin`, `obj`, `config/`

Supported extensions: `.py .js .ts .jsx .tsx .java .kt .kts .go .rb .php .cs .swift .env .yaml .yml .toml .xml .config .cfg .ini .sh .bash .sql`

MEDIUM/LOW findings appear in the PR review body as advisory but do not block merging.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| L1 detects secrets in old commits | Gitleaks scans PR commits only, but another branch in the repo has a secret commit | Delete the branch with the secret commit; rewrite history if needed |
| L2 blocks on dependencies you can't update yet | A CVE has no upstream fix yet | Add it to `trivy-comprehensive.yaml` under `vulnerability.ignore-unfixed` |
| L3 finds 0 issues on Python/JS code | Custom rules are language-specific — check `config/semgrep-custom-rules/` for coverage | Add rules or enable community pack for that language |
| L4 inline comments don't appear | Findings reference files not changed in this PR | Findings for unchanged files appear in the PR review body instead |
| Gap rules PR goes to wrong repo | `RULES_REPO_TOKEN` not set or pointing at wrong repo | Set `RULES_REPO_TOKEN` secret in the target repo — must be a PAT with `contents:write` + `pull-requests:write` on the pipeline/rules repo |
