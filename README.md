# organization-security-pipeline

Reusable GitHub Actions security pipeline. Wire it into any repo in one step — it runs four detection layers in sequence on every PR, posts inline comments per finding, and auto-generates Semgrep rules whenever Claude finds a gap not covered by existing rules.

---

## Layers

| # | Tool | What it catches | Blocks PR? | PR feedback |
|---|------|----------------|------------|-------------|
| L1 | Gitleaks | Hardcoded secrets, credentials, tokens | Yes — any finding | Comment: table of leaked files + lines |
| L2 | Trivy | CVEs in dependencies, IaC misconfigs | Yes — CRITICAL only | Comment: CVE table with package and fix version (CRITICAL only) |
| L3 | Semgrep | SAST patterns (custom rules + community/GitLab packs) | Yes — ERROR severity | Comment: SAST findings table |
| L4 | Claude `claude-sonnet-4-6` | Logic flaws, auth bypasses, taint flows rules miss | No — advisory only | Inline review comments on exact file + line |

**Each layer only runs if the previous passed.** L1 fail → L2/L3/L4 skip. L2 fail → L3/L4 skip.

---

## Setup — add this pipeline to your repo

Total time: ~10 minutes. No tool installs required — everything runs in GitHub Actions.

---

### Prerequisites

Before starting, make sure you have:

- [ ] Admin access to the target repo (to add secrets and branch protection rules)
- [ ] An Anthropic API key — create one at [console.anthropic.com](https://console.anthropic.com) → API Keys → Create key
- [ ] Collaborator or owner access to `politechielabs/organization-security-pipeline` (to create a PAT for it)

---

### Step 1 — Add the caller workflow file

In your target repo, create the file `.github/workflows/security.yml` with this content:

```yaml
name: Security

on:
  pull_request:
    branches: [prod]          # production branch — adjust if yours is named differently
    types: [opened, synchronize, reopened]

permissions:
  contents: write
  pull-requests: write
  security-events: write

jobs:
  security:
    if: github.repository_owner == 'politechielabs'
    uses: politechielabs/organization-security-pipeline/.github/workflows/security-pipeline.yml@main
    secrets:
      CLAUDE_API_KEY: ${{ secrets.CLAUDE_API_KEY }}
      RULES_REPO_TOKEN: ${{ secrets.RULES_REPO_TOKEN }}
```

> The `if: github.repository_owner == 'politechielabs'` guard prevents this workflow from running if the repo is forked or moved outside the organization. Remove or update it if your org name differs.

Commit and push this file to your default branch (not a feature branch — it must be on `main`/`master` for GitHub Actions to pick it up).

---

### Step 2 — Get your Anthropic API key

1. Go to [console.anthropic.com](https://console.anthropic.com)
2. Click **API Keys** in the left sidebar
3. Click **Create Key**
4. Name it (e.g. `github-security-pipeline`)
5. Copy the key — it starts with `sk-ant-...`
6. Save it somewhere temporarily — you'll add it in Step 4

---

### Step 3 — Create a GitHub PAT for the pipeline repo

The pipeline needs permission to push auto-generated Semgrep rules back to `organization-security-pipeline` as a PR.

1. Go to **GitHub → Settings** (your personal settings, top-right avatar)
2. Click **Developer settings** → **Personal access tokens** → **Fine-grained tokens**
3. Click **Generate new token**
4. Set:
   - **Token name**: `security-pipeline-rules`
   - **Expiration**: 90 days (or No expiration)
   - **Resource owner**: `politechielabs`
   - **Repository access**: Only select repositories → `organization-security-pipeline`
   - **Permissions → Repository permissions**:
     - `Contents`: **Read and write**
     - `Pull requests`: **Read and write**
5. Click **Generate token**
6. Copy the token — it starts with `github_pat_...`

---

### Step 4 — Add secrets to your target repo

Navigate to your target repo on GitHub:

**Settings → Secrets and variables → Actions → New repository secret**

Add these two secrets:

| Secret name | Value |
|-------------|-------|
| `CLAUDE_API_KEY` | The `sk-ant-...` key from Step 2 |
| `RULES_REPO_TOKEN` | The `github_pat_...` token from Step 3 |

**Verify**: After saving, both secrets should appear in the list (values are hidden but names are shown). If either is missing the pipeline will not work correctly.

> `GITHUB_TOKEN` is **not** listed here — GitHub injects it automatically into every workflow run. No setup needed.

---

### Step 5 — Enforce checks with branch protection

Without this step the pipeline runs but cannot block a merge even if secrets or CVEs are found.

1. Go to your target repo → **Settings → Branches**
2. Click **Add branch protection rule** (or edit an existing rule for `main`)
3. Set **Branch name pattern**: `main` (or your default branch name)
4. Enable **Require status checks to pass before merging**
5. Click inside the search box and add these three checks one by one:
   ```
   security / L1 · Gitleaks — Secrets
   security / L2 · Trivy — SCA / CVE
   security / L3 · Semgrep — SAST
   ```
   > These checks only appear in the search box after the pipeline has run at least once. Open a test PR first if they don't show up.
6. Enable **Require branches to be up to date before merging**
7. Click **Save changes**

> Do **not** add `L4 · Claude` as a required check — it is advisory only and should never block merging.

---

### Step 6 — Open a test PR and verify

1. Create a feature branch: `git checkout -b test/security-check`
2. Make any small change (edit a comment, add a blank line)
3. Push and open a pull request against `main`
4. Go to the **Checks** tab of the PR

You should see four checks appear:

```
✅ security / L1 · Gitleaks — Secrets
✅ security / L2 · Trivy — SCA / CVE
✅ security / L3 · Semgrep — SAST
✅ security / L4 · Claude — Semantic Review + Rule Generation
```

If all pass, the pipeline is working. L4 will post an inline review even on a clean PR (it scans the full file context, not just the diff).

---

### What to check if something goes wrong

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| All 4 checks never appear on the PR | Workflow file is on a feature branch, not `main` | Merge `.github/workflows/security.yml` to `main` first |
| L4 crashes with authentication error | `CLAUDE_API_KEY` missing or wrong | Re-add the secret in Settings → Secrets |
| L4 runs but gap-rules PR never appears | `RULES_REPO_TOKEN` missing or wrong scope | Re-create PAT with `contents:write` + `pull-requests:write` on the pipeline repo |
| Status checks missing in branch protection search | Pipeline hasn't run yet | Open a test PR first, then come back and add the checks |
| L1 detects secrets in old commits | Another branch in the repo has a secret commit in history | Delete that branch; git history is shared across branches |

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
Rule generation ─── CRITICAL gaps → raises PR with new Semgrep rules
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
❌ L2 · Trivy — PR Blocked (CRITICAL CVEs found)

Found 1 CRITICAL CVE(s) — PR is blocked until resolved.

| Package | CVE            | Fix Available |
|---------|----------------|---------------|
| Django  | CVE-2024-42005 | 4.2.15        |

Action required: Fix CRITICAL CVEs before this PR can be merged.
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

## How each layer works in the code

### L1 · Gitleaks

Gitleaks runs **two independent scans** per PR — both write SARIF, results are merged and deduplicated before the comment is posted.

| Scan | Flag | What it covers |
|------|------|----------------|
| Filesystem | `--no-git` | Every file in the current working tree — catches secrets added in this PR |
| Git history | `--log-opts BASE_SHA..HEAD` | Only commits between the PR branch tip and the merge-base — prevents false positives from secrets on unrelated branches |

`BASE_SHA` is computed with `git merge-base HEAD origin/<base_ref>` so the scan is always scoped to exactly the commits this PR introduces.

Custom rules are loaded from `config/gitleaks.toml` (hardcoded passwords, HMAC secrets, cookie secrets, JWT literals, etc.). The job fails if the combined finding count from both SARIFs is > 0.

---

### L2 · Trivy

Uses `aquasecurity/trivy-action` in **filesystem mode** (`scan-type: fs`) — scans `requirements.txt`, `package.json`, `go.sum`, and other dependency manifests for known CVEs.

Key flags:

| Flag | Value | Effect |
|------|-------|--------|
| `severity` | `CRITICAL` | Only report CRITICAL CVEs — HIGH/MEDIUM/LOW are skipped |
| `ignore-unfixed` | `true` | Suppress CVEs that have no upstream fix yet (reduces noise) |
| `exit-code` | `1` | Non-zero exit on any finding → blocks the PR job |
| `skip-dirs` | `config/community,config/gitlab,.git,node_modules,vendor,.venv` | Excludes rule packs and vendored code |

The SARIF output is parsed by an inline Python script that groups findings by package and posts a single PR comment table with the CVE ID and the fixed version to upgrade to.

---

### L3 · Semgrep

Semgrep runs **diff-aware** — it only scans files that changed in this PR, not the full codebase.

**How diff-awareness works:**

```
git diff --name-only origin/<base_ref>...HEAD
  → filter to supported extensions (.py .js .ts .java .go .rb .php ...)
  → filter to files that still exist (not deleted)
  → write list to /tmp/semgrep_targets.txt
  → pass as positional arguments to semgrep
```

If no relevant files changed, an empty SARIF is written and the job exits 0 immediately — no Semgrep install cost.

**Rule loading:**

Rules come from two sources:
1. `config/semgrep-custom-rules/` in this repo (custom + auto-generated gap-fill rules)
2. Semgrep Registry packs downloaded at runtime: `p/python`, `p/javascript`, `p/typescript`, `p/java`, `p/kotlin`, `p/secrets`

No Semgrep login required. Registry packs stay fresh automatically.

**Blocking threshold:**

```bash
semgrep --config .security-tools/config/semgrep-custom-rules \
        --severity ERROR \
        --error \
        --sarif --output semgrep-results.sarif \
        <changed files>
```

`--severity ERROR` filters output to `severity: ERROR` rules only. `--error` makes semgrep exit non-zero when any ERROR finding exists. Rules with `severity: WARNING` appear in the SARIF but do not trigger the non-zero exit — they are shown in the PR comment as advisory.

---

After L4 runs, the pipeline automatically generates Semgrep rules for any CRITICAL finding not already covered by an existing rule (matched by CWE ID). Rules are generated via Claude in batches of 3.

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

L3 also pulls Semgrep Registry packs at runtime (`p/python`, `p/javascript`, `p/typescript`, `p/java`, `p/kotlin`, `p/secrets`) — no local copies needed.

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
  # community/ and gitlab/ not committed — registry packs downloaded at runtime

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
