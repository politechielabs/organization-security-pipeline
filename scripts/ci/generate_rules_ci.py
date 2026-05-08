#!/usr/bin/env python3
"""
CI Semgrep rule generator — runs after L4 Claude analysis.

Reads /tmp/ci_findings.json, filters for CRITICAL/HIGH findings whose CWE IDs
are not already covered by existing Semgrep rules, generates new Semgrep YAML
rules via Claude, and either:
  - Creates a PR in SEMGREP_RULES_REPO (if SEMGREP_RULES_REPO + RULES_REPO_TOKEN set)
  - Saves rules to /tmp/generated_rules.yml only (workflow uploads it as artifact)

Environment:
    CLAUDE_API_KEY       — Anthropic API key (required)
    SEMGREP_RULES_REPO   — External rules repo in org/repo format (optional)
    RULES_REPO_TOKEN     — PAT with write access to SEMGREP_RULES_REPO (optional)
    PR_NUMBER            — Source PR number (used in commit/PR messages)
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import anthropic
import yaml

# ─── Paths ───────────────────────────────────────────────────────────────────

# Script lives at .security-tools/scripts/ci/generate_rules_ci.py
# ROOT resolves to .security-tools/ (the security_rep checkout)
ROOT = Path(__file__).resolve().parent.parent.parent
FINDINGS_PATH = Path("/tmp/ci_findings.json")
CUSTOM_RULES_PATH = ROOT / "scripts" / "config" / "semgrep-custom-rules.yml"
GENERATED_RULES_OUTPUT = Path("/tmp/generated_rules.yml")

MODEL = "claude-sonnet-4-6"
BATCH_SIZE = 3

sys.path.insert(0, str(ROOT))
from scripts.prompts.constants import SEMGREP_RULE_SYSTEM  # noqa: E402

# ─── Findings helpers ────────────────────────────────────────────────────────


def load_critical_high_findings() -> list[dict]:
    if not FINDINGS_PATH.exists():
        print("No findings file at /tmp/ci_findings.json — skipping rule generation")
        return []
    data = json.loads(FINDINGS_PATH.read_text())
    if data.get("skipped"):
        print("L4 was skipped — no findings to process")
        return []
    return [f for f in data.get("findings", []) if f.get("severity") in ("CRITICAL", "HIGH")]


def load_existing_cwes() -> set[str]:
    if not CUSTOM_RULES_PATH.exists():
        return set()
    try:
        rules_data = yaml.safe_load(CUSTOM_RULES_PATH.read_text()) or {}
        cwes: set[str] = set()
        for rule in rules_data.get("rules", []):
            cwe_str = rule.get("metadata", {}).get("cwe", "")
            for cwe in re.split(r"[|,\s]+", cwe_str):
                cwe = cwe.strip().upper()
                if cwe:
                    cwes.add(cwe)
        return cwes
    except Exception:
        return set()


def filter_novel(findings: list[dict], existing_cwes: set[str]) -> list[dict]:
    novel = []
    for f in findings:
        cwe_ids = {
            c.strip().upper()
            for c in re.split(r"[|,\s]+", f.get("cwe", ""))
            if c.strip()
        }
        if not cwe_ids or not cwe_ids.intersection(existing_cwes):
            novel.append(f)
    return novel


# ─── Language detection ──────────────────────────────────────────────────────

_EXT_LANG: dict[str, str] = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".go": "go",
    ".rb": "ruby", ".php": "php", ".cs": "csharp",
    ".swift": "swift", ".sh": "bash",
}


def detect_language(filepath: str) -> str:
    return _EXT_LANG.get(Path(filepath).suffix.lower(), "generic")


def format_for_prompt(findings: list[dict]) -> str:
    return json.dumps(
        [
            {
                "category": f.get("category", "Security"),
                "sub_category": f.get("vulnerability", ""),
                "vulnerability": f.get("vulnerability", ""),
                "cwe": f.get("cwe", "CWE-unknown"),
                "language": detect_language(f.get("file", "")),
            }
            for f in findings
        ],
        indent=2,
    )


# ─── YAML helpers ────────────────────────────────────────────────────────────


def sanitize_yaml_patterns(text: str) -> str:
    pattern_re = re.compile(
        r"^( *)- (pattern(?:-not|-regex|-inside|-either)?): (.+)$",
        re.MULTILINE,
    )

    def fix_match(m: re.Match) -> str:
        leading, key, value = m.group(1), m.group(2), m.group(3).strip()
        if value in ("|", "|-", "|+", ">", ">-"):
            return m.group(0)
        if (value.startswith("'") and value.endswith("'")) or (
            value.startswith('"') and value.endswith('"')
        ):
            inner = value[1:-1]
            if any(c in inner for c in ["'", "{", "[", "#"]) or ": " in inner:
                value = inner
            else:
                return m.group(0)
        if not (any(c in value for c in ["'", "{", "[", "#"]) or ": " in value):
            return m.group(0)
        content_indent = leading + "    "
        return f"{leading}- {key}: |-\n{content_indent}{value}"

    return pattern_re.sub(fix_match, text)


def merge_yaml_blocks(blocks: list[str]) -> str:
    rule_entries: list[str] = []
    for block in blocks:
        in_rules = False
        current: list[str] = []
        for line in block.splitlines():
            if line.strip() == "rules:":
                in_rules = True
                continue
            if in_rules:
                if line.startswith("  - ") and current:
                    rule_entries.append("\n".join(current))
                    current = [line]
                else:
                    current.append(line)
        if current:
            rule_entries.append("\n".join(current))
    return "rules:\n" + "\n\n".join(rule_entries) + "\n"


# ─── Claude rule generation ───────────────────────────────────────────────────


def generate_rules_yaml(client: anthropic.Anthropic, findings: list[dict]) -> str:
    vuln_list = format_for_prompt(findings)
    msg = client.messages.create(
        model=MODEL,
        max_tokens=8192,
        thinking={"type": "enabled", "budget_tokens": 5000},
        temperature=1,
        messages=[
            {
                "role": "user",
                "content": SEMGREP_RULE_SYSTEM.replace("{vuln_list}", vuln_list),
            }
        ],
    )
    text = next(b.text for b in msg.content if b.type == "text").strip()
    if text.startswith("```"):
        text = "\n".join(
            line for line in text.splitlines() if not line.strip().startswith("```")
        ).strip()
    return text


# ─── Deduplication ───────────────────────────────────────────────────────────


def deduplicate_rules(new_yaml: str, existing_path: Path) -> str:
    if not existing_path.exists():
        return new_yaml
    try:
        existing = yaml.safe_load(existing_path.read_text()) or {}
        existing_ids = {r["id"] for r in existing.get("rules", []) if "id" in r}
        new_data = yaml.safe_load(new_yaml) or {}
        new_rules = [r for r in new_data.get("rules", []) if r.get("id") not in existing_ids]
        skipped = len(new_data.get("rules", [])) - len(new_rules)
        if skipped:
            print(f"    Skipped {skipped} duplicate rule(s)")
        if not new_rules:
            return ""
        return yaml.dump({"rules": new_rules}, default_flow_style=False, allow_unicode=True)
    except Exception as exc:
        print(f"    Warning: deduplication failed ({exc}) — using all generated rules")
        return new_yaml


# ─── PR creation ─────────────────────────────────────────────────────────────


def _git(args: list[str], cwd: str | None = None) -> None:
    subprocess.run(["git"] + args, cwd=cwd, check=True)


def create_pr_in_rules_repo(
    rules_yaml: str, rules_repo: str, token: str, pr_number: str,
    rules_file_path: str = "custom-rules.yml",
) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"security/gap-rules-{timestamp}"
    clone_url = f"https://x-access-token:{token}@github.com/{rules_repo}"

    with tempfile.TemporaryDirectory() as tmpdir:
        subprocess.run(["git", "clone", "--depth=1", clone_url, tmpdir], check=True)
        _git(["config", "user.email", "security-ci@github.com"], cwd=tmpdir)
        _git(["config", "user.name", "Security CI"], cwd=tmpdir)
        _git(["checkout", "-b", branch], cwd=tmpdir)

        rules_file = Path(tmpdir) / rules_file_path
        rules_file.parent.mkdir(parents=True, exist_ok=True)
        with rules_file.open("a") as fh:
            fh.write(f"\n# Auto-generated from PR #{pr_number} — {timestamp}\n")
            fh.write(rules_yaml + "\n")

        _git(["add", rules_file_path], cwd=tmpdir)
        _git(
            ["commit", "-m", f"chore: gap-fill rules from PR #{pr_number} [skip ci]"],
            cwd=tmpdir,
        )
        _git(["push", "origin", branch], cwd=tmpdir)

        subprocess.run(
            [
                "gh", "pr", "create",
                "--repo", rules_repo,
                "--head", branch,
                "--base", "main",
                "--title", f"security: gap-fill Semgrep rules (from PR #{pr_number})",
                "--body", (
                    f"## New Semgrep Rules\n\n"
                    f"Auto-generated from L4 Claude analysis of PR #{pr_number}.\n\n"
                    f"These rules close detection gaps found by semantic analysis.\n\n"
                    f"**Review before merging.**"
                ),
            ],
            check=True,
            env={**os.environ, "GH_TOKEN": token},
        )
    print(f"    Created rules PR in {rules_repo} — branch: {branch}")


def create_pr_in_caller_repo(rules_yaml: str, caller_repo: str, token: str, pr_number: str) -> None:
    """Fallback: raise PR in the calling repo at .security/semgrep-rules.yml."""
    create_pr_in_rules_repo(
        rules_yaml, caller_repo, token, pr_number,
        rules_file_path=".security/semgrep-rules.yml",
    )


# ─── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    api_key = os.environ.get("CLAUDE_API_KEY")
    if not api_key:
        print("CLAUDE_API_KEY not set — skipping rule generation")
        sys.exit(0)

    findings = load_critical_high_findings()
    if not findings:
        print("No CRITICAL/HIGH findings — nothing to generate rules for")
        sys.exit(0)

    existing_cwes = load_existing_cwes()
    novel = filter_novel(findings, existing_cwes)
    if not novel:
        print(f"All {len(findings)} finding(s) already covered by existing Semgrep rules")
        sys.exit(0)

    print(f"\n{len(novel)} novel finding(s) need new Semgrep rules:")
    for f in novel:
        print(f"  [{f.get('severity'):8}] {f.get('vulnerability')} ({f.get('cwe')})")

    client = anthropic.Anthropic(api_key=api_key)
    all_blocks: list[str] = []

    batches = [novel[i : i + BATCH_SIZE] for i in range(0, len(novel), BATCH_SIZE)]
    for idx, batch in enumerate(batches, 1):
        print(f"\nBatch {idx}/{len(batches)} — {len(batch)} finding(s)...")
        yaml_text = generate_rules_yaml(client, batch)
        all_blocks.append(yaml_text)
        print(f"    Received {len(yaml_text)} chars")

    final_yaml = sanitize_yaml_patterns(merge_yaml_blocks(all_blocks))

    try:
        parsed = yaml.safe_load(final_yaml)
        rule_count = len(parsed.get("rules", []))
        print(f"\nYAML valid — {rule_count} rule(s) generated")
    except yaml.YAMLError as exc:
        print(f"\nWarning: YAML validation failed: {exc}")

    deduped = deduplicate_rules(final_yaml, CUSTOM_RULES_PATH)
    if not deduped:
        print("All generated rules are duplicates — nothing to commit")
        sys.exit(0)

    # Always save for artifact upload (workflow handles the upload step)
    GENERATED_RULES_OUTPUT.write_text(deduped)
    print(f"\n    Saved → {GENERATED_RULES_OUTPUT}")

    pr_number = os.environ.get("PR_NUMBER", "unknown")
    rules_repo = os.environ.get("SEMGREP_RULES_REPO", "")
    rules_token = os.environ.get("RULES_REPO_TOKEN", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    caller_repo = os.environ.get("GITHUB_REPOSITORY", "")

    if rules_repo and rules_token:
        print(f"\nCreating rules PR in external repo: {rules_repo}")
        create_pr_in_rules_repo(deduped, rules_repo, rules_token, pr_number)
    elif github_token and caller_repo:
        print(f"\nNo external rules repo configured — creating PR in caller repo: {caller_repo}")
        create_pr_in_caller_repo(deduped, caller_repo, github_token, pr_number)
    else:
        print(
            "\nNo token/repo available — rules saved as artifact only.\n"
            f"Path: {GENERATED_RULES_OUTPUT}"
        )
        sys.exit(0)

    print("\n✅ Semgrep rules PR created")


if __name__ == "__main__":
    main()
