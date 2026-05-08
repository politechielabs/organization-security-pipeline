#!/usr/bin/env python3
"""
CI-adapted Claude L4 semantic security analysis.

Reads /tmp/all_changed.txt (written by the workflow's `git diff` step),
analyzes changed files for security vulnerabilities, posts a summary comment
on the PR, writes /tmp/ci_findings.json, and exits 1 if CRITICAL/HIGH findings
are present (blocking the PR).

Runs from the TARGET REPO's working directory so relative file paths resolve
correctly. The script itself lives in .security-tools/scripts/ci/ (a separate
checkout of security_rep).

Environment:
    CLAUDE_API_KEY   — Anthropic API key (required)
    GITHUB_TOKEN     — GitHub token for PR comments
    PR_NUMBER        — Pull request number
    REPO             — Repository in org/repo format
"""

import json
import os
import re
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import anthropic

# ─── Config ──────────────────────────────────────────────────────────────────

MODEL = "claude-sonnet-4-6"
CHANGED_FILES_PATH = "/tmp/all_changed.txt"
FINDINGS_OUTPUT = "/tmp/ci_findings.json"

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".kt", ".kts", ".go", ".rb", ".php", ".cs", ".swift",
    ".env", ".yaml", ".yml", ".toml",
    ".xml", ".config", ".cfg", ".ini",
    ".sh", ".bash", ".sql",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "dist",
    "build", ".next", "vendor", "target", "bin", "obj",
    ".security-tools",
}

MAX_FILES = 40
MAX_FILE_CHARS = 3000
MAX_PROMPT_CHARS = 150_000

SYSTEM_PROMPT = """\
You are a senior application security engineer performing a diff-aware security review.
You are given the changed files from a pull request. Your job is to find exploitable
security vulnerabilities introduced or exposed by these changes.

Focus on:
- Injection flaws (SQL, OS command, LDAP, XPath)
- Authentication and authorization bypasses
- Hardcoded secrets, credentials, or tokens
- Insecure cryptography (weak algorithms, bad key management)
- Sensitive data exposure (PII, tokens in logs or responses)
- Insecure deserialization
- Path traversal and file system access issues
- SSRF and open redirect vulnerabilities
- Business logic flaws with security impact

Return ONLY a valid JSON object — no markdown fences, no prose:
{
  "findings": [
    {
      "vulnerability": "Short descriptive name",
      "cwe": "CWE-XXX",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "owasp": "AXX:2021",
      "file": "relative/path/to/file",
      "line": 42,
      "description": "What is vulnerable, how it can be exploited, and the recommended fix",
      "category": "Injection|Auth|Crypto|Secrets|Exposure|..."
    }
  ]
}

Report only findings with confidence >= 8/10. Skip theoretical or low-impact issues.
"""

# ─── File gathering ───────────────────────────────────────────────────────────


def read_changed_files() -> list[str]:
    path = Path(CHANGED_FILES_PATH)
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def gather_file_contents(changed_files: list[str]) -> str:
    chunks: list[str] = []
    total_chars = 0
    count = 0

    for fpath_str in changed_files:
        if count >= MAX_FILES:
            break
        fpath = Path(fpath_str)
        if not fpath.exists() or not fpath.is_file():
            continue
        if fpath.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        if any(part in SKIP_DIRS for part in fpath.parts):
            continue
        try:
            text = fpath.read_text(errors="ignore")
            chunk = f"### File: {fpath_str}\n```\n{text[:MAX_FILE_CHARS]}\n```"
            if total_chars + len(chunk) > MAX_PROMPT_CHARS:
                break
            chunks.append(chunk)
            total_chars += len(chunk)
            count += 1
        except OSError:
            pass

    print(f"    Gathered {count} file(s) ({total_chars:,} chars) for analysis")
    return "\n\n".join(chunks)


# ─── Claude call ─────────────────────────────────────────────────────────────


def call_claude(api_key: str, code_context: str) -> dict:
    client = anthropic.Anthropic(api_key=api_key)
    user_msg = (
        "Review these changed files from a pull request for security vulnerabilities:\n\n"
        + code_context
    )
    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )
    raw = response.content[0].text

    cleaned = re.sub(r"^```(?:json)?\s*\n?", "", raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\n?```\s*$", "", cleaned.strip(), flags=re.MULTILINE)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        s, e = cleaned.find("{"), cleaned.rfind("}")
        if s != -1 and e > s:
            try:
                parsed = json.loads(cleaned[s : e + 1])
            except json.JSONDecodeError:
                parsed = {}
        else:
            parsed = {}

    return parsed if isinstance(parsed, dict) else {"findings": []}


# ─── PR comment ──────────────────────────────────────────────────────────────


def post_pr_comment(
    findings: list[dict],
    pr_number: str,
    repo: str,
    token: str,
) -> None:
    if not (pr_number and repo and token):
        print("    Skipping PR comment: PR_NUMBER, REPO, or GITHUB_TOKEN not set")
        return

    blocking = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    advisory = [f for f in findings if f.get("severity") in ("MEDIUM", "LOW")]

    if not findings:
        body = "## L4 · Claude Security Review\n\n✅ No security findings in changed files."
    else:
        lines = ["## L4 · Claude Security Review\n"]

        if blocking:
            lines.append(f"### 🚨 Blocking Findings — {len(blocking)} issue(s)\n")
            for f in blocking:
                lines.append(
                    f"**[{f.get('severity')}] {f.get('vulnerability')}**  \n"
                    f"- File: `{f.get('file')}` line {f.get('line')}  \n"
                    f"- {f.get('cwe', 'N/A')} · {f.get('owasp', 'N/A')}  \n"
                    f"- {f.get('description')}\n"
                )

        if advisory:
            lines.append(f"### ⚠️ Advisory Findings — {len(advisory)} issue(s)\n")
            for f in advisory:
                lines.append(
                    f"**[{f.get('severity')}] {f.get('vulnerability')}**  \n"
                    f"- File: `{f.get('file')}` line {f.get('line')}  \n"
                    f"- {f.get('description')}\n"
                )

        verdict = (
            "\n> ❌ **PR blocked** — CRITICAL/HIGH findings must be remediated before merge."
            if blocking
            else "\n> ✅ No blocking issues found."
        )
        lines.append(verdict)
        body = "\n".join(lines)

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode()
    req = Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github.v3+json",
        },
    )
    try:
        urlopen(req, timeout=30)
        print(f"    Posted findings comment to PR #{pr_number}")
    except URLError as exc:
        print(f"    Warning: failed to post PR comment: {exc}")


# ─── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    api_key = os.environ.get("CLAUDE_API_KEY")
    if not api_key:
        print("Error: CLAUDE_API_KEY not set")
        sys.exit(1)

    changed_files = read_changed_files()
    if not changed_files:
        print("No changed files found — skipping L4 analysis")
        Path(FINDINGS_OUTPUT).write_text(json.dumps({"findings": [], "skipped": True}))
        sys.exit(0)

    print(f"\n{'=' * 60}")
    print(f"L4 Claude Security Analysis — {len(changed_files)} changed file(s)")
    print(f"Model: {MODEL}")
    print(f"{'=' * 60}\n")

    code_context = gather_file_contents(changed_files)
    if not code_context:
        print("No scannable content in changed files — skipping")
        Path(FINDINGS_OUTPUT).write_text(json.dumps({"findings": [], "skipped": True}))
        sys.exit(0)

    print("    Calling Claude API...")
    result = call_claude(api_key, code_context)
    findings = result.get("findings", [])

    print(f"    {len(findings)} finding(s):")
    for f in findings:
        print(f"      [{f.get('severity', '?'):8}] {f.get('vulnerability', '?')} — {f.get('file', '?')}")

    Path(FINDINGS_OUTPUT).write_text(
        json.dumps(
            {"findings": findings, "changed_files": changed_files, "model": MODEL},
            indent=2,
        )
    )
    print(f"\n    Saved findings → {FINDINGS_OUTPUT}")

    post_pr_comment(
        findings,
        pr_number=os.environ.get("PR_NUMBER", ""),
        repo=os.environ.get("REPO", ""),
        token=os.environ.get("GITHUB_TOKEN", ""),
    )

    blocking = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    if blocking:
        print(f"\n❌ Blocking PR: {len(blocking)} CRITICAL/HIGH finding(s)")
        sys.exit(1)

    print("\n✅ L4 check passed — no blocking findings")


if __name__ == "__main__":
    main()
