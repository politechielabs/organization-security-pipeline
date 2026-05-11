#!/usr/bin/env python3
"""
4-Layer Security Pipeline (Local Runner)
=========================================
Sequential layers with hard gates:

  L1 · Gitleaks  — any secret/credential leak          → BLOCK
  L2 · Trivy     — CRITICAL or HIGH CVE / misconfig    → BLOCK
  L3 · Semgrep   — ERROR-severity SAST finding         → BLOCK
  L4 · Claude    — always runs; CRITICAL/HIGH findings →
                     generate Semgrep rules + raise PR + comment on PR

Usage:
    python3 run_all_layers.py <target_path>
    python3 run_all_layers.py          # defaults to current working directory

Environment (.env at repo root OR exported):
    CLAUDE_API_KEY      — Anthropic API key (required for L4)
    GITHUB_TOKEN        — GitHub token (PR comments + fallback rule PR)
    PR_NUMBER           — PR number to comment on
    GITHUB_REPOSITORY   — org/repo of the scanned repo (PR comment target)
    SEMGREP_RULES_REPO  — org/repo for Semgrep rules PR (optional)
    RULES_REPO_TOKEN    — PAT with write access to SEMGREP_RULES_REPO
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import anthropic
import yaml
from dotenv import load_dotenv

# ─── Paths ────────────────────────────────────────────────────────────────────

ROOT        = Path(__file__).resolve().parent.parent   # security_rep/
SCRIPTS_DIR = Path(__file__).resolve().parent          # security_rep/scripts/

CUSTOM_RULES_DIR   = ROOT / "config" / "semgrep-custom-rules"
GITLEAKS_CONFIG    = ROOT / "config" / "gitleaks.toml"
TRIVY_CONFIG       = ROOT / "config" / "trivy-comprehensive.yaml"
SEMGREP_CONFIG_DIR = ROOT / "config"
SKILL_DIR          = Path.home() / ".claude" / "skills" / "security-review"
GENERATED_RULES_OUTPUT = Path("/tmp/generated_rules.yml")

sys.path.insert(0, str(SCRIPTS_DIR))
from prompts.constants import SEMGREP_RULE_SYSTEM  # noqa: E402

# ─── Config ───────────────────────────────────────────────────────────────────

L4_MODEL        = "claude-sonnet-4-6"
L4_MAX_TOKENS   = 8192
RULE_MODEL      = "claude-sonnet-4-6"
RULE_MAX_TOKENS = 16000
RULE_BATCH_SIZE = 3

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".kt", ".kts", ".go", ".rb", ".php", ".cs", ".swift",
    ".env", ".yaml", ".yml", ".toml", ".xml", ".config",
    ".cfg", ".ini", ".sh", ".bash", ".sql",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "dist",
    "build", ".next", "vendor", "target", "bin", "obj",
}

MAX_FILES        = 60
MAX_FILE_CHARS   = 4000
MAX_PROMPT_CHARS = 180_000

L4_JSON_SCHEMA = """
---
OUTPUT INSTRUCTIONS:
Return ONLY a valid JSON object — no markdown fences, no prose:
{
  "target": "<name>",
  "languages": ["javascript", "python"],
  "findings": [
    {
      "vulnerability": "Short vulnerability name",
      "cwe": "CWE-XXX",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "owasp": "AXX:2021",
      "file": "relative/path/to/file",
      "line": 42,
      "description": "Clear explanation: what is vulnerable, how it can be exploited, and recommended fix",
      "category": "Injection|Auth|Crypto|..."
    }
  ]
}
Only report findings with confidence >= 8/10. Focus on HIGH-CONFIDENCE, EXPLOITABLE vulnerabilities only.
"""

# ─── Shared helpers ───────────────────────────────────────────────────────────

def _run(cmd: list[str], label: str, cwd: str | None = None) -> tuple[int, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if r.returncode not in (0, 1):
        print(f"    [!] {label} exited {r.returncode}: {(r.stderr or '')[:200]}")
    return r.returncode, r.stderr or ""


def _is_blocking(severity: str) -> bool:
    return severity.upper() in ("CRITICAL", "HIGH")


def _print_findings(findings: list[dict]) -> None:
    for f in findings:
        sev  = f.get("severity", "?").upper()
        name = f.get("vulnerability") or f.get("type") or "?"
        loc  = f.get("file", "")
        line = f.get("line", "")
        icon = "❌" if _is_blocking(sev) else "⚠️ "
        print(f"    {icon} [{sev:8}] {name}  →  {loc}:{line}")


# ─── PR comment ──────────────────────────────────────────────────────────────

def post_pr_comment(body: str) -> None:
    token     = os.environ.get("GITHUB_TOKEN", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    repo      = os.environ.get("GITHUB_REPOSITORY", "")
    if not (token and pr_number and repo):
        print("    [comment] PR_NUMBER / GITHUB_TOKEN / GITHUB_REPOSITORY not set — skipping")
        return
    url  = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode()
    req  = Request(url, data=data, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/vnd.github.v3+json",
    })
    try:
        urlopen(req, timeout=30)
        print(f"    [comment] ✅ Posted to PR #{pr_number}")
    except URLError as exc:
        print(f"    [comment] Warning: {exc}")


def _layer_comment(title: str, findings: list[dict]) -> str:
    lines = [f"## {title}\n", f"### 🚨 {len(findings)} blocking finding(s)\n"]
    for f in findings:
        lines.append(
            f"**[{f.get('severity')}] {f.get('vulnerability') or f.get('type')}**  \n"
            f"- File: `{f.get('file', '')}` line {f.get('line', '')}  \n"
            f"- {f.get('description', '')[:200]}\n"
        )
    lines.append("\n> ❌ **PR blocked** — fix the above before merging.")
    return "\n".join(lines)


def _l4_comment(findings: list[dict]) -> str:
    blocking = [f for f in findings if _is_blocking(f.get("severity", ""))]
    advisory = [f for f in findings if not _is_blocking(f.get("severity", ""))]
    if not findings:
        return "## L4 · Claude Security Review\n\n✅ No security findings detected."
    lines = ["## L4 · Claude Security Review\n"]
    if blocking:
        lines.append(f"### 🚨 Blocking Findings — {len(blocking)} issue(s)\n")
        for f in blocking:
            lines.append(
                f"**[{f.get('severity')}] {f.get('vulnerability')}**  \n"
                f"- File: `{f.get('file')}` line {f.get('line')}  \n"
                f"- {f.get('cwe', '')} · {f.get('owasp', '')}  \n"
                f"- {f.get('description', '')}\n"
            )
    if advisory:
        lines.append(f"### ⚠️ Advisory — {len(advisory)} issue(s)\n")
        for f in advisory:
            lines.append(
                f"**[{f.get('severity')}] {f.get('vulnerability')}**  \n"
                f"- `{f.get('file')}` line {f.get('line')} — {f.get('description', '')}\n"
            )
    lines.append(
            "\n> ✅ No blocking issues."
        )
    return "\n".join(lines)


def _get_pr_changed_files(token: str, repo: str, pr_number: str) -> set[str]:
    """Return the set of file paths changed in this PR (relative to repo root)."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    req = Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    })
    try:
        resp = urlopen(req, timeout=15)
        files = json.loads(resp.read())
        return {f["filename"] for f in files}
    except Exception as exc:
        print(f"    [review] Warning: could not fetch PR files: {exc}")
        return set()


def post_inline_review(findings: list[dict]) -> None:
    """
    Post an inline GitHub PR review.
    Only findings whose file is in the PR diff get inline comments — the
    GitHub Reviews API rejects inline comments on lines outside the diff.
    Everything else falls back to a top-level summary comment.
    Review is submitted as COMMENT — never REQUEST_CHANGES — so it never blocks the PR.
    """
    token     = os.environ.get("GITHUB_TOKEN", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    repo      = os.environ.get("GITHUB_REPOSITORY", "")
    if not (token and pr_number and repo):
        print("    [review] PR_NUMBER / GITHUB_TOKEN / GITHUB_REPOSITORY not set — skipping")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/vnd.github.v3+json",
    }

    def _api(url: str, payload: dict) -> bool:
        req = Request(url, data=json.dumps(payload).encode(), headers=headers)
        try:
            urlopen(req, timeout=30)
            return True
        except URLError as exc:
            print(f"    [review] Warning: {exc}")
            return False

    # Only inline-comment files actually changed in this PR
    pr_files = _get_pr_changed_files(token, repo, pr_number)

    inline_comments: list[dict] = []
    orphan_findings: list[dict] = []

    for f in findings:
        file_path = f.get("file", "")
        line      = f.get("line")
        sev       = f.get("severity", "?").upper()
        icon      = "🚨" if _is_blocking(sev) else "⚠️"
        body = (
            f"{icon} **[{sev}] {f.get('vulnerability', '?')}**\n\n"
            f"{f.get('description', '')}\n\n"
            f"- CWE: `{f.get('cwe', 'N/A')}`  ·  OWASP: `{f.get('owasp', 'N/A')}`\n"
            f"- Category: `{f.get('category', 'N/A')}`\n\n"
            f"*Generated by L4 · Claude security review. "
            f"New Semgrep rule raised in a separate PR.*"
        )
        in_diff = not pr_files or file_path in pr_files
        if file_path and line and in_diff:
            inline_comments.append({"path": file_path, "line": int(line), "body": body})
        else:
            orphan_findings.append(f)

    # Build review body (always present; shows orphan findings + overall header)
    review_body_lines = ["## L4 · Claude Security Review"]
    if not findings:
        review_body_lines.append("\n✅ No security findings detected.")
    if orphan_findings:
        review_body_lines.append(f"\n### {len(orphan_findings)} finding(s) outside this PR's diff:\n")
        for f in orphan_findings:
            sev  = f.get('severity', '?').upper()
            icon = "🚨" if _is_blocking(sev) else "⚠️"
            review_body_lines.append(
                f"{icon} **[{sev}] {f.get('vulnerability', '?')}** — "
                f"`{f.get('file', 'unknown')}`\n"
                f"{f.get('description', '')}\n"
            )

    review_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    payload: dict = {
        "body":     "\n".join(review_body_lines),
        "event":    "COMMENT",
        "comments": inline_comments,
    }
    ok = _api(review_url, payload)
    if not ok and inline_comments:
        # Inline comments failed (e.g. line not in diff) — retry with summary only
        print("    [review] Inline review failed — retrying as summary comment")
        payload["comments"] = []
        orphan_findings = findings  # show all findings in body
        review_body_lines = ["## L4 · Claude Security Review\n"]
        for f in findings:
            sev  = f.get('severity', '?').upper()
            icon = "🚨" if _is_blocking(sev) else "⚠️"
            review_body_lines.append(
                f"{icon} **[{sev}] {f.get('vulnerability', '?')}** — "
                f"`{f.get('file', 'unknown')}:{f.get('line', '?')}`\n"
                f"{f.get('description', '')}\n"
            )
        payload["body"] = "\n".join(review_body_lines)
        _api(review_url, payload)

    inline_count = len(inline_comments)
    print(f"    [review] Posted inline review on PR #{pr_number} "
          f"({inline_count} inline, {len(orphan_findings)} summary)")

# ─── Layer 1: Gitleaks ────────────────────────────────────────────────────────

def layer1_gitleaks(target_path: Path) -> list[dict]:
    tmp = Path(tempfile.mkdtemp())
    out_fs  = tmp / "gl_fs.json"
    out_git = tmp / "gl_git.json"

    base = ["gitleaks", "detect", "--source", str(target_path),
            "--report-format", "json"]
    if GITLEAKS_CONFIG.exists():
        base += ["--config", str(GITLEAKS_CONFIG)]

    print("  [L1] Gitleaks filesystem scan ...")
    _run(base + ["--report-path", str(out_fs), "--no-git"], "gitleaks-fs")

    if (target_path / ".git").exists():
        print("  [L1] Gitleaks git-history scan ...")
        _run(base + ["--report-path", str(out_git)], "gitleaks-git")

    findings: list[dict] = []
    seen: set[tuple] = set()

    def _parse(path: Path) -> None:
        if not path.exists():
            return
        try:
            leaks = json.loads(path.read_text()) or []
        except (json.JSONDecodeError, OSError):
            return
        for leak in leaks:
            key = (leak.get("File", ""), leak.get("StartLine"), leak.get("RuleID", ""))
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "severity":      "CRITICAL",
                "vulnerability": f"Secret: {leak.get('Description') or leak.get('RuleID', 'Exposed Secret')}",
                "file":          leak.get("File", ""),
                "line":          leak.get("StartLine"),
                "description":   f"[{leak.get('RuleID', '')}] {str(leak.get('Secret', ''))[:80]}",
            })

    _parse(out_fs)
    _parse(out_git)
    print(f"  [L1] → {len(findings)} unique secret(s)")
    return findings


# ─── Layer 2: Trivy ──────────────────────────────────────────────────────────

# Directories that are part of this security tooling repo itself and should
# never be scanned for CVEs — they contain intentionally vulnerable test
# fixtures (Semgrep community rule corpus) and old config history.
_TRIVY_SKIP_DIRS = [
    "config/community",    # Semgrep test fixtures (old vulnerable deps)
    "config/gitlab",       # Semgrep GitLab rules corpus (old vulnerable deps)
    ".git",
    "node_modules",
    "vendor",
    ".venv",
    "__pycache__",
]

def layer2_trivy(target_path: Path) -> list[dict]:
    tmp = Path(tempfile.mkdtemp())
    out = tmp / "trivy.json"
    cmd = ["trivy", "fs", "--format", "json", "-o", str(out)]
    if TRIVY_CONFIG.exists():
        cmd += ["--config", str(TRIVY_CONFIG)]
    else:
        cmd += ["--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                "--scanners", "vuln,misconfig,secret"]
    # Always apply skip-dirs explicitly — config-file skip-dirs can be
    # unreliable depending on Trivy version / working directory.
    for d in _TRIVY_SKIP_DIRS:
        cmd += ["--skip-dirs", d]
    cmd.append(str(target_path))

    print("  [L2] Trivy scan ...")
    _run(cmd, "trivy")

    if not out.exists():
        return []
    try:
        data = json.loads(out.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  [L2] Parse error: {exc}")
        return []

    findings: list[dict] = []
    for result in data.get("Results", []):
        ft = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            sev = v.get("Severity", "UNKNOWN").upper()
            cve = v.get("VulnerabilityID", "")
            findings.append({
                "severity":      sev,
                "vulnerability": f"CVE: {v.get('Title') or cve}",
                "file":          ft,
                "line":          None,
                "description":   f"{cve} pkg:{v.get('PkgName')}@{v.get('InstalledVersion')} fix:{v.get('FixedVersion','-')}",
                "cwe":           ", ".join(v.get("CweIDs") or []),
            })
        for mc in result.get("Misconfigurations") or []:
            findings.append({
                "severity":      mc.get("Severity", "UNKNOWN").upper(),
                "vulnerability": f"Misconfig: {mc.get('Title', mc.get('ID',''))}",
                "file":          ft,
                "line":          None,
                "description":   mc.get("Description", ""),
                "cwe":           "",
            })
        for s in result.get("Secrets") or []:
            findings.append({
                "severity":      s.get("Severity", "HIGH").upper(),
                "vulnerability": f"Secret: {s.get('Title', s.get('RuleID',''))}",
                "file":          ft,
                "line":          s.get("StartLine"),
                "description":   str(s.get("Match", ""))[:80],
                "cwe":           "CWE-798",
            })

    blocking = sum(1 for f in findings if _is_blocking(f["severity"]))
    print(f"  [L2] → {len(findings)} total  ({blocking} CRITICAL/HIGH)")
    return findings


# ─── Layer 3: Semgrep ────────────────────────────────────────────────────────

def layer3_semgrep(target_path: Path) -> list[dict]:
    tmp = Path(tempfile.mkdtemp())
    out = tmp / "semgrep.json"

    cmd = ["semgrep", "scan"]
    for pack in ("community", "gitlab"):
        p = SEMGREP_CONFIG_DIR / pack
        if p.exists():
            cmd += ["--config", str(p)]
    if CUSTOM_RULES_DIR.exists():
        cmd += ["--config", str(CUSTOM_RULES_DIR)]
    if "--config" not in " ".join(cmd):
        cmd += ["--config", "auto"]
    cmd += ["--json", "--json-output", str(out), str(target_path)]

    print("  [L3] Semgrep scan ...")
    _run(cmd, "semgrep")

    if not out.exists():
        return []
    try:
        data = json.loads(out.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  [L3] Parse error: {exc}")
        return []

    _SEV = {"error": "CRITICAL", "warning": "MEDIUM", "info": "LOW"}
    findings: list[dict] = []
    for r in data.get("results", []):
        meta   = r.get("extra", {}).get("metadata", {})
        sg_sev = r.get("extra", {}).get("severity", "info").lower()
        findings.append({
            "severity":      _SEV.get(sg_sev, sg_sev.upper()),
            "vulnerability": ", ".join(meta.get("vulnerability_class") or []) or r.get("check_id", "").split(".")[-1],
            "file":          r.get("path", ""),
            "line":          r.get("start", {}).get("line"),
            "description":   r.get("extra", {}).get("message", "")[:300],
            "cwe":           ", ".join(meta.get("cwe") or []),
            "rule_id":       r.get("check_id", ""),
        })

    blocking = sum(1 for f in findings if _is_blocking(f["severity"]))
    print(f"  [L3] → {len(findings)} total  ({blocking} ERROR-severity blocking)")
    return findings


# ─── Layer 4: Claude ─────────────────────────────────────────────────────────

def _gather_files(target_path: Path) -> str:
    chunks: list[str] = []
    total = count = 0
    for dirpath, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs
                   if d not in SKIP_DIRS and d not in ("community", "gitlab")]
        for fname in sorted(files):
            if count >= MAX_FILES:
                break
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            if str(fpath.relative_to(target_path)).startswith("config"):
                continue
            try:
                text  = fpath.read_text(errors="ignore")
                rel   = fpath.relative_to(target_path)
                chunk = f"### File: {rel}\n```\n{text[:MAX_FILE_CHARS]}\n```"
                if total + len(chunk) > MAX_PROMPT_CHARS:
                    break
                chunks.append(chunk)
                total += len(chunk)
                count += 1
            except OSError:
                pass
    print(f"    [gather] {count} files, {total:,} chars")
    return "\n\n".join(chunks)


def _extract_json(raw: str) -> dict:
    cleaned = re.sub(r"^```(?:json)?\s*\n?", "", raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\n?```\s*$", "", cleaned.strip(), flags=re.MULTILINE)
    try:
        outer = json.loads(cleaned)
        if isinstance(outer, dict) and "result" in outer:
            cleaned = outer["result"]
    except (json.JSONDecodeError, TypeError):
        pass
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        s, e = cleaned.find("{"), cleaned.rfind("}")
        if s != -1 and e > s:
            try:
                parsed = json.loads(cleaned[s : e + 1])
            except json.JSONDecodeError:
                return {"findings": [], "languages": []}
        else:
            return {"findings": [], "languages": []}
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        return {"findings": parsed, "languages": []}
    return {"findings": [], "languages": []}


def layer4_claude(client: anthropic.Anthropic, target_path: Path) -> list[dict]:
    target_name = target_path.name
    out_dir     = ROOT / "results" / "raw" / "claude_code"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{target_name}.json"

    code_context = _gather_files(target_path)
    if not code_context:
        print(f"  [L4] No scannable files")
        return []

    parts = ["You are a senior security engineer performing a full codebase security review.\n"]
    if SKILL_DIR.exists():
        for md in sorted(SKILL_DIR.glob("*.md")):
            parts.append(md.read_text(errors="ignore"))
    parts.append(L4_JSON_SCHEMA)
    system = "\n\n".join(parts)

    print(f"  [L4] Sending to {L4_MODEL} ...")
    t0 = time.monotonic()
    try:
        response = client.messages.create(
            model=L4_MODEL, max_tokens=L4_MAX_TOKENS, system=system,
            messages=[{"role": "user", "content": (
                f"Perform a comprehensive security review of the '{target_name}' codebase.\n\n"
                f"Files to review:\n\n{code_context}"
            )}],
        )
        raw = response.content[0].text
    except anthropic.APIError as exc:
        print(f"  [L4] API error: {exc}")
        return []

    elapsed  = time.monotonic() - t0
    parsed   = _extract_json(raw)
    findings = parsed.get("findings", [])

    out_file.write_text(json.dumps({
        "target": target_name, "languages": parsed.get("languages", []),
        "findings_count": len(findings), "findings": findings,
        "analyzer": f"anthropic-api-{L4_MODEL}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, indent=2))

    if not findings:
        raw_path = out_file.with_suffix(".raw.txt")
        raw_path.write_text(raw)
        print(f"  [L4] No findings parsed — raw saved to {raw_path.name}")
    else:
        blocking = sum(1 for f in findings if _is_blocking(f.get("severity", "")))
        print(f"  [L4] → {len(findings)} findings  ({blocking} CRITICAL/HIGH)  [{elapsed:.1f}s]")

    return findings


# ─── Semgrep rule generation ─────────────────────────────────────────────────

_EXT_LANG: dict[str, str] = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
    ".kt": "kotlin", ".go": "go", ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".swift": "swift", ".sh": "bash",
}


def _load_existing_cwes() -> set[str]:
    if not CUSTOM_RULES_DIR.exists():
        return set()
    try:
        cwes: set[str] = set()
        for yml_file in sorted(CUSTOM_RULES_DIR.glob("*.yml")):
            data = yaml.safe_load(yml_file.read_text()) or {}
            for rule in data.get("rules", []):
                for cwe in re.split(r"[|,\s]+", rule.get("metadata", {}).get("cwe", "")):
                    c = cwe.strip().upper()
                    if c:
                        cwes.add(c)
        return cwes
    except Exception:
        return set()


def _sanitize_yaml_patterns(text: str) -> str:
    pat = re.compile(
        r'^( *)- (pattern(?:-not|-regex|-inside|-either)?): (.+)$', re.MULTILINE
    )
    def _fix(m: re.Match) -> str:
        leading, key, value = m.group(1), m.group(2), m.group(3).strip()
        if value in ("|", "|-", "|+", ">", ">-"):
            return m.group(0)
        if (value.startswith("'") and value.endswith("'")) or \
           (value.startswith('"') and value.endswith('"')):
            inner = value[1:-1]
            if any(c in inner for c in ["'", "{", "[", "#"]) or ": " in inner:
                value = inner
            else:
                return m.group(0)
        if not (any(c in value for c in ["'", "{", "[", "#"]) or ": " in value):
            return m.group(0)
        return f"{leading}- {key}: |-\n{leading}    {value}"
    return pat.sub(_fix, text)


def _merge_yaml_blocks(blocks: list[str]) -> str:
    entries: list[str] = []
    for block in blocks:
        in_rules, current = False, []
        for line in block.splitlines():
            if line.strip() == "rules:":
                in_rules = True
                continue
            if in_rules:
                if line.startswith("  - ") and current:
                    entries.append("\n".join(current))
                    current = [line]
                else:
                    current.append(line)
        if current:
            entries.append("\n".join(current))
    return "rules:\n" + "\n\n".join(entries) + "\n"


def generate_semgrep_rules(
    client: anthropic.Anthropic, findings: list[dict]
) -> str | None:
    critical_high = [f for f in findings if _is_blocking(f.get("severity", ""))]
    if not critical_high:
        print("  [RuleGen] No CRITICAL/HIGH findings — skipping")
        return None

    existing_cwes = _load_existing_cwes()
    seen: set[tuple] = set()
    novel: list[dict] = []

    for f in critical_high:
        lang    = _EXT_LANG.get(Path(f.get("file", "")).suffix.lower(), "generic")
        cwe_ids = {
            c.strip().upper()
            for c in re.split(r"[|,\s]+", f.get("cwe", ""))
            if c.strip()
        }
        key = (f.get("vulnerability", ""), lang)
        if key in seen:
            continue
        seen.add(key)
        if cwe_ids and cwe_ids.issubset(existing_cwes):
            continue
        novel.append({
            "category":      f.get("category", "Security"),
            "sub_category":  f.get("vulnerability", ""),
            "vulnerability": f.get("vulnerability", ""),
            "cwe":           f.get("cwe", ""),
            "language":      lang,
        })

    if not novel:
        print("  [RuleGen] All CWEs already covered — nothing new to generate")
        return None

    print(f"  [RuleGen] Generating rules for {len(novel)} novel finding(s):")
    for n in novel:
        print(f"    [{n['cwe']:>15}] {n['language']:<12} {n['sub_category']}")

    batches    = [novel[i : i + RULE_BATCH_SIZE] for i in range(0, len(novel), RULE_BATCH_SIZE)]
    all_blocks: list[str] = []

    for idx, batch in enumerate(batches, 1):
        print(f"    Batch {idx}/{len(batches)} ({len(batch)}) → {RULE_MODEL} ...")
        msg = client.messages.create(
            model=RULE_MODEL, max_tokens=RULE_MAX_TOKENS,
            thinking={"type": "enabled", "budget_tokens": 10000},
            temperature=1,
            messages=[{"role": "user", "content":
                SEMGREP_RULE_SYSTEM.replace("{vuln_list}", json.dumps(batch, indent=2))}],
        )
        text = next(b.text for b in msg.content if b.type == "text").strip()
        if text.startswith("```"):
            text = "\n".join(
                l for l in text.splitlines() if not l.strip().startswith("```")
            ).strip()
        all_blocks.append(text)
        print(f"      {len(text)} chars")

    final_yaml = _sanitize_yaml_patterns(_merge_yaml_blocks(all_blocks))

    try:
        parsed     = yaml.safe_load(final_yaml)
        rule_count = len(parsed.get("rules", []))
        print(f"  [RuleGen] YAML valid — {rule_count} rule(s)")
    except yaml.YAMLError as exc:
        print(f"  [RuleGen] WARNING: invalid YAML ({exc}) — writing anyway")

    # Deduplicate against all existing rule files in the directory
    existing_ids: set[str] = set()
    if CUSTOM_RULES_DIR.exists():
        for yml_file in sorted(CUSTOM_RULES_DIR.glob("*.yml")):
            try:
                data = yaml.safe_load(yml_file.read_text()) or {}
                for r in data.get("rules", []):
                    if "id" in r:
                        existing_ids.add(r["id"])
            except Exception:
                pass
    if existing_ids:
        try:
            new_data = yaml.safe_load(final_yaml) or {}
        except yaml.YAMLError as exc:
            print(f"  [RuleGen] Warning: generated YAML parse error ({exc}); skipping deduplication")
            return final_yaml
        new_rules = [r for r in new_data.get("rules", []) if r.get("id") not in existing_ids]
        skipped   = len(new_data.get("rules", [])) - len(new_rules)
        if skipped:
            print(f"  [RuleGen] Skipped {skipped} duplicate rule(s)")
        if not new_rules:
            print("  [RuleGen] All generated rules are duplicates — nothing to commit")
            return None
        final_yaml = yaml.dump({"rules": new_rules}, default_flow_style=False, allow_unicode=True)

    return final_yaml


# ─── PR creation ─────────────────────────────────────────────────────────────

def _git(args: list[str], cwd: str) -> None:
    subprocess.run(["git"] + args, cwd=cwd, check=True,
                   capture_output=True, text=True)


def create_rules_pr(rules_yaml: str) -> None:
    """
    Push rules to a branch and open a PR.
    Priority:
      1. SEMGREP_RULES_REPO + RULES_REPO_TOKEN  → external rules repo
      2. GITHUB_TOKEN + GITHUB_REPOSITORY        → caller repo at .security/semgrep-rules.yml
      3. Neither                                 → save to /tmp/generated_rules.yml only
    """
    pr_number    = os.environ.get("PR_NUMBER", "local")
    rules_repo   = os.environ.get("SEMGREP_RULES_REPO", "")
    rules_token  = os.environ.get("RULES_REPO_TOKEN", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    caller_repo  = os.environ.get("GITHUB_REPOSITORY", "")

    GENERATED_RULES_OUTPUT.write_text(rules_yaml)
    print(f"  [PR] Rules saved → {GENERATED_RULES_OUTPUT}")

    target_repo = rules_repo or caller_repo
    token       = rules_token or github_token
    timestamp   = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch      = f"security/gap-rules-{timestamp}"
    # Always place generated rules under config/semgrep-custom-rules/
    rules_file = f"config/semgrep-custom-rules/custom_rules_{timestamp}.yml"

    if not target_repo:
        print("  [PR] No SEMGREP_RULES_REPO / GITHUB_REPOSITORY configured — rules saved as artifact only")
        return

    # Prefer HTTPS+token when a token is available; fall back to SSH (gh CLI auth)
    if token:
        clone_url = f"https://x-access-token:{token}@github.com/{target_repo}"
    else:
        clone_url = f"git@github.com:{target_repo}"
        print("  [PR] No token set — using SSH clone (gh CLI auth)")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(
                ["git", "clone", "--depth=1", clone_url, tmpdir],
                check=True, capture_output=True, text=True,
            )
            _git(["config", "user.email", "security-pipeline@github.com"], tmpdir)
            _git(["config", "user.name",  "Security Pipeline"], tmpdir)
            _git(["checkout", "-b", branch], tmpdir)

            out_file = Path(tmpdir) / rules_file
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(
                f"# Auto-generated from run #{pr_number} — {timestamp}\n"
                + rules_yaml + "\n"
            )

            _git(["add", rules_file], tmpdir)
            _git(["commit", "-m",
                  f"chore: gap-fill Semgrep rules (run #{pr_number}) [skip ci]"], tmpdir)
            _git(["push", "origin", branch], tmpdir)

            gh_env = {**os.environ}
            if token:
                gh_env["GH_TOKEN"] = token
            subprocess.run(
                ["gh", "pr", "create",
                 "--repo", target_repo,
                 "--head", branch, "--base", "main",
                 "--title", f"security: gap-fill Semgrep rules (run #{pr_number})",
                 "--body", (
                     f"## New Semgrep Rules\n\n"
                     f"Auto-generated by L4 Claude analysis (run `{pr_number}`).\n\n"
                     f"These rules close SAST detection gaps found by semantic analysis.\n\n"
                     f"**Review carefully before merging.**"
                 )],
                check=True, env=gh_env,
            )
        print(f"  [PR] ✅ Rules PR created in {target_repo}  branch: {branch}")
    except subprocess.CalledProcessError as exc:
        print(f"  [PR] Failed to create PR: {exc}")
        print(f"  [PR] Rules still available at {GENERATED_RULES_OUTPUT}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    for env_path in (ROOT / ".env", ROOT.parent / ".env"):
        if env_path.exists():
            load_dotenv(env_path)
            break

    args = sys.argv[1:]
    force = "--force" in args
    args  = [a for a in args if a != "--force"]

    target_path = Path(args[0]).resolve() if args else Path.cwd()
    if not target_path.is_dir():
        print(f"[!] Target not found: {target_path}")
        sys.exit(1)

    if force:
        print("  ⚠️  --force mode: layer gates disabled (benchmark/test run)")

    api_key = os.environ.get("CLAUDE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[!] CLAUDE_API_KEY not set — L4 and rule generation will be skipped")

    t_start  = time.monotonic()
    start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("=" * 62)
    print(f"  4-Layer Security Pipeline")
    print(f"  Target  : {target_path}")
    print(f"  Started : {start_ts}")
    print("=" * 62)

    # ── L1: Gitleaks ──────────────────────────────────────────────────────────
    print(f"\n{'─'*62}")
    print("  Layer 1 · Gitleaks — Secrets & Credentials")
    print(f"{'─'*62}")
    l1_findings = layer1_gitleaks(target_path)
    l1_blocking = [f for f in l1_findings if _is_blocking(f["severity"])]
    if l1_blocking:
        print(f"\n  ❌ L1 BLOCKED — {len(l1_blocking)} secret(s) found:")
        _print_findings(l1_blocking)
        post_pr_comment(_layer_comment("L1 · Gitleaks — Secrets & Credentials", l1_blocking))
        if not force:
            print(f"\n  Pipeline stopped at L1 after {time.monotonic()-t_start:.1f}s\n")
            sys.exit(1)
        print("  ⚠️  --force: continuing past L1 gate")
    else:
        print("  ✅ L1 passed — no secrets found")

    # ── L2: Trivy ─────────────────────────────────────────────────────────────
    print(f"\n{'─'*62}")
    print("  Layer 2 · Trivy — SCA / CVE / Misconfigs")
    print(f"{'─'*62}")
    l2_findings = layer2_trivy(target_path)
    l2_blocking = [f for f in l2_findings if _is_blocking(f["severity"])]
    if l2_blocking:
        print(f"\n  ❌ L2 BLOCKED — {len(l2_blocking)} CRITICAL/HIGH finding(s):")
        _print_findings(l2_blocking)
        post_pr_comment(_layer_comment("L2 · Trivy — SCA / CVE / Misconfigs", l2_blocking))
        if not force:
            print(f"\n  Pipeline stopped at L2 after {time.monotonic()-t_start:.1f}s\n")
            sys.exit(1)
        print("  ⚠️  --force: continuing past L2 gate")
    else:
        print("  ✅ L2 passed — no CRITICAL/HIGH CVEs or misconfigs")

    # ── L3: Semgrep ───────────────────────────────────────────────────────────
    print(f"\n{'─'*62}")
    print("  Layer 3 · Semgrep — SAST")
    print(f"{'─'*62}")
    l3_findings = layer3_semgrep(target_path)
    l3_blocking = [f for f in l3_findings if _is_blocking(f["severity"])]
    if l3_blocking:
        print(f"\n  ❌ L3 BLOCKED — {len(l3_blocking)} ERROR-severity finding(s):")
        _print_findings(l3_blocking)
        post_pr_comment(_layer_comment("L3 · Semgrep — SAST", l3_blocking))
        if not force:
            print(f"\n  Pipeline stopped at L3 after {time.monotonic()-t_start:.1f}s\n")
            sys.exit(1)
        print("  ⚠️  --force: continuing past L3 gate")
    else:
        print("  ✅ L3 passed — no ERROR-severity SAST findings")

    # ── L4: Claude ────────────────────────────────────────────────────────────
    print(f"\n{'─'*62}")
    print("  Layer 4 · Claude — Semantic Security Review")
    print(f"{'─'*62}")
    if not api_key:
        print("  [L4] Skipped — no CLAUDE_API_KEY")
        sys.exit(0)

    client      = anthropic.Anthropic(api_key=api_key)
    l4_findings = layer4_claude(client, target_path)
    l4_blocking = [f for f in l4_findings if _is_blocking(f.get("severity", ""))]

    # Post inline GitHub review — COMMENT only, never blocks the PR
    post_inline_review(l4_findings)

    if l4_findings:
        print(f"\n  L4 findings:")
        _print_findings(l4_findings)

    # ── Rule generation + PR ──────────────────────────────────────────────────
    if l4_blocking:
        print(f"\n{'─'*62}")
        print("  Generating Semgrep rules for CRITICAL/HIGH findings")
        print(f"{'─'*62}")
        rules_yaml = generate_semgrep_rules(client, l4_findings)
        if rules_yaml:
            create_rules_pr(rules_yaml)
    else:
        print("  [RuleGen] No CRITICAL/HIGH Claude findings — skipping rule generation")

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed    = time.monotonic() - t_start
    mins, secs = divmod(int(elapsed), 60)
    end_ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*62}")
    print("  Pipeline Summary")
    print(f"{'='*62}")
    print(f"  L1 Gitleaks : {len(l1_findings):>3} findings  (0 blocking)")
    print(f"  L2 Trivy    : {len(l2_findings):>3} findings  (0 blocking)")
    print(f"  L3 Semgrep  : {len(l3_findings):>3} findings  (0 blocking)")
    print(f"  L4 Claude   : {len(l4_findings):>3} findings  ({len(l4_blocking)} CRITICAL/HIGH — inline review posted)")
    print(f"\n  Started  : {start_ts}")
    print(f"  Finished : {end_ts}")
    print(f"  Duration : {mins}m {secs}s ({elapsed:.1f}s)\n")

    if l4_blocking:
        print("  ⚠️  CRITICAL/HIGH findings — inline review posted, Semgrep rules raised in separate PR\n")
    else:
        print("  ✅ All layers passed\n")


if __name__ == "__main__":
    main()
