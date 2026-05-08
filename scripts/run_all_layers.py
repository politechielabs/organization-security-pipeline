#!/usr/bin/env python3
"""
Claude-Only Security Pipeline
==============================
Step 1 — Claude L4  : AI semantic security review via Anthropic API
Step 2 — Rule Gen   : Generate Semgrep rules from Claude-detected vulnerabilities

For each target repo, this script:
  1. Gathers source files and sends them to Claude for a full security review
  2. Saves raw findings to results/raw/claude_code/{target}.json
  3. Generates Semgrep YAML rules for every vulnerability Claude found
  4. Appends new (deduplicated) rules to scripts/config/semgrep-custom-rules.yml

Usage:
    python3 run_all_layers.py [target1 target2 ...]
    python3 run_all_layers.py                       # runs all configured targets

Environment (.env at repo root):
    CLAUDE_API_KEY  — Anthropic API key (required)
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import anthropic
import yaml
from dotenv import load_dotenv

# ─── Paths ────────────────────────────────────────────────────────────────────

# security_rep/scripts/run_all_layers.py  →  security_rep/ is ROOT
ROOT        = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent

# Targets live two levels up at the workspace root
WORKSPACE_ROOT = ROOT.parent
TARGETS_DIR    = WORKSPACE_ROOT / "targets"

RAW_DIR    = ROOT / "results" / "raw"
OUT_DIR    = ROOT / "results"

SKILL_DIR  = Path.home() / ".claude" / "skills" / "security-review"

CUSTOM_RULES_PATH = SCRIPTS_DIR / "config" / "semgrep-custom-rules.yml"

# ─── Config ───────────────────────────────────────────────────────────────────

TARGETS = ["InsecureShop", "juice-shop", "NodeGoat", "inc-photo-app"]

MODEL      = "claude-sonnet-4-6"
MAX_TOKENS = 8192

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
}

MAX_FILES        = 60
MAX_FILE_CHARS   = 4000
MAX_PROMPT_CHARS = 180_000

RULE_MODEL      = "claude-sonnet-4-6"
RULE_MAX_TOKENS = 16000
RULE_BATCH_SIZE = 3

# ─── Semgrep rule generation constants ───────────────────────────────────────

sys.path.insert(0, str(SCRIPTS_DIR))
from prompts.constants import SEMGREP_RULE_SYSTEM  # noqa: E402

# ─── JSON output schema for Claude security review ───────────────────────────

JSON_OUTPUT_INSTRUCTION = """
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

For "languages": list every programming language present in the codebase.
Only report findings with confidence >= 8/10. Focus on HIGH-CONFIDENCE, EXPLOITABLE vulnerabilities only.
"""


# ─── System prompt ────────────────────────────────────────────────────────────

def _load_system_prompt() -> str:
    parts = ["You are a senior security engineer performing a full codebase security review.\n"]
    if SKILL_DIR.exists():
        for md_file in sorted(SKILL_DIR.glob("*.md")):
            parts.append(md_file.read_text(errors="ignore"))
    parts.append(JSON_OUTPUT_INSTRUCTION)
    return "\n\n".join(parts)


SYSTEM_PROMPT = _load_system_prompt()


# ─── File gathering ───────────────────────────────────────────────────────────

def gather_files(target_path: Path) -> str:
    chunks: list[str] = []
    total_chars = 0
    count = 0

    for dirpath, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in sorted(files):
            if count >= MAX_FILES:
                break
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            try:
                text = fpath.read_text(errors="ignore")
                rel   = fpath.relative_to(target_path)
                chunk = f"### File: {rel}\n```\n{text[:MAX_FILE_CHARS]}\n```"
                if total_chars + len(chunk) > MAX_PROMPT_CHARS:
                    break
                chunks.append(chunk)
                total_chars += len(chunk)
                count += 1
            except OSError:
                pass

    print(f"    [gather] {count} files, {total_chars:,} chars")
    return "\n\n".join(chunks)


# ─── JSON extraction ─────────────────────────────────────────────────────────

def _extract_json(raw: str) -> dict:
    cleaned = re.sub(r"^```(?:json)?\s*\n?", "", raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\n?```\s*$", "", cleaned.strip(), flags=re.MULTILINE)

    try:
        outer = json.loads(cleaned)
        if isinstance(outer, dict) and "result" in outer:
            cleaned = outer["result"]
    except (json.JSONDecodeError, TypeError):
        pass

    parsed = None
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        s, e = cleaned.find("{"), cleaned.rfind("}")
        if s != -1 and e > s:
            try:
                parsed = json.loads(cleaned[s : e + 1])
            except json.JSONDecodeError:
                pass

    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        return {"findings": parsed, "languages": []}
    return {"findings": [], "languages": []}


# ─── L4: Claude analysis ─────────────────────────────────────────────────────

def run_claude_analysis(client: anthropic.Anthropic, target: str) -> list[dict]:
    """Run Claude security review on a target; save JSON; return findings list."""
    target_path = TARGETS_DIR / target
    if not target_path.exists():
        print(f"  [L4] Skipping {target} — not found at {target_path}")
        return []

    out_dir = RAW_DIR / "claude_code"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{target}.json"

    print(f"\n{'─'*60}")
    print(f"  [L4] Claude analysis: {target}")
    print(f"{'─'*60}")

    code_context = gather_files(target_path)
    if not code_context:
        print(f"  [L4] No scannable files in {target_path}")
        return []

    print(f"    [*] Sending to {MODEL} ...")
    t0 = time.monotonic()
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Perform a comprehensive security review of the '{target}' codebase.\n\n"
                        f"Files to review:\n\n{code_context}"
                    ),
                }
            ],
        )
        raw = response.content[0].text
    except anthropic.APIError as exc:
        print(f"  [L4] API error: {exc}")
        return []

    elapsed = time.monotonic() - t0
    parsed    = _extract_json(raw)
    findings  = parsed.get("findings", [])
    langs_raw = parsed.get("languages", [])
    languages = (
        ",".join(str(l).lower() for l in langs_raw)
        if isinstance(langs_raw, list)
        else str(langs_raw).lower()
    )

    result = {
        "target":         target,
        "languages":      languages,
        "findings_count": len(findings),
        "findings":       findings,
        "analyzer":       f"anthropic-api-{MODEL}",
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    }
    out_file.write_text(json.dumps(result, indent=2))

    if not findings:
        raw_path = out_file.with_suffix(".raw.txt")
        raw_path.write_text(raw)
        print(f"    [!] No findings parsed — raw saved to {raw_path.name}")
    else:
        print(f"    [+] {len(findings)} findings → {out_file.name}  ({elapsed:.1f}s)")

    return findings


# ─── Semgrep rule generation ─────────────────────────────────────────────────

def _detect_language(filepath: str) -> str:
    _EXT_LANG = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript",
        ".java": "java", ".kt": "kotlin", ".go": "go",
        ".rb": "ruby", ".php": "php", ".cs": "csharp",
        ".swift": "swift", ".sh": "bash",
    }
    return _EXT_LANG.get(Path(filepath).suffix.lower(), "generic")


def _format_finding_for_rule(finding: dict) -> dict:
    lang = _detect_language(finding.get("file", ""))
    return {
        "category":     finding.get("category", "Security"),
        "sub_category": finding.get("vulnerability", "Unknown"),
        "vulnerability": finding.get("vulnerability", "Unknown"),
        "cwe":          finding.get("cwe", ""),
        "language":     lang,
    }


def _call_claude_for_rules(client: anthropic.Anthropic, vuln_list_str: str) -> str:
    msg = client.messages.create(
        model=RULE_MODEL,
        max_tokens=RULE_MAX_TOKENS,
        thinking={"type": "enabled", "budget_tokens": 10000},
        temperature=1,
        messages=[
            {
                "role": "user",
                "content": SEMGREP_RULE_SYSTEM.replace("{vuln_list}", vuln_list_str),
            }
        ],
    )
    text = next(b.text for b in msg.content if b.type == "text").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(l for l in lines if not l.strip().startswith("```")).strip()
    return text


def _sanitize_yaml_patterns(text: str) -> str:
    pattern_re = re.compile(
        r'^( *)- (pattern(?:-not|-regex|-inside|-either)?): (.+)$',
        re.MULTILINE,
    )

    def fix_match(m: re.Match) -> str:
        leading = m.group(1)
        key     = m.group(2)
        value   = m.group(3).strip()

        if value in ("|", "|-", "|+", ">", ">-"):
            return m.group(0)

        if (value.startswith("'") and value.endswith("'")) or \
           (value.startswith('"') and value.endswith('"')):
            inner = value[1:-1]
            if any(c in inner for c in ["'", "{", "[", "#"]) or ": " in inner:
                value = inner
            else:
                return m.group(0)

        needs_block = any(c in value for c in ["'", "{", "[", "#"]) or ": " in value
        if not needs_block:
            return m.group(0)

        content_indent = leading + "    "
        return f"{leading}- {key}: |-\n{content_indent}{value}"

    return pattern_re.sub(fix_match, text)


def _merge_yaml_blocks(blocks: list[str]) -> str:
    rule_entries: list[str] = []
    for block in blocks:
        lines = block.splitlines()
        in_rules = False
        current: list[str] = []
        for line in lines:
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

    body = "\n\n".join(rule_entries)
    return f"rules:\n{body}\n"


def _load_existing_cwes() -> set[str]:
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


def generate_rules_for_findings(
    client: anthropic.Anthropic,
    all_findings: list[dict],
    target_name: str,
) -> int:
    """Generate Semgrep rules for Claude-detected findings. Returns number of new rules added."""
    if not all_findings:
        print(f"  [RuleGen] No findings for {target_name} — skipping")
        return 0

    existing_cwes = _load_existing_cwes()

    # Deduplicate by CWE+language, skip already-covered CWEs
    seen_keys: set[tuple] = set()
    novel: list[dict] = []
    for f in all_findings:
        formatted = _format_finding_for_rule(f)
        cwe_ids = {
            c.strip().upper()
            for c in re.split(r"[|,\s]+", formatted.get("cwe", ""))
            if c.strip()
        }
        key = (formatted["vulnerability"], formatted["language"])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        if cwe_ids and cwe_ids.issubset(existing_cwes):
            continue
        novel.append(formatted)

    if not novel:
        print(f"  [RuleGen] All CWEs already covered — no new rules needed for {target_name}")
        return 0

    print(f"  [RuleGen] Generating rules for {len(novel)} novel finding(s) from {target_name}:")
    for nf in novel:
        print(f"    [{nf.get('cwe','?'):>12}] {nf['language']:<12} {nf['sub_category']}")

    batches = [novel[i : i + RULE_BATCH_SIZE] for i in range(0, len(novel), RULE_BATCH_SIZE)]
    all_blocks: list[str] = []

    for idx, batch in enumerate(batches, 1):
        print(f"    Batch {idx}/{len(batches)} ({len(batch)} vulns) → {RULE_MODEL} ...")
        yaml_text = _call_claude_for_rules(client, json.dumps(batch, indent=2))
        all_blocks.append(yaml_text)
        print(f"      received {len(yaml_text)} chars")

    final_yaml = _sanitize_yaml_patterns(_merge_yaml_blocks(all_blocks))

    try:
        parsed_rules = yaml.safe_load(final_yaml)
        rule_count = len(parsed_rules.get("rules", []))
        print(f"  [RuleGen] YAML valid — {rule_count} rule(s) generated")
    except yaml.YAMLError as exc:
        print(f"  [RuleGen] WARNING: YAML invalid after sanitize: {exc}")
        print("  [RuleGen] Writing anyway — manual review needed.")
        rule_count = 0

    CUSTOM_RULES_PATH.parent.mkdir(parents=True, exist_ok=True)

    if CUSTOM_RULES_PATH.exists() and CUSTOM_RULES_PATH.stat().st_size > 0:
        existing = yaml.safe_load(CUSTOM_RULES_PATH.read_text()) or {}
        existing_ids = {r["id"] for r in existing.get("rules", []) if "id" in r}
        new_parsed   = yaml.safe_load(final_yaml) or {}
        new_rules    = [r for r in new_parsed.get("rules", []) if r.get("id") not in existing_ids]
        skipped = len(new_parsed.get("rules", [])) - len(new_rules)
        if skipped:
            print(f"  [RuleGen] Skipped {skipped} duplicate rule(s).")
        if new_rules:
            existing.setdefault("rules", []).extend(new_rules)
            CUSTOM_RULES_PATH.write_text(yaml.dump(existing, default_flow_style=False, sort_keys=False))
            print(f"  [RuleGen] Appended {len(new_rules)} new rule(s) → {CUSTOM_RULES_PATH}")
            return len(new_rules)
        else:
            print(f"  [RuleGen] No new rules to add (all duplicate).")
            return 0
    else:
        CUSTOM_RULES_PATH.write_text(final_yaml)
        count = rule_count
        print(f"  [RuleGen] Created {CUSTOM_RULES_PATH} with {count} rule(s)")
        return count


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    load_dotenv(WORKSPACE_ROOT / ".env")

    api_key = os.environ.get("CLAUDE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[!] CLAUDE_API_KEY not found in .env or environment")
        sys.exit(1)

    # Allow passing specific targets on the command line
    targets = sys.argv[1:] if len(sys.argv) > 1 else TARGETS

    client = anthropic.Anthropic(api_key=api_key)

    t_start   = time.monotonic()
    start_ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("=" * 60)
    print("  Claude-Only Security Pipeline")
    print("  Step 1: L4 Claude analysis")
    print("  Step 2: Semgrep rule generation from Claude findings")
    print(f"  Model:  {MODEL}")
    print(f"  Started: {start_ts}")
    print("=" * 60)

    summary: list[dict] = []

    for target in targets:
        if not (TARGETS_DIR / target).exists():
            print(f"\n[!] Skipping {target} — not found at {TARGETS_DIR / target}")
            continue

        findings = run_claude_analysis(client, target)

        new_rules = generate_rules_for_findings(client, findings, target)

        summary.append({
            "target":     target,
            "findings":   len(findings),
            "new_rules":  new_rules,
        })

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed = time.monotonic() - t_start
    mins, secs = divmod(int(elapsed), 60)
    end_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*60}")
    print("  Pipeline Summary")
    print(f"{'='*60}")
    print(f"  {'Target':<20} {'Findings':>10} {'New Rules':>10}")
    print(f"  {'─'*20} {'─'*10} {'─'*10}")
    for row in summary:
        print(f"  {row['target']:<20} {row['findings']:>10} {row['new_rules']:>10}")
    total_findings  = sum(r["findings"]  for r in summary)
    total_new_rules = sum(r["new_rules"] for r in summary)
    print(f"  {'─'*20} {'─'*10} {'─'*10}")
    print(f"  {'TOTAL':<20} {total_findings:>10} {total_new_rules:>10}")
    print(f"\n  Rules file: {CUSTOM_RULES_PATH}")
    print(f"  Started:    {start_ts}")
    print(f"  Finished:   {end_ts}")
    print(f"  Duration:   {mins}m {secs}s ({elapsed:.1f}s total)\n")


if __name__ == "__main__":
    main()
