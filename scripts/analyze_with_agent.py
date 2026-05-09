#!/usr/bin/env python3
"""
Security analysis using Anthropic API directly 
Replicates /security-review behavior against source files.

Usage:
    python3 analyze_with_agent.py <target_path>
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

# ===========================
# CONFIG
# ===========================

if len(sys.argv) < 2:
    print("Usage: python3 analyze_with_agent.py <target_path>")
    sys.exit(1)

TARGET      = sys.argv[1]
TARGET_NAME = Path(TARGET).name
OUTPUT_DIR  = Path(__file__).parent.parent / "results" / "raw" / "claude_code"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
CLAUDE_OUTPUT = OUTPUT_DIR / f"{TARGET_NAME}.json"

MODEL = "claude-sonnet-4-5"   # or claude-opus-4-5 for deeper analysis

SKILL_DIR = Path.home() / ".claude" / "skills" / "security-review"

# File types to scan
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

MAX_FILES      = 60
MAX_FILE_CHARS = 4000   # chars per file before truncation
MAX_PROMPT_CHARS = 180_000  # stay well within 200k context window


# ===========================
# FILE GATHERING
# ===========================

def gather_files(target_path: str) -> str:
    """Walk target dir, collect source files, format for prompt."""
    root = Path(target_path)
    chunks = []
    total_chars = 0
    count = 0

    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in sorted(files):
            if count >= MAX_FILES:
                break
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            try:
                text = fpath.read_text(errors="ignore")
                rel   = fpath.relative_to(root)
                chunk = f"### File: {rel}\n```\n{text[:MAX_FILE_CHARS]}\n```"
                if total_chars + len(chunk) > MAX_PROMPT_CHARS:
                    break
                chunks.append(chunk)
                total_chars += len(chunk)
                count += 1
            except OSError:
                pass

    print(f"    [*] Gathered {count} files ({total_chars:,} chars) for review")
    return "\n\n".join(chunks)


# ===========================
# PROMPT
# ===========================

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

For "languages": list every programming language present in the codebase (e.g. ["javascript", "python", "java"]).
Only report findings with confidence >= 8/10. Focus on HIGH-CONFIDENCE, EXPLOITABLE vulnerabilities only.
"""


def load_system_prompt() -> str:
    """Build system prompt from skill files in SKILL_DIR."""
    if not SKILL_DIR.exists():
        raise FileNotFoundError(f"Skill directory not found: {SKILL_DIR}")
    parts = ["You are a senior security engineer performing a full codebase security review.\n"]
    for md_file in sorted(SKILL_DIR.glob("*.md")):
        parts.append(md_file.read_text(errors="ignore"))
    parts.append(JSON_OUTPUT_INSTRUCTION)
    return "\n\n".join(parts)


SYSTEM_PROMPT = load_system_prompt()


def build_user_prompt(target_name: str, code_context: str) -> str:
    return (
        f"Perform a comprehensive security review of the '{target_name}' codebase.\n\n"
        f"Files to review:\n\n{code_context}"
    )


# ===========================
# JSON EXTRACTION
# ===========================

def extract_output(raw: str) -> dict:
    """Parse Claude response; return dict with 'findings' and 'languages'."""
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
                parsed = json.loads(cleaned[s:e+1])
            except json.JSONDecodeError:
                pass

    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        return {"findings": parsed, "languages": []}
    return {"findings": [], "languages": []}


# ===========================
# MAIN
# ===========================

def main():
    api_key = os.environ.get("CLAUDE_API_KEY")
    if not api_key:
        print("[!] CLAUDE_API_KEY not found in .env or environment")
        sys.exit(1)

    target_path = os.path.abspath(TARGET)
    if not os.path.isdir(target_path):
        print(f"[!] Target not found: {target_path}")
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"[*] Security Review (Anthropic API): {TARGET_NAME}")
    print(f"    Model : {MODEL}")
    print(f"{'='*70}")

    code_context = gather_files(target_path)
    if not code_context:
        print("[!] No scannable files found")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    print(f"    [*] Sending to Claude API...")
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=8192,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_user_prompt(TARGET_NAME, code_context)}],
        )
        raw = response.content[0].text
    except anthropic.APIError as exc:
        print(f"[!] API error: {exc}")
        sys.exit(1)

    parsed    = extract_output(raw)
    findings  = parsed.get("findings", [])
    langs_raw = parsed.get("languages", [])
    languages = ",".join(str(l).lower() for l in langs_raw) if isinstance(langs_raw, list) else str(langs_raw).lower()

    output = {
        "target":         TARGET_NAME,
        "languages":      languages,
        "findings_count": len(findings),
        "findings":       findings,
        "analyzer":       f"anthropic-api-{MODEL}",
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    }
    CLAUDE_OUTPUT.write_text(json.dumps(output, indent=2))

    if not findings:
        raw_path = CLAUDE_OUTPUT.with_suffix(".raw.txt")
        raw_path.write_text(raw)
        print(f"    [!] No findings parsed — raw saved to: {raw_path}")


    print(f"\\n[+] Done: {len(findings)} findings → {CLAUDE_OUTPUT}")


if __name__ == "__main__":
    main()
