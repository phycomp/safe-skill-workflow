#!/usr/bin/env python3
"""
audit_skill.py — repeatable security audit helper for safe-skill-workflow.

Stdlib-only. Wraps NVIDIA SkillSpector when available, then applies the
workflow's noise-triage rules (project vs vendored/generated trees),
inventories sensitive capabilities, writes a Markdown + JSON report,
and records a sha256 manifest for post-install drift detection.

Usage:
  python3 audit_skill.py <skill-dir> [--name NAME] [--outdir DIR]
  python3 audit_skill.py --verify <manifest.sha256> <skill-dir>
  python3 audit_skill.py <skill-dir> --no-scan

Exit codes: 0 ok, 2 verification drift, 3 skillspector missing (still writes report).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

VENDORED_DIRS = {
    "node_modules", "vendor", ".venv", "venv", "site-packages",
    "third_party", "Pods", "bower_components",
}
GENERATED_DIRS = {
    "dist", "build", ".next", "target", "__pycache__", "out", "coverage", ".cache",
}
LOCKFILES = {
    "package-lock.json", "yarn.lock", "bun.lock", "pnpm-lock.yaml", "uv.lock",
    "poetry.lock", "Cargo.lock", "Gemfile.lock", "composer.lock",
}
TEXT_EXT = {
    ".md", ".txt", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py",
    ".sh", ".bash", ".zsh", ".json", ".yaml", ".yml", ".toml", ".rs", ".go",
    ".rb", ".php", ".html", ".css", ".xml", ".ini", ".cfg", ".conf",
}
MAX_READ = 2_000_000
SKIP_FILE = {"audit_skill.py"}

DANGEROUS_RE = {
    "shell/eval": re.compile(r"\b(eval|exec|Function\(|child_process|spawnSync|spawn\(|execSync|subprocess\.|os\.system|shell=True|Runtime\.evaluate)\b"),
    "download-exec": re.compile(r"(curl[^\n|]*\|\s*(ba)?sh|wget[^\n|]*\|\s*(ba)?sh|iwr[^\n]*\|\s*iex|Invoke-Expression)"),
    "obfuscation": re.compile(r"(atob\(|b64decode|base64\s*--decode|fromCharCode|certutil\s+-decode)"),
    "persistence": re.compile(r"(crontab|\.bashrc|\.zshrc|\.bash_profile|\.profile\b|LaunchAgents|systemd|nohup|autostart|schtasks|Startup\\\\|launchctl)"),
    "credential-path": re.compile(r"(\.ssh/|\.aws/|\.config/gcloud|\.netrc|id_rsa|id_ed25519|\.env\b|credentials|api[_-]?key|token|password|secret|cookies)", re.I),
    "network": re.compile(r"(fetch\(|https?\.request|requests\.(get|post)|axios\.|curl\s|wget\s|WebSocket\()"),
}
INSTALL_RE = re.compile(
    r"(npx\s+-y\s+\S+|npx\s+[^@\s]+|uvx\s+\S+|pip\s+install\s+\S+|npm\s+(?:install|i)\s+-g\s+\S+|"
    r"brew\s+install\s+\S+|releases/download|git\+https://|curl\s+-[^\n]*\|\s*(?:ba)?sh)"
)
URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+)")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def classify(rel: Path) -> str:
    parts = set(rel.parts[:-1])
    if parts & VENDORED_DIRS:
        return "vendored"
    if parts & GENERATED_DIRS:
        return "generated"
    return "project"


def iter_files(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            # skip VCS metadata
            if ".git" in p.relative_to(root).parts:
                continue
            yield p


def read_text(p: Path) -> str | None:
    try:
        if p.stat().st_size > MAX_READ:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_skillspector() -> str | None:
    exe = shutil.which("skillspector")
    if exe:
        return exe
    candidate = Path.home() / ".local" / "bin" / "skillspector"
    if candidate.exists():
        return str(candidate)
    return None


def run_scan(target: Path) -> dict:
    exe = find_skillspector()
    if not exe:
        return {"available": False, "reason": "skillspector CLI not found"}
    fd, tmp = tempfile.mkstemp(prefix="skillspector-", suffix=".json")
    os.close(fd)
    try:
        proc = subprocess.run(
            [exe, "scan", str(target), "--no-llm", "--format", "json", "--output", tmp],
            capture_output=True, text=True, timeout=1800,
        )
        try:
            report = json.loads(Path(tmp).read_text(encoding="utf-8"))
        except Exception:
            report = None
        return {
            "available": True,
            "exit_code": proc.returncode,
            "stderr_tail": (proc.stderr or "")[-600:],
            "report": report,
        }
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def summarize_report(report: dict | None) -> dict:
    if not report:
        return {"available": False}
    ra = report.get("risk_assessment", {}) or {}
    issues = report.get("issues", []) or []
    by_sev: dict[str, int] = {}
    by_rule: dict[str, dict] = {}
    vendored = generated = 0
    project = []
    for it in issues:
        sev = it.get("severity") or "UNKNOWN"
        by_sev[sev] = by_sev.get(sev, 0) + 1
        rid = it.get("id") or "?"
        rec = by_rule.setdefault(rid, {"severity": sev, "count": 0, "sample": None})
        rec["count"] += 1
        loc = (it.get("location") or {}).get("file") or ""
        rel = Path(loc)
        cls = classify(rel) if loc else "project"
        if cls == "vendored":
            vendored += 1
        elif cls == "generated":
            generated += 1
        else:
            project.append(it)
            if rec["sample"] is None:
                rec["sample"] = {
                    "file": loc,
                    "line": (it.get("location") or {}).get("start_line"),
                    "finding": str(it.get("finding"))[:160],
                    "explanation": str(it.get("explanation"))[:200],
                }
    proj_sev: dict[str, int] = {}
    for it in project:
        sev = it.get("severity") or "UNKNOWN"
        proj_sev[sev] = proj_sev.get(sev, 0) + 1
    return {
        "available": True,
        "score": ra.get("score"),
        "severity": ra.get("severity"),
        "recommendation": ra.get("recommendation"),
        "total_issues": len(issues),
        "by_severity": by_sev,
        "by_rule": by_rule,
        "vendored_findings": vendored,
        "generated_findings": generated,
        "project_findings": len(project),
        "project_by_severity": proj_sev,
        "project_examples": project[:40],
    }


def inventory(project_files: list[Path], root: Path) -> dict:
    hosts: dict[str, int] = {}
    dangerous: dict[str, list] = {k: [] for k in DANGEROUS_RE}
    installs: list = []
    lockfiles: list = []
    executables: list = []
    for p in project_files:
        rel = p.relative_to(root)
        if os.access(p, os.X_OK) or p.suffix in {".sh", ".bash", ".command"}:
            executables.append(str(rel))
        if p.name in LOCKFILES:
            lockfiles.append(str(rel))
            continue
        text = read_text(p)
        if text is None:
            continue
        for m in URL_RE.finditer(text):
            host = m.group(1).lower()
            if host not in LOCAL_HOSTS:
                hosts[host] = hosts.get(host, 0) + 1
        for name, rx in DANGEROUS_RE.items():
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                dangerous[name].append({"file": str(rel), "line": line, "match": m.group(0)[:80]})
        for m in INSTALL_RE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            installs.append({"file": str(rel), "line": line, "match": m.group(0)[:120]})
    # dedupe samples
    for k in dangerous:
        seen = set()
        uniq = []
        for d in dangerous[k]:
            key = (d["file"], d["line"], d["match"])
            if key in seen:
                continue
            seen.add(key)
            uniq.append(d)
        dangerous[k] = uniq[:25]
    return {
        "hosts": dict(sorted(hosts.items(), key=lambda t: -t[1])[:30]),
        "dangerous": dangerous,
        "installs": installs[:40],
        "lockfiles": lockfiles,
        "executables": executables[:60],
    }


def static_posture(proj_sev: dict[str, int]) -> str:
    if proj_sev.get("CRITICAL"):
        return "REVIEW (project CRITICAL present — verify each against source)"
    if proj_sev.get("HIGH"):
        return "CAUTION (project HIGH present — verify each against source)"
    if proj_sev.get("MEDIUM"):
        return "CAUTION (project MEDIUM present — verify each against source)"
    return "APPROVE-LEANING (no project HIGH/CRITICAL; still do semantic review)"


def render_md(name: str, target: Path, files: dict, scan: dict, summary: dict, inv: dict, manifest: str) -> str:
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    lines = []
    lines.append(f"# Skill Security Audit — `{name}`\n")
    lines.append(f"- **Target:** `{target}`")
    lines.append(f"- **Generated:** {now}")
    lines.append(f"- **Files:** project={files['project']} · vendored={files['vendored']} · generated={files['generated']}")
    lines.append(f"- **Manifest:** `{manifest}`\n")

    lines.append("## Verdict (agent must fill after semantic review)\n")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append("| Verdict | `APPROVE` / `CAUTION` / `REJECT` |")
    lines.append("| Risk level | Low / Medium / High / Critical |")
    lines.append(f"| Static posture (hint) | {static_posture(summary.get('project_by_severity', {}) if summary.get('available') else {})} |")
    lines.append("| Reviewed by | <agent> |")
    lines.append("| Notes | <fill> |\n")

    lines.append("## Static scan\n")
    if not scan.get("available"):
        lines.append(f"- **Not available:** {scan.get('reason','')}")
    else:
        lines.append(f"- SkillSpector exit={scan.get('exit_code')}")
        if not summary.get("available"):
            lines.append("- Report unreadable/partial.")
        else:
            lines.append(f"- Raw: **{summary.get('score')}/100 · {summary.get('severity')} · {summary.get('recommendation')}** · {summary.get('total_issues')} findings")
            lines.append(f"- Noise split: vendored={summary.get('vendored_findings')} · generated={summary.get('generated_findings')} · **project={summary.get('project_findings')}**")
            psev = summary.get("project_by_severity") or {}
            lines.append(f"- Project severity: {', '.join(f'{k}={v}' for k,v in sorted(psev.items())) or 'none'}")
            lines.append("\n| Rule | Severity | Count | Sample location |")
            lines.append("|---|---|---:|---|")
            for rid, rec in sorted(summary.get("by_rule", {}).items(), key=lambda t: -t[1]["count"])[:25]:
                s = rec.get("sample") or {}
                loc = f"{s.get('file')}:{s.get('line')}" if s else "—"
                lines.append(f"| {rid} | {rec.get('severity')} | {rec.get('count')} | `{loc}` |")
    lines.append("")

    lines.append("## Sensitive-surface inventory (project files only)\n")
    hosts = inv.get("hosts") or {}
    if hosts:
        lines.append("**External hosts referenced:**")
        for h, n in hosts.items():
            lines.append(f"- `{h}` ×{n}")
    else:
        lines.append("**External hosts referenced:** none")
    lines.append("")
    if inv.get("executables"):
        lines.append("**Executable / shell files:**")
        for e in inv["executables"]:
            lines.append(f"- `{e}`")
        lines.append("")
    if inv.get("installs"):
        lines.append("**Install / fetch / run-another-tool patterns:**")
        for i in inv["installs"][:25]:
            lines.append(f"- `{i['file']}:{i['line']}` — `{i['match']}`")
        lines.append("")
    for k, items in (inv.get("dangerous") or {}).items():
        if items:
            lines.append(f"**{k}:**")
            for d in items[:12]:
                lines.append(f"- `{d['file']}:{d['line']}` — `{d['match']}`")
            lines.append("")

    lines.append("## Manual review checklist\n")
    lines.append("- [ ] Read every project HIGH/CRITICAL at its file:line.")
    lines.append("- [ ] Classify each match: executed instruction vs example/quote vs test fixture.")
    lines.append("- [ ] Confirm external hosts are expected and documented.")
    lines.append("- [ ] Confirm credential access is necessary and bounded.")
    lines.append("- [ ] Confirm persistence (if any) is a documented feature, not hidden.")
    lines.append("- [ ] Identify uninspected external trust anchors (binaries, unpinned npx/pip/uvx, releases).")
    lines.append("- [ ] Note scan completeness (AE1 / partial) and lower confidence if applicable.")
    lines.append("")
    lines.append("## Raw summary (machine-readable)\n")
    lines.append("```json")
    lines.append(json.dumps({
        "name": name,
        "files": files,
        "scan": summary,
        "inventory": inv,
    }, indent=2, ensure_ascii=False)[:12000])
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--name")
    ap.add_argument("--outdir", default=str(Path.home() / "skill-reports"))
    ap.add_argument("--no-scan", action="store_true")
    ap.add_argument("--verify", metavar="MANIFEST")
    args = ap.parse_args()

    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"error: not a directory: {target}", file=sys.stderr)
        return 1

    name = args.name or target.name

    if args.verify:
        return verify_manifest(Path(args.verify).expanduser(), target)

    files = {"project": 0, "vendored": 0, "generated": 0}
    project_files: list[Path] = []
    for p in iter_files(target):
        rel = p.relative_to(target)
        cls = classify(rel)
        files[cls] += 1
        if cls == "project" and p.name not in SKIP_FILE:
            project_files.append(p)

    scan = {"available": False, "reason": "skipped (--no-scan)"}
    summary = {"available": False}
    if not args.no_scan:
        scan = run_scan(target)
        summary = summarize_report(scan.get("report"))

    inv = inventory(project_files, target)

    outdir = Path(args.outdir).expanduser()
    outdir.mkdir(parents=True, exist_ok=True)
    manifests = outdir / "manifests"
    manifests.mkdir(exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    md_path = outdir / f"{name}-{stamp}.md"
    json_path = outdir / f"{name}-{stamp}.json"
    manifest_path = manifests / f"{name}.sha256"

    # manifest
    mlines = []
    for p in sorted(project_files):
        mlines.append(f"{sha256_file(p)}  {p.relative_to(target)}")
    manifest_path.write_text("\n".join(mlines) + "\n", encoding="utf-8")

    md = render_md(name, target, files, scan, summary, inv, str(manifest_path))
    md_path.write_text(md, encoding="utf-8")
    json_path.write_text(json.dumps({
        "name": name,
        "target": str(target),
        "generated": datetime.now(timezone.utc).isoformat(),
        "files": files,
        "scan": summary,
        "inventory": inv,
        "manifest": str(manifest_path),
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Report:   {md_path}")
    print(f"JSON:     {json_path}")
    print(f"Manifest: {manifest_path}")
    print(f"Files:    project={files['project']} vendored={files['vendored']} generated={files['generated']}")
    if summary.get("available"):
        print(f"Raw scan: {summary.get('score')}/100 {summary.get('severity')} {summary.get('recommendation')} "
              f"({summary.get('total_issues')} findings; project={summary.get('project_findings')}, "
              f"vendored={summary.get('vendored_findings')}, generated={summary.get('generated_findings')})")
        print(f"Static posture hint: {static_posture(summary.get('project_by_severity', {}))}")
    else:
        print(f"Scan: unavailable ({scan.get('reason','')})")
    print("Next: perform semantic review and fill the verdict in the report.")

    if scan.get("available") is False and not args.no_scan:
        return 3
    return 0


def verify_manifest(manifest: Path, target: Path) -> int:
    if not manifest.exists():
        print(f"error: manifest not found: {manifest}", file=sys.stderr)
        return 1
    drift = []
    expected = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        expected[rel] = digest
    for rel, digest in expected.items():
        p = target / rel
        if not p.exists():
            drift.append(f"MISSING  {rel}")
            continue
        actual = sha256_file(p)
        if actual != digest:
            drift.append(f"CHANGED  {rel}")
    # detect new files
    current = set()
    for p in iter_files(target):
        if classify(p.relative_to(target)) == "project" and p.name not in SKIP_FILE:
            current.add(str(p.relative_to(target)))
    for rel in sorted(current - set(expected)):
        drift.append(f"NEW      {rel}")
    if drift:
        print("DRIFT DETECTED:")
        for d in drift:
            print("  " + d)
        return 2
    print(f"OK: {len(expected)} files match manifest {manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
