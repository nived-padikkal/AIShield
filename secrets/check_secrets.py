#!/usr/bin/env python3
"""
check_secrets.py - find leaked secrets in a codespace folder with TruffleHog.

Scans a folder (codespace root) for committed credentials - AWS keys, private
keys, tokens, passwords, ... - and returns everything it found as a response.

Backends, tried in this order (or force one with --scanner):
  python   pip package `truffleHog` (truffleHog.truffleHog.scan_file, falling
           back to TruffleHog's own detector regexes if scan_file is missing)
  cli      official `trufflehog` binary (`trufflehog filesystem <path> --json`)

Usage
  py secrets/check_secrets.py /path/to/codespace
  py secrets/check_secrets.py /path/to/codespace --json
  py secrets/check_secrets.py /path/to/codespace --scanner python

Exit codes (CLI): 0 = clean, 1 = secrets found, 2 = error.

Use from another script:
  import sys; sys.path.insert(0, "secrets")
  from check_secrets import check_secrets
  resp = check_secrets("/path/to/codespace")   -> resp["secrets"]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".hg", ".svn", ".idea", ".vscode", "node_modules", "__pycache__",
             ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".eggs",
             "dist", "build", "site-packages"}
MAX_FILE_BYTES = 5 * 1024 * 1024
CLI_TIMEOUT = 900

INSTALL_HINT = ("install one of them: `py -m pip install truffleHog` "
                "or the TruffleHog CLI (https://github.com/trufflesecurity/trufflehog)")


class ScannerError(Exception):
    """No usable scanner, bad folder, or the scan itself failed."""


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------
def _iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        dirnames[:] = [d for d in sorted(dirnames) if d not in SKIP_DIRS]
        for name in sorted(filenames):
            p = Path(dirpath) / name
            try:
                if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def _rel(root, path):
    p = Path(str(path))
    if not p.is_absolute():
        return str(path)
    try:
        return str(p.resolve().relative_to(root))
    except (ValueError, OSError):
        return str(path)


def _make_record(root, path, line, rule, secret, reason):
    return {"file": _rel(root, path), "line": line, "rule": rule or "unknown",
            "secret": secret, "reason": reason or ""}


def _locate_line(path, secret):
    """Best-effort line number of `secret` inside `path` (None when unknown)."""
    if not secret:
        return None
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    for i, ln in enumerate(text.splitlines(), 1):
        if secret in ln:
            return i
    return None


def _first(mapping, *keys):
    for k in keys:
        v = mapping.get(k)
        if v is None or v == "" or v == []:
            continue
        if isinstance(v, (str, int)):
            return v
        if isinstance(v, (list, tuple, set)) and v:
            return v
    return None


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [x for x in v if isinstance(x, str) and x]
    if isinstance(v, str):
        return [v] if v else []
    if hasattr(v, "group"):
        return [v.group(0)] if v.group(0) else []
    return []


def _collect(res, default_rule="trufflehog", default_path=None):
    """Flatten whatever TruffleHog handed back into (file, line, rule, secret, reason)."""
    out = []
    if res is None:
        return out
    if isinstance(res, (list, tuple, set)):
        for item in res:
            out.extend(_collect(item, default_rule, default_path))
        return out
    if isinstance(res, str):
        if res:
            out.append((default_path, None, default_rule, res, ""))
        return out
    if not isinstance(res, dict):
        return out

    nested = False
    for key in ("results", "findings", "secrets", "matches", "issues", "detections"):
        if isinstance(res.get(key), (list, dict, tuple)):
            out.extend(_collect(res[key], default_rule, res.get("path") or res.get("file") or default_path))
            nested = True
    if nested:
        return out

    rule = _first(res, "reason", "rule", "DetectorName", "detector", "DetectorType",
                  "type", "name", "title")
    line = _first(res, "line", "lineNumber", "line_number", "Line", "lineno")
    path = _first(res, "path", "file", "filename", "File", "Location") or default_path
    secret = _first(res, "secret", "Raw", "RawV2", "raw", "value", "match", "string")
    reason = _first(res, "reason", "details", "Description", "description") or ""

    secrets = _as_list(secret) + _as_list(
        _first(res, "stringsFound", "strings", "foundStrings", "secrets_found"))
    if not secrets:
        return out
    try:
        line = int(line) if line is not None else None
    except (TypeError, ValueError):
        line = None
    for s in secrets:
        out.append((path, line, rule, s, reason if isinstance(reason, str) else ""))
    return out


# --------------------------------------------------------------------------------------
# backend 1: TruffleHog Python package
# --------------------------------------------------------------------------------------
def _load_trufflehog_py():
    try:
        from truffleHog import truffleHog as mod       # truffleHog 2.x layout
    except ImportError:
        try:
            import truffleHog as mod                   # package exposes it directly
        except ImportError as e:
            raise ScannerError(f"TruffleHog Python package not available ({e}); {INSTALL_HINT}")
    return mod


def _load_trufflehog_regexes():
    """Detector regexes shipped with TruffleHog (name -> pattern), from any known layout."""
    try:
        import truffleHog as pkg
    except ImportError as e:
        raise ScannerError(f"TruffleHog Python package not available ({e}); {INSTALL_HINT}")

    getters = (lambda: getattr(pkg, "regexes", None),
               lambda: __import__("truffleHog.truffleHog", fromlist=["regexes"]).regexes,
               lambda: __import__("truffleHogRegexes.regexChecks", fromlist=["regexes"]).regexes)
    for get in getters:
        try:
            obj = get()
        except Exception:
            continue
        if isinstance(obj, dict) and obj:
            return list(obj.items())
        inner = getattr(obj, "regexes", None)
        if isinstance(inner, dict) and inner:
            return list(inner.items())
    raise ScannerError(f"TruffleHog detector regexes not found in {pkg.__file__}; {INSTALL_HINT}")


def _rx_search(pat, text):
    return pat.search(text) if hasattr(pat, "search") else re.search(pat, text)


def _scan_python(root):
    mod = _load_trufflehog_py()
    scan_file = getattr(mod, "scan_file", None)
    if not callable(scan_file):
        # truffleHog 2.x has no per-file scanner -> run its detector regexes instead
        return _scan_python_regexes(root)

    records = []
    for path in _iter_files(root):
        try:
            res = scan_file(str(path))
        except Exception:
            continue
        for f_path, line, rule, secret, reason in _collect(res, "trufflehog", str(path)):
            if not secret:
                continue
            records.append(_make_record(root, f_path or path, line or _locate_line(path, secret),
                                        rule, secret, reason))
    return records, "trufflehog-python"


def _scan_python_regexes(root):
    """Fallback: run TruffleHog's own detector regexes over the folder."""
    patterns = _load_trufflehog_regexes()
    records = []
    for path in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "\x00" in text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for name, pat in patterns:
                try:
                    m = _rx_search(pat, line)
                except re.error:
                    continue
                if m:
                    records.append(_make_record(root, path, i, name, m.group(0) if hasattr(m, "group") else line.strip(),
                                                "TruffleHog detector regex"))
    return records, "trufflehog-python-regexes"


# --------------------------------------------------------------------------------------
# backend 2: official trufflehog CLI
# --------------------------------------------------------------------------------------
def _parse_cli_output(text, root):
    """Parse trufflehog CLI output: a JSON array, a single object, or JSON lines.

    Handles both the Go CLI (v3, SourceMetadata/DetectorName/Raw) and the legacy
    truffleHog 2.x Python CLI ({"results": [{"reason", "path", "stringsFound"}]}).
    """
    text = (text or "").strip()
    if not text:
        return []
    items = []
    try:
        data = json.loads(text)
        items = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    flat = []
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("results"), list):
            flat.extend(item["results"])
        else:
            flat.append(item)

    records = []
    for item in flat:
        if not isinstance(item, dict):
            continue
        meta = item.get("SourceMetadata") if isinstance(item.get("SourceMetadata"), dict) else {}
        data = meta.get("Data") if isinstance(meta.get("Data"), dict) else {}
        block = next((data[k] for k in ("Filesystem", "Git", "S3", "Github", "GCS")
                      if isinstance(data.get(k), dict)), meta)

        path = (_first(block, "file", "File", "file_name", "repo")
                or _first(item, "path", "file", "SourceName"))
        line = _first(block, "line", "Line", "line_number") or item.get("line")
        rule = (item.get("DetectorName") or item.get("DetectorType")
                or _first(item, "rule", "type") or item.get("reason") or "trufflehog")

        verified = item.get("Verified")
        if verified is True:
            reason = "verified secret"
        elif verified is False:
            reason = "unverified secret"
        else:
            reason = ""

        secrets = _as_list(item.get("Raw") or item.get("RawV2") or item.get("raw"))
        secrets += _as_list(item.get("stringsFound") or item.get("strings") or item.get("secret"))
        try:
            line = int(line) if line is not None else None
        except (TypeError, ValueError):
            line = None

        where = path or root
        target = where if Path(where).is_absolute() else root / where
        for s in secrets:
            records.append(_make_record(root, where, line or _locate_line(target, s),
                                        rule, s, reason))
    return records


def _run_cli(exe, cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=CLI_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as e:
        raise ScannerError(f"failed to run trufflehog CLI: {e}")


def _scan_cli(root):
    exe = shutil.which("trufflehog") or shutil.which("trufflehog.exe")
    if not exe:
        raise ScannerError(f"trufflehog CLI not found on PATH; {INSTALL_HINT}")

    proc = _run_cli(exe, [exe, "filesystem", str(root), "--json"])
    if not (proc.stdout or "").strip() and proc.returncode not in (0, 1):
        # not the Go CLI: the truffleHog 2.x script scans a git repo's history
        proc = _run_cli(exe, [exe, "--json", str(root)])
    if not (proc.stdout or "").strip() and proc.returncode not in (0, 1):
        raise ScannerError(f"trufflehog CLI failed (exit {proc.returncode}): "
                           f"{(proc.stderr or '').strip()[:300]}")
    return _parse_cli_output(proc.stdout, root), "trufflehog-cli"


# --------------------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------------------
SCANNERS = {"python": _scan_python, "python-regexes": _scan_python_regexes, "cli": _scan_cli}


def check_secrets(folder_path, scanner="auto"):
    """Scan `folder_path` for secrets.

    Returns {"path", "scanner", "files_scanned", "count", "secrets"} where each
    secret is {"file", "line", "rule", "secret", "reason"}.
    Raises ScannerError when the folder is bad or no scanner can run.
    """
    root = Path(str(folder_path)).expanduser()
    if not root.exists():
        raise ScannerError(f"folder does not exist: {root}")
    if not root.is_dir():
        raise ScannerError(f"not a folder: {root}")
    root = root.resolve()

    if scanner != "auto":
        if scanner not in SCANNERS:
            raise ScannerError(f"unknown scanner {scanner!r}; choose from {sorted(SCANNERS)}")
        order = [scanner]
    else:
        order = ["python", "cli", "python-regexes"]

    errors, found = [], None
    used, name = None, None
    for key in order:
        try:
            used, name = SCANNERS[key](root)
            break
        except ScannerError as e:
            errors.append(str(e))
    if used is None:
        raise ScannerError(" ".join(errors) if errors else "no scanner available")

    secrets, seen = [], set()
    for rec in used:
        key = (rec["file"], rec["line"], rec["rule"], rec["secret"])
        if key in seen:
            continue
        seen.add(key)
        secrets.append(rec)
    secrets.sort(key=lambda r: (r["file"], r["line"] or 0))

    return {"path": str(root), "scanner": name, "files_scanned": sum(1 for _ in _iter_files(root)),
            "count": len(secrets), "secrets": secrets}


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def format_response(resp):
    lines = [f"Scanner : {resp['scanner']}",
             f"Scanned : {resp['files_scanned']} files under {resp['path']}",
             f"Secrets : {resp['count']}"]
    for i, s in enumerate(resp["secrets"], 1):
        where = f"{s['file']}:{s['line']}" if s["line"] else s["file"]
        shown = s["secret"] if len(s["secret"]) <= 60 else s["secret"][:57] + "..."
        lines.append(f"  {i}. [{s['rule']}] {where}")
        lines.append(f"     secret = {shown}")
        if s["reason"]:
            lines.append(f"     reason = {s['reason']}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find leaked secrets in a codespace folder with TruffleHog.")
    ap.add_argument("path", help="folder to scan (codespace root)")
    ap.add_argument("--scanner", default="auto", choices=["auto", "python", "cli", "python-regexes"],
                    help="which TruffleHog backend to use (default: auto)")
    ap.add_argument("--json", action="store_true", help="print the response as JSON")
    args = ap.parse_args(argv)

    try:
        resp = check_secrets(args.path, args.scanner)
    except ScannerError as e:
        if args.json:
            print(json.dumps({"path": args.path, "scanner": args.scanner, "count": None,
                              "secrets": [], "error": str(e)}, indent=2))
        else:
            print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(resp, indent=2))
    else:
        print(format_response(resp))
    return 1 if resp["count"] else 0


if __name__ == "__main__":
    sys.exit(main())
