#!/usr/bin/env python3
"""
generate_dataset.py - Build detection datasets from Atomic Red Team.

Downloads atomics from GitHub and extracts every test command.

Usage:
  python generate_dataset.py                           # generate all
  python generate_dataset.py --techniques T1059.004,T1105   # specific techniques only
"""
import argparse
import csv
import gzip
import io
import json
import re
import sys
import tempfile
import urllib.request
import zipfile
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pip install pyyaml")

HERE = Path(__file__).resolve().parent
GITHUB_URL = "https://github.com/redcanaryco/atomic-red-team/archive/master.zip"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
AISHIELD_SCHEMA = ["command", "attack_technique", "technique_name"]

# Supported platforms: linux, windows, macos, containers, all
# To use multiple: PLATFORMS = ["linux", "windows"]
PLATFORMS = ["linux", "windows"]

PLACEHOLDER = re.compile(r"#\{([A-Za-z_]\w*)\}")
SKIP_EXECUTORS = {"manual", "none", ""}


def fetch_attack_technique_names():
    """Download ATT&CK technique names from MITRE CTI."""
    out = HERE / "out" / "attack_technique_names.csv"
    out.parent.mkdir(exist_ok=True)
    print("Fetching ATT&CK technique names...")
    try:
        data = json.loads(urllib.request.urlopen(ATTACK_URL).read())
    except Exception as e:
        print(f"  Failed: {e}")
        return

    rows = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id", "")
                name = obj.get("name", "")
                is_sub = "yes" if obj.get("x_mitre_is_subtechnique") else "no"
                if tid:
                    rows.append((tid, name, is_sub, "mitre/cti@github"))
                break

    rows.sort(key=lambda x: x[0])
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack_technique", "technique_name", "is_subtechnique", "source"])
        w.writerows(rows)
    print(f"  attack_technique_names.csv ({len(rows)} techniques)")


def load_yaml(path):
    with io.open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        return yaml.safe_load(f)


def resolve_placeholders(cmd, input_args, keep_unknown=True):
    args = input_args or {}
    known = {k: str(v.get("default", "")) for k, v in (args or {}).items() if isinstance(v, dict)}
    unknown = []

    def sub(m):
        key = m.group(1)
        if key in known and known[key]:
            return known[key]
        unknown.append(key)
        return m.group(0) if keep_unknown else "ARG"

    return PLACEHOLDER.sub(sub, cmd), sorted(set(unknown))


def fetch_atomics(only=None):
    """Download atomics from GitHub - either specific techniques or full set."""
    cache_dir = Path(tempfile.gettempdir()) / "atomic-red-team-cache"

    if only:
        # Fetch only specific technique files
        atomics_dir = cache_dir / "atomics-selected"
        atomics_dir.mkdir(parents=True, exist_ok=True)
        for tid in sorted(only):
            yml_path = atomics_dir / tid / f"{tid}.yaml"
            if yml_path.exists():
                continue
            yml_path.parent.mkdir(parents=True, exist_ok=True)
            url = f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/{tid}/{tid}.yaml"
            print(f"  Fetching {tid}...")
            try:
                urllib.request.urlretrieve(url, yml_path)
            except Exception:
                print(f"    not found: {tid}")
        return atomics_dir

    # Full fetch
    atomics_dir = cache_dir / "atomic-red-team-master" / "atomics"
    if atomics_dir.exists() and any(atomics_dir.iterdir()):
        print("Using cached data...")
        return atomics_dir

    print("Downloading from GitHub (this may take a few minutes)...")
    cache_dir.mkdir(parents=True, exist_ok=True)
    zip_path = cache_dir / "atomic-red-team.zip"

    try:
        urllib.request.urlretrieve(GITHUB_URL, zip_path)
    except Exception as e:
        sys.exit(f"Failed to download: {e}")

    print("Extracting...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for member in z.namelist():
                if member.startswith("atomic-red-team-master/atomics/"):
                    z.extract(member, cache_dir)
    finally:
        zip_path.unlink(missing_ok=True)

    return atomics_dir


def executor_commands(test):
    ex = test.get("executor") or {}
    if not isinstance(ex, dict):
        return "", False, []
    name = str(ex.get("name", "")).strip()
    elev = bool(ex.get("elevation_required", False))
    cmds = []
    for key in ("command", "content"):
        v = ex.get(key)
        if isinstance(v, str) and v.strip():
            cmds.append(v)
    steps = ex.get("steps")
    if isinstance(steps, list):
        for s in steps:
            if isinstance(s, dict) and isinstance(s.get("command"), str) and s["command"].strip():
                cmds.append(s["command"])
            elif isinstance(s, str) and s.strip():
                cmds.append(s)
    return name, elev, cmds


def extract(atomics_dir, resolve=True, only=None):
    rows = []
    tech_names = OrderedDict()
    skipped = Counter()
    files = sorted(atomics_dir.glob("T*/T*.yaml"))

    for yml in files:
        try:
            doc = load_yaml(yml)
        except Exception as e:
            skipped[f"yaml-error:{type(e).__name__}"] += 1
            continue
        if not isinstance(doc, dict) or not doc.get("attack_technique"):
            skipped["no-technique-id"] += 1
            continue

        tid = str(doc["attack_technique"]).strip()
        if only is not None and tid.upper() not in only:
            continue
        tname = str(doc.get("display_name") or doc.get("technique_name") or "").strip()
        tech_names.setdefault(tid, tname or tid)

        tests = doc.get("atomic_tests") or []
        if not tests:
            skipped["no-tests"] += 1

        for idx, test in enumerate(tests, 1):
            if not isinstance(test, dict):
                continue
            platforms = [str(p).strip().lower() for p in (test.get("supported_platforms") or [])]
            exname, elev, cmds = executor_commands(test)
            if not cmds:
                skipped["no-command"] += 1
                continue
            if exname.lower() in SKIP_EXECUTORS and not cmds:
                skipped["manual-executor"] += 1
                continue

            iargs = test.get("input_arguments") or {}
            for raw in cmds:
                if resolve:
                    cmd, unknown = resolve_placeholders(raw, iargs)
                else:
                    cmd, unknown = raw, sorted(set(PLACEHOLDER.findall(raw)))
                cmd = cmd.replace("\r\n", "\n").strip("\n")
                if not cmd.strip():
                    skipped["empty-command"] += 1
                    continue
                rows.append({
                    "attack_technique": tid,
                    "technique_name": tname,
                    "platforms": "|".join(platforms),
                    "test_name": str(test.get("name", "")).strip(),
                    "test_index": idx,
                    "executor": exname,
                    "elevation_required": "yes" if elev else "no",
                    "placeholders_left": "|".join(unknown),
                    "command": cmd,
                })

    return rows, tech_names, skipped, len(files)


def write_csv(path, rows, cols, gz=False):
    path = Path(path)
    opener = gzip.open if gz else io.open
    kw = {"mode": "wt", "newline": "", "encoding": "utf-8", "errors": "replace"}
    with opener(path, **kw) as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return path


def parse_techniques(value):
    if not value:
        return None
    ids = set()
    for tok in re.split(r"[,\s;]+", value.strip()):
        tok = tok.strip().upper()
        if re.fullmatch(r"T\d{3,4}(?:\.\d{1,3})?", tok):
            ids.add(tok)
    return ids if ids else None


def main():
    ap = argparse.ArgumentParser(description="Build datasets from Atomic Red Team")
    ap.add_argument("--techniques", metavar="IDS", help="comma-separated technique ids (e.g., T1059.004,T1105)")
    args = ap.parse_args()

    out = HERE / "out"
    out.mkdir(exist_ok=True)

    only = parse_techniques(args.techniques)
    if only:
        print(f"Filter: {', '.join(sorted(only))}")
        src = fetch_atomics(only)
    else:
        src = fetch_atomics()

    print(f"Platforms: {', '.join(PLATFORMS)}")
    print("Extracting...")
    rows, tech_names, skipped, nfiles = extract(src, only=only)

    # Filter and write for each platform
    for platform in PLATFORMS:
        if platform == "all":
            filtered = rows
            out_file = "atomic_commands.csv"
        else:
            filtered = [r for r in rows if platform in r["platforms"].split("|")]
            out_file = f"atomic_{platform}_commands.csv"

        write_csv(out / out_file, filtered, AISHIELD_SCHEMA)
        write_csv(out / f"{out_file}.gz", filtered, AISHIELD_SCHEMA, gz=True)
        print(f"  {out_file}: {len(filtered)} rows")

    # Fetch ATT&CK technique names
    fetch_attack_technique_names()

    print(f"\nOutput folder: {out}")
    print("Done!")


if __name__ == "__main__":
    main()
