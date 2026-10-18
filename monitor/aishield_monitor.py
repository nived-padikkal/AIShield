#!/usr/bin/env python3
"""
AIShield live monitor (Windows, pure Python, no PowerShell profile hook).

Watches shells started by known AI agents (see WATCH_PARENTS), FREEZES each
one the moment it appears, shows the agent name + original process name + the
command, and waits for you:

    A = allow  (resume the command)
    B = block  (kill the command)

No answer within the timeout = block (fail closed).

Run in a normal terminal (admin not required):
    py -m pip install psutil
    py aishield_monitor.py

Options:
    --api URL            ask your AIShield backend for a suggested verdict
    --auto-block         with --api: block without asking when API says BLOCK
    --parent prefix=Name watch a different parent (repeatable). Replaces the
                         built-in WATCH_PARENTS list.
                         e.g. --parent cursor=Cursor --parent codex=Codex
    --discover           only print new shells + parent chain (find parents)

LIMITS (be honest about these in your report):
  * "Detect, freeze, decide" - not a kernel-level pre-execution hook. The OS
    starts the process first; we freeze it within milliseconds. PowerShell
    takes far longer than that to run the command, so this normally wins the
    race, but it is not guaranteed. Too-fast commands are logged as MISSED.
  * Only shells launched directly by a watched parent are covered (SHELLS).
  * Agents that type into one long-lived terminal are not covered.
"""
import argparse
import base64
import json
import msvcrt
import queue
import threading
import time
import urllib.request
from datetime import datetime

import psutil

# ---------------------------------------------------------------------------
# WATCH PARENTS:  process-name prefix (lowercase)  ->  friendly agent name
# The prefix is matched against the ORIGINAL process name, e.g.
#   language_server_windows_x64.exe  starts with  "language_server"
# Remove a line to stop watching that agent.
# ---------------------------------------------------------------------------
WATCH_PARENTS = {
    "language_server": "Antigravity",       # language_server_windows_x64.exe
    "codex": "Codex",                       # codex.exe
    "copilot-runtime": "GitHub Copilot",    # copilot-runtime.exe (also runs
                                            # startup checks - press A for those)
}

SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "bash.exe", "wsl.exe"}
LOG_FILE = "aishield_decisions.jsonl"
DISCOVERY_LOG = "aishield_discovery.log"
POLL_SECONDS = 0.005


def parse_parents(items):
    """--parent prefix=Label  ->  {prefix: label}. No items = built-in list."""
    if not items:
        return dict(WATCH_PARENTS)
    out = {}
    for item in items:
        prefix, _, label = item.partition("=")
        prefix = prefix.strip().lower()
        out[prefix] = label.strip() or prefix
    return out


def extract_command(argv):
    """Pull the real command text out of a shell's argument list."""
    flags = {"-command", "-c", "/c", "/k", "-encodedcommand", "-ec"}
    for i, a in enumerate(argv[1:], start=1):
        if a.lower() in flags:
            rest = " ".join(argv[i + 1:])
            if a.lower() in ("-encodedcommand", "-ec"):
                try:
                    return base64.b64decode(rest).decode("utf-16-le")
                except Exception:
                    return rest
            return rest
    return " ".join(argv)


def ask_api(url, command):
    """Ask the AIShield backend for a suggested verdict (optional)."""
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps({"command": command}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=2) as r:
            return str(json.loads(r.read().decode()).get("verdict", "?")).upper()
    except Exception:
        return "UNAVAILABLE"


def kill_tree(proc):
    try:
        victims = proc.children(recursive=True) + [proc]
    except psutil.Error:
        victims = [proc]
    for p in victims:
        try:
            p.kill()
        except psutil.Error:
            pass


def log_decision(record):
    record["time"] = datetime.now().isoformat(timespec="seconds")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def find_watched(parents):
    """Return [(process, friendly_name, original_process_name)]."""
    found = []
    for p in psutil.process_iter(["name"]):
        original = p.info["name"] or ""
        low = original.lower()
        for prefix, label in parents.items():
            if low.startswith(prefix):
                found.append((p, label, original))
                break
    return found


def watcher(q, stop, parents):
    """Poll children of the watched parents; freeze new shells instantly."""
    seen = set()
    servers = []
    last_refresh = 0.0
    while not stop.is_set():
        now = time.time()
        if now - last_refresh > 1.0:
            servers = find_watched(parents)
            last_refresh = now
            if len(seen) > 5000:
                seen.clear()
        for sp, label, original in servers:
            try:
                kids = sp.children()
            except psutil.Error:
                continue
            for k in kids:
                try:
                    key = (k.pid, k.create_time())
                    if key in seen:
                        continue
                    seen.add(key)
                    name = k.name().lower()
                except psutil.Error:
                    continue
                if name not in SHELLS:
                    continue
                try:
                    k.suspend()
                    argv = k.cmdline()
                except psutil.Error:
                    q.put(("missed", k, None, label, original))
                    continue
                q.put(("command", k, argv, label, original))
        time.sleep(POLL_SECONDS)


def discover():
    """Print every new shell with its ancestor chain. Freezes/blocks nothing."""
    print("DISCOVERY MODE: nothing is frozen or blocked.")
    print("Now use your agent to run a command. Look for the parent chain that")
    print(f"appears only when the AGENT runs it. Full log: {DISCOVERY_LOG}\n")
    seen = {p.pid for p in psutil.process_iter()}
    try:
        while True:
            for p in psutil.process_iter(["pid", "name"]):
                if p.pid in seen:
                    continue
                seen.add(p.pid)
                try:
                    if (p.info["name"] or "").lower() not in SHELLS:
                        continue
                    chain = [a.name() for a in p.parents()]
                    cmd = " ".join(p.cmdline())[:3000]
                except psutil.Error:
                    continue
                known = next((lbl for a in chain for pre, lbl in WATCH_PARENTS.items()
                              if a.lower().startswith(pre)), None)
                tag = f"   [known agent: {known}]" if known else ""
                print(f"{datetime.now():%H:%M:%S}  {p.info['name']}  <-  "
                      f"{' <- '.join(chain[:4])}{tag}\n           cmd: {cmd}\n")
                with open(DISCOVERY_LOG, "a", encoding="utf-8") as lf:
                    lf.write(f"{datetime.now().isoformat(timespec='seconds')}\t"
                             f"{p.info['name']}\t{' <- '.join(chain[:4])}\t{cmd}\n")
            time.sleep(0.01)
    except KeyboardInterrupt:
        pass


def wait_key(timeout):
    """Return 'a' or 'b', or None on timeout."""
    while msvcrt.kbhit():          # discard keys typed earlier
        msvcrt.getwch()
    end = time.time() + timeout
    while time.time() < end:
        if msvcrt.kbhit():
            ch = msvcrt.getwch().lower()
            if ch in ("a", "b"):
                return ch
        time.sleep(0.02)
    return None


def main():
    ap = argparse.ArgumentParser(description="AIShield live command monitor")
    ap.add_argument("--api", help="AIShield /api/check URL for a suggested verdict")
    ap.add_argument("--timeout", type=int, default=30, help="seconds to wait for A/B")
    ap.add_argument("--auto-block", action="store_true",
                    help="with --api: block automatically when the API says BLOCK")
    ap.add_argument("--parent", action="append", metavar="PREFIX=NAME",
                    help="watch this parent process (repeatable); replaces the "
                         "built-in WATCH_PARENTS list")
    ap.add_argument("--discover", action="store_true",
                    help="only print new shells + parent chain, to find parents")
    args = ap.parse_args()

    if args.discover:
        discover()
        return

    parents = parse_parents(args.parent)
    q = queue.Queue()
    stop = threading.Event()
    threading.Thread(target=watcher, args=(q, stop, parents), daemon=True).start()

    print("AIShield monitor running. Watching these agents:")
    for prefix, label in parents.items():
        print(f"  {label:<16} <- process name starts with '{prefix}'")
    print(f"\n  A = allow   B = block   (no answer in {args.timeout}s = block)")
    print(f"  Decisions are logged to {LOG_FILE}. Ctrl+C to stop.\n")

    current = None
    try:
        while True:
            try:
                kind, proc, argv, label, original = q.get(timeout=0.5)
            except queue.Empty:
                continue

            if kind == "missed":
                print(f"[MISSED] {label} ({original}) pid {proc.pid}: "
                      "ended before it could be frozen\n")
                log_decision({"decision": "MISSED", "agent": label,
                              "parent_process": original, "pid": proc.pid})
                continue

            current = proc
            cmd = extract_command(argv)
            verdict = ask_api(args.api, cmd) if args.api else "-"

            print("=" * 70)
            print(f"AGENT   : {label}")
            print(f"PARENT  : {original}")
            print(f"COMMAND : (pid {proc.pid}, frozen)")
            print(f"  {cmd}")
            if args.api:
                print(f"AIShield suggests: {verdict}")

            if args.auto_block and verdict == "BLOCK":
                choice, note = "b", "auto-blocked by API verdict"
            else:
                print("  [A] allow    [B] block ...", flush=True)
                choice = wait_key(args.timeout)
                note = "user" if choice else "timeout"

            decision = "ALLOW" if choice == "a" else "BLOCK"
            try:
                if decision == "ALLOW":
                    proc.resume()
                else:
                    kill_tree(proc)
            except psutil.Error:
                pass
            current = None

            print(f"  -> {decision} ({note})\n")
            log_decision({"decision": decision, "reason": note, "agent": label,
                          "parent_process": original, "api_verdict": verdict,
                          "command": cmd})
    except KeyboardInterrupt:
        print("\nStopping. Killing any frozen commands (fail closed)...")
    finally:
        stop.set()
        if current is not None:
            kill_tree(current)
        while not q.empty():
            kind, proc, *_ = q.get_nowait()
            if kind == "command":
                kill_tree(proc)


if __name__ == "__main__":
    main()