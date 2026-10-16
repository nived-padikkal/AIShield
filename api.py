"""Flask API that exposes AiShield's check() to the React dashboard.

All decisions are persisted in PostgreSQL (see database/).
The domain whitelist (POST /api/domains) is enforced on every check:
if the list is non-empty, commands that post/pass data to other domains get BLOCK.

Run:  python api.py            (serves on http://localhost:5000)
"""
import re

from flask import Flask, jsonify, request
from flask_cors import CORS

import main as aishield
from database import db

app = Flask(__name__)
CORS(app)

DOMAIN_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def _status_of(verdict):
    """Map AiShield verdict -> dashboard status."""
    return {"ALLOW": "allow", "REVIEW": "review", "BLOCK": "disallow"}.get(verdict, "review")


def _run_check(command, allowed_domains=None):
    try:
        result = aishield.check(command, allowed_domains=allowed_domains)
        return result.to_dict()
    except Exception as exc:  # missing dataset, bad model state, ...
        return {
            "command": command,
            "verdict": "ERROR",
            "findings": [],
            "note": f"scanner error: {exc}",
        }


def _db_error(exc):
    return jsonify({"error": f"database unavailable: {exc}"}), 503


@app.get("/api/health")
def health():
    db_up = db.ping()
    return jsonify({"status": "ok" if db_up else "degraded", "database": "up" if db_up else "down"})


@app.get("/api/stats")
def stats():
    try:
        return jsonify(db.count_by_status())
    except Exception as exc:
        return _db_error(exc)


@app.get("/api/history")
def history():
    limit = request.args.get("limit", 100, type=int)
    try:
        return jsonify(db.list_checks(limit))
    except Exception as exc:
        return _db_error(exc)


@app.post("/api/check")
def check_endpoint():
    data = request.get_json(silent=True) or {}
    command = (data.get("command") or "").strip()
    if not command:
        return jsonify({"error": "command is required"}), 400

    try:
        allowed = [d["domain"] for d in db.list_domains()]
    except Exception as exc:
        return _db_error(exc)

    result = _run_check(command, allowed_domains=allowed or None)
    try:
        entry = db.insert_check(
            command=command,
            verdict=result["verdict"],
            status=_status_of(result["verdict"]),
            note=result.get("note", ""),
            findings=result.get("findings", []),
        )
        return jsonify(entry)
    except Exception as exc:
        return _db_error(exc)


@app.delete("/api/history")
def clear_history():
    try:
        deleted = db.clear_checks()
        return jsonify({"cleared": True, "deleted": deleted})
    except Exception as exc:
        return _db_error(exc)


@app.get("/api/domains")
def get_domains():
    try:
        return jsonify(db.list_domains())
    except Exception as exc:
        return _db_error(exc)


@app.post("/api/domains")
def add_domain():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    if not DOMAIN_RE.match(domain):
        return jsonify({"error": f"invalid domain: {domain} (use host like api.example.com or *.example.com)"}), 400
    try:
        entry = db.add_domain(domain)
        return jsonify(entry), 201
    except Exception as exc:
        return _db_error(exc)


@app.delete("/api/domains")
def delete_domain():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip().lower()
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    try:
        removed_id = db.remove_domain(domain)
        if removed_id is None:
            return jsonify({"error": f"domain not found: {domain}"}), 404
        return jsonify({"removed": domain})
    except Exception as exc:
        return _db_error(exc)


if __name__ == "__main__":
    try:
        db.init_db()
        print(f"PostgreSQL ready: {db.connection_url()}")
    except Exception as exc:
        print(f"WARNING: PostgreSQL not reachable ({exc}). Start it, then restart api.py.")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
