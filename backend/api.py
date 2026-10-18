"""Flask API that exposes AiShield's check() to the React dashboard.

All decisions are persisted in PostgreSQL (see database/).

Run:  python api.py            (serves on http://localhost:5000)
"""
from flask import Flask, jsonify, request
from flask_cors import CORS

import main as aishield
from database import db

app = Flask(__name__)
CORS(app)


def _status_of(verdict):
    """Map AiShield verdict -> dashboard status."""
    return {"ALLOW": "allow", "REVIEW": "review", "BLOCK": "disallow"}.get(verdict, "review")


def _run_check(command):
    try:
        result = aishield.check(command)
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

    result = _run_check(command)
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


if __name__ == "__main__":
    try:
        db.init_db()
        print(f"PostgreSQL ready: {db.connection_url()}")
    except Exception as exc:
        print(f"WARNING: PostgreSQL not reachable ({exc}). Start it, then restart api.py.")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
