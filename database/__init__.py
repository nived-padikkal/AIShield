"""Database package for AiShield.

Usage:
    from database import db          # module access: db.ping(), db.insert_check(), ...
    from database import ping        # or direct function access
"""
from . import db
from .db import (
    clear_checks,
    connection_url,
    count_by_status,
    get_conn,
    init_db,
    insert_check,
    list_checks,
    ping,
)

__all__ = [
    "db",
    "clear_checks",
    "connection_url",
    "count_by_status",
    "get_conn",
    "init_db",
    "insert_check",
    "list_checks",
    "ping",
]
