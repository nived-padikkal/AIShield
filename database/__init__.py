"""Database package for AiShield.

Usage:
    from database import db          # module access: db.ping(), db.insert_check(), ...
    from database import ping        # or direct function access
"""
from . import db
from .db import (
    add_domain,
    clear_checks,
    connection_url,
    count_by_status,
    get_conn,
    init_db,
    insert_check,
    list_checks,
    list_domains,
    ping,
    remove_domain,
)

__all__ = [
    "db",
    "add_domain",
    "clear_checks",
    "connection_url",
    "count_by_status",
    "get_conn",
    "init_db",
    "insert_check",
    "list_checks",
    "list_domains",
    "ping",
    "remove_domain",
]
