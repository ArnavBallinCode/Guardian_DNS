import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.settings import settings


def initialize_db() -> None:
    db_path = Path(settings.database_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(settings.database_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS domain_policy (
                domain TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                category TEXT NOT NULL,
                p_risk REAL,
                p_vote REAL,
                combined_confidence REAL,
                review_required INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS votes (
                domain TEXT NOT NULL,
                reviewer_id TEXT NOT NULL,
                agree INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (domain, reviewer_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_events (
                day TEXT NOT NULL,
                category TEXT NOT NULL,
                blocked_count INTEGER NOT NULL,
                PRIMARY KEY (day, category)
            )
            """
        )


@contextmanager
def get_conn():
    conn = sqlite3.connect(settings.database_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
