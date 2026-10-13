"""
Safe SQLite schema migration utility for IntelliDocs V4.
Uses PRAGMA table_info to detect existing columns and safely adds missing ones.
Never drops tables or columns.
"""
import logging
from datetime import datetime, timezone
from sqlalchemy import text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

def _get_table_columns(engine: Engine, table_name: str) -> set:
    """Return the set of column names that currently exist in a table."""
    with engine.connect() as conn:
        result = conn.execute(text(f"PRAGMA table_info({table_name})"))
        return {row[1] for row in result.fetchall()}

def _table_exists(engine: Engine, table_name: str) -> bool:
    with engine.connect() as conn:
        result = conn.execute(text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=:name"
        ), {"name": table_name})
        return result.fetchone() is not None

def run_migrations(engine: Engine):
    """
    Run all pending schema migrations safely.
    Call this AFTER Base.metadata.create_all() so new tables are already created.
    """
    _migrate_documents_table(engine)
    _migrate_document_suggestions_table(engine)
    _migrate_sessions_table(engine)
    _migrate_user_mfa_table(engine)
    _migrate_mfa_pending_challenges_table(engine)
    _migrate_sharing_tables(engine)
    _seed_system_categories(engine)
    logger.info("IntelliDocs V4 schema migrations completed.")


def _migrate_mfa_pending_challenges_table(engine: Engine):
    """Ensure the one-time MFA pending challenge table exists."""
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS mfa_pending_challenges (
                challenge_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                used_at TEXT,
                ip_address TEXT
            )
        """))

        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS "
            "ix_mfa_pending_challenges_user_id "
            "ON mfa_pending_challenges(user_id)"
        ))

        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS "
            "ix_mfa_pending_challenges_expires_at "
            "ON mfa_pending_challenges(expires_at)"
        ))

        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS "
            "ix_mfa_pending_challenges_used "
            "ON mfa_pending_challenges(used)"
        ))


def _migrate_user_mfa_table(engine: Engine):
    """Ensure user_mfa table exists with required columns."""
    if not _table_exists(engine, "user_mfa"):
        return

    existing_cols = _get_table_columns(engine, "user_mfa")
    new_columns = [
        ("secret_encrypted", "TEXT"),
        ("is_enabled", "INTEGER DEFAULT 0"),
        ("recovery_codes_hash", "TEXT"),
        ("updated_at", "TEXT"),
    ]

    with engine.begin() as conn:
        for col_name, col_def in new_columns:
            if col_name not in existing_cols:
                try:
                    conn.execute(text(f"ALTER TABLE user_mfa ADD COLUMN {col_name} {col_def}"))
                except Exception as e:
                    logger.warning(f"Could not add column user_mfa.{col_name}: {e}")



def _migrate_sessions_table(engine: Engine):
    """Ensure sessions table has all required columns and valid timestamps."""
    if not _table_exists(engine, "sessions"):
        return

    existing_cols = _get_table_columns(engine, "sessions")

    new_columns = [
        ("revoked_at", "TEXT"),
        ("ip_address", "TEXT"),
    ]

    with engine.begin() as conn:
        for col_name, col_def in new_columns:
            if col_name not in existing_cols:
                try:
                    conn.execute(text(f"ALTER TABLE sessions ADD COLUMN {col_name} {col_def}"))
                    logger.info(f"Added column sessions.{col_name}")
                except Exception as e:
                    logger.warning(f"Could not add column sessions.{col_name}: {e}")

        from datetime import datetime, timezone, timedelta
        default_exp = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        try:
            conn.execute(
                text("UPDATE sessions SET expires_at = :default_exp WHERE expires_at IS NULL OR expires_at = ''"),
                {"default_exp": default_exp}
            )
        except Exception as e:
            logger.warning(f"Could not update legacy session timestamps: {e}")



def _migrate_document_suggestions_table(engine: Engine):
    """Add V4 columns to document_suggestions table if missing."""
    if not _table_exists(engine, "document_suggestions"):
        return

    existing_cols = _get_table_columns(engine, "document_suggestions")

    new_columns = [
        ("evidence", "TEXT"),
        ("resolved_at", "TEXT"),
        ("resolved_by", "INTEGER REFERENCES users(id)"),
        ("created_for_user_id", "INTEGER REFERENCES users(id) ON DELETE CASCADE"),
    ]

    with engine.begin() as conn:
        for col_name, col_def in new_columns:
            if col_name not in existing_cols:
                try:
                    conn.execute(
                        text(
                            f"ALTER TABLE document_suggestions "
                            f"ADD COLUMN {col_name} {col_def}"
                        )
                    )
                    logger.info(
                        f"Added column document_suggestions.{col_name}"
                    )
                except Exception as e:
                    logger.warning(
                        f"Could not add column "
                        f"document_suggestions.{col_name}: {e}"
                    )

    with engine.begin() as conn:
        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_document_suggestions_created_for_user_id ON document_suggestions(created_for_user_id)"))
        except Exception as e:
            logger.warning(f"Could not create personal suggestion scope index: {e}")

def _migrate_documents_table(engine: Engine):
    """Add V4 columns to documents table if missing."""
    if not _table_exists(engine, "documents"):
        return

    existing_cols = _get_table_columns(engine, "documents")

    new_columns = [
        ("folder_id", "INTEGER REFERENCES folders(id) ON DELETE SET NULL"),
        ("category_id", "INTEGER REFERENCES categories(id) ON DELETE SET NULL"),
        ("subcategory", "TEXT"),
        ("version_group_id", "TEXT"),
        ("version_number", "INTEGER NOT NULL DEFAULT 1"),
        ("parent_version_id", "INTEGER REFERENCES documents(id)"),
        ("perceptual_hash", "TEXT"),
        ("display_name", "TEXT"),  # User-visible logical name
        ("access_lock_hash", "TEXT"),
        ("is_access_locked", "INTEGER DEFAULT 0"),
    ]

    with engine.begin() as conn:
        for col_name, col_def in new_columns:
            if col_name not in existing_cols:
                try:
                    conn.execute(text(f"ALTER TABLE documents ADD COLUMN {col_name} {col_def}"))
                    logger.info(f"Added column documents.{col_name}")
                except Exception as e:
                    logger.warning(f"Could not add column documents.{col_name}: {e}")

def _migrate_sharing_tables(engine: Engine):
    """Ensure document_shares, sharing_groups, group_members, and group_document_shares tables exist."""
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS document_shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                target_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                permission TEXT NOT NULL DEFAULT 'READ',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                revoked_at TEXT,
                share_key_hash TEXT,
                share_key_required INTEGER NOT NULL DEFAULT 0,
                share_key_verified_at TEXT,
                share_key_created_at TEXT,
                share_key_rotated_at TEXT
            )
        """))

        existing_cols = _get_table_columns(engine, "document_shares")
        share_key_columns = [
            ("share_key_hash", "TEXT"),
            ("share_key_required", "INTEGER NOT NULL DEFAULT 0"),
            ("share_key_verified_at", "TEXT"),
            ("share_key_created_at", "TEXT"),
            ("share_key_rotated_at", "TEXT"),
        ]
        for col_name, col_def in share_key_columns:
            if col_name not in existing_cols:
                try:
                    conn.execute(text(f"ALTER TABLE document_shares ADD COLUMN {col_name} {col_def}"))
                    logger.info(f"Added column document_shares.{col_name}")
                except Exception as e:
                    logger.warning(f"Could not add column document_shares.{col_name}: {e}")

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sharing_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS group_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL REFERENCES sharing_groups(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role TEXT NOT NULL DEFAULT 'member',
                created_at TEXT NOT NULL
            )
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS group_document_shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                group_id INTEGER NOT NULL REFERENCES sharing_groups(id) ON DELETE CASCADE,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                permission TEXT NOT NULL DEFAULT 'READ',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                revoked_at TEXT
            )
        """))

def _seed_system_categories(engine: Engine):
    """Insert system categories if not already present."""
    if not _table_exists(engine, "categories"):
        return

    from backend.models.category import SYSTEM_CATEGORIES

    with engine.begin() as conn:
        existing = conn.execute(text("SELECT name FROM categories WHERE is_system=1")).fetchall()
        existing_names = {row[0] for row in existing}
        for cat_name in SYSTEM_CATEGORIES:
            if cat_name not in existing_names:
                conn.execute(
                    text("INSERT INTO categories (name, description, is_system, owner_id, created_at) VALUES (:name, :desc, 1, NULL, :created_at)"),
                    {"name": cat_name, "desc": f"System category: {cat_name}", "created_at": datetime.now(timezone.utc).isoformat()}
                )
                logger.info(f"Seeded system category: {cat_name}")
