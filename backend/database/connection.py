from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.config import settings
import os

# SQLite cannot create a database file when its parent directory does not exist.
# Ensure fresh installs start cleanly without requiring a manual data/ folder.
if settings.DATABASE_URL.startswith("sqlite:///"):
    sqlite_path = settings.DATABASE_URL[len("sqlite:///"):]
    from pathlib import Path
    Path(sqlite_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)

Path(settings.STORAGE_DIR).expanduser().resolve().mkdir(parents=True, exist_ok=True)

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

# Enable SQLite pragmas: WAL mode, foreign keys, cache size
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA cache_size=-65536")
    cursor.execute("PRAGMA temp_store=MEMORY")
    try:
        cursor.execute("ALTER TABLE documents ADD COLUMN summary VARCHAR")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE documents ADD COLUMN key_topics VARCHAR")
    except Exception:
        pass
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
