"""
MailTrust Database Engine & Session Management
Thread-safe SQLite engine with WAL journaling and foreign key integrity.
"""

import os
from contextlib import contextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from models import Base

# Database path defaults to local workspace storage
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mailtrust.db")
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# Create engine with thread-safety for SQLite
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    pool_pre_ping=True
)

# Enable SQLite foreign key constraint enforcement and WAL mode
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if "sqlite" in DATABASE_URL:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.close()

SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine))


def init_db():
    """Create all relational tables if they do not exist."""
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db():
    """Provide a transactional database session context."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
