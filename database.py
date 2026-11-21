"""
MailTrust Database Engine & Session Management
Thread-safe engine supporting SQLite local session caching with automated
real-time synchronization and permanent NoSQL persistence in MongoDB Atlas.
"""

import os
from contextlib import contextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from models import (
    Base, User, SessionRecord, RecoveryCode, AnalysisRecord,
    AuditLog, AuditCheckpoint, AppSetting
)
from mongo_db import (
    mongo_save_user, mongo_delete_user,
    mongo_save_session, mongo_delete_session,
    mongo_save_recovery_code,
    mongo_save_analysis,
    mongo_save_audit_log,
    mongo_save_checkpoint,
    mongo_save_setting,
    init_mongodb,
    sync_from_mongodb_to_sqlite
)

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


# ---------------------------------------------------------------------------
# MongoDB Real-Time Synchronization Listeners
# ---------------------------------------------------------------------------

@event.listens_for(User, "after_insert")
@event.listens_for(User, "after_update")
def on_user_saved(mapper, connection, target):
    mongo_save_user(target)

@event.listens_for(User, "after_delete")
def on_user_deleted(mapper, connection, target):
    mongo_delete_user(target)

@event.listens_for(SessionRecord, "after_insert")
@event.listens_for(SessionRecord, "after_update")
def on_session_saved(mapper, connection, target):
    mongo_save_session(target)

@event.listens_for(SessionRecord, "after_delete")
def on_session_deleted(mapper, connection, target):
    mongo_delete_session(target)

@event.listens_for(RecoveryCode, "after_insert")
@event.listens_for(RecoveryCode, "after_update")
def on_recovery_saved(mapper, connection, target):
    mongo_save_recovery_code(target)

@event.listens_for(AnalysisRecord, "after_insert")
@event.listens_for(AnalysisRecord, "after_update")
def on_analysis_saved(mapper, connection, target):
    mongo_save_analysis(target)

@event.listens_for(AuditLog, "after_insert")
@event.listens_for(AuditLog, "after_update")
def on_audit_saved(mapper, connection, target):
    mongo_save_audit_log(target)

@event.listens_for(AuditCheckpoint, "after_insert")
@event.listens_for(AuditCheckpoint, "after_update")
def on_checkpoint_saved(mapper, connection, target):
    mongo_save_checkpoint(target)

@event.listens_for(AppSetting, "after_insert")
@event.listens_for(AppSetting, "after_update")
def on_setting_saved(mapper, connection, target):
    mongo_save_setting(target)


def init_db():
    """Create local relational schema, connect to MongoDB Atlas, and sync state."""
    Base.metadata.create_all(bind=engine)
    init_mongodb()
    with get_db() as db:
        sync_from_mongodb_to_sqlite(db)


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
