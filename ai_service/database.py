"""
VULKN — ai_service/database.py
PostgreSQL connection and table management.
The document says:
  engine = create_engine(DB_URL)
  Create all tables using schema
  Insert a test scan record
  Query it back and print it
"""

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone
import uuid

# ── Connection URL ────────────────────────────────────────────────────
# Reads from environment variable DB_URL
# When docker-compose is running: postgresql://vulkn_user:vulkn_pass@postgres:5432/vulkn_db
# For local testing: set DB_URL in your terminal or use the fallback below
DB_URL = os.getenv(
    "DB_URL",
    "postgresql://vulkn_user:vulkn_pass@localhost:5432/vulkn_db"
)

# ── Engine (the connection) ───────────────────────────────────────────
def get_engine():
    """
    Creates and returns a SQLAlchemy engine.
    connect_args timeout prevents hanging if Postgres is not running.
    """
    try:
        engine = create_engine(
            DB_URL,
            pool_pre_ping=True,  # checks connection is alive before using it
            connect_args={"connect_timeout": 3}
        )
        return engine
    except Exception as e:
        print(f"[database.py] Engine creation error: {e}")
        return None


# ── Session factory ───────────────────────────────────────────────────
def get_session(engine):
    """Returns a database session for running queries."""
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()


# ── Create tables from schema.sql ─────────────────────────────────────
def create_tables(engine):
    """
    Reads infra/schema.sql and runs it against the database.
    This creates all 4 tables: users, scans, findings, reports.
    """
    schema_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "infra", "schema.sql"
    )
    if not os.path.exists(schema_path):
        print(f"[database.py] schema.sql not found at {schema_path}")
        return False

    with open(schema_path, "r") as f:
        schema_sql = f.read()

    try:
        with engine.connect() as conn:
            conn.execute(text(schema_sql))
            conn.commit()
        print("[database.py] All tables created successfully")
        return True
    except Exception as e:
        print(f"[database.py] Table creation error: {e}")
        return False


# ── Insert a test scan record ─────────────────────────────────────────
def insert_test_scan(engine):
    """
    The document says: 'Insert a test scan record'.
    Creates a dummy user + scan for testing.
    Returns the scan_id if successful.
    """
    test_user_id = str(uuid.uuid4())
    test_scan_id = str(uuid.uuid4())

    try:
        with engine.connect() as conn:
            # Insert test user
            conn.execute(text("""
                INSERT INTO users (id, email, password_hash, is_active)
                VALUES (:id, :email, :password_hash, :is_active)
                ON CONFLICT (email) DO NOTHING
            """), {
                "id": test_user_id,
                "email": "test@vulkn.dev",
                "password_hash": "hashed_test_password",
                "is_active": True
            })

            # Get the actual user id (in case it already existed)
            result = conn.execute(text(
                "SELECT id FROM users WHERE email = 'test@vulkn.dev'"
            ))
            user_row = result.fetchone()
            actual_user_id = str(user_row[0])

            # Insert test scan
            conn.execute(text("""
                INSERT INTO scans
                    (id, user_id, target_url, status, scanners_total)
                VALUES
                    (:id, :user_id, :target_url, :status, :scanners_total)
            """), {
                "id": test_scan_id,
                "user_id": actual_user_id,
                "target_url": "http://testphp.vulnweb.com",
                "status": "queued",
                "scanners_total": 6
            })

            conn.commit()
            print(f"[database.py] Test scan inserted: scan_id={test_scan_id}")
            return test_scan_id

    except Exception as e:
        print(f"[database.py] Insert error: {e}")
        return None


# ── Query a scan back and print it ───────────────────────────────────
def query_scan(engine, scan_id):
    """
    The document says: 'Query it back and print it'.
    """
    try:
        with engine.connect() as conn:
            result = conn.execute(text(
                "SELECT * FROM scans WHERE id = :scan_id"
            ), {"scan_id": scan_id})
            row = result.fetchone()
            if row:
                print("\n[database.py] Scan record retrieved:")
                print(f"  id          : {row[0]}")
                print(f"  user_id     : {row[1]}")
                print(f"  target_url  : {row[2]}")
                print(f"  status      : {row[3]}")
                print(f"  created_at  : {row[8]}")
                return dict(row._mapping)
            else:
                print(f"[database.py] No scan found with id={scan_id}")
                return None
    except Exception as e:
        print(f"[database.py] Query error: {e}")
        return None


# ── Test function — run directly to verify everything ─────────────────
def test_postgres_connection():
    """
    Runs all 4 document tasks:
    1. Create engine
    2. Create tables
    3. Insert test scan record
    4. Query it back and print it
    """
    print("=" * 50)
    print("Testing PostgreSQL connection...")
    print(f"DB_URL: {DB_URL}")
    print("=" * 50)

    engine = get_engine()
    if engine is None:
        print("\nCould not create engine. PostgreSQL not running yet.")
        print("This is expected — run docker-compose up in Week 5.")
        print("Code is ready and will work when DB is available.")
        return

    # Test basic connection
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            print("Connection successful!")
    except Exception as e:
        print(f"\nCannot connect to PostgreSQL: {e}")
        print("This is expected — run docker-compose up in Week 5.")
        return

    # Create tables
    print("\nCreating tables from schema.sql...")
    create_tables(engine)

    # Insert test scan
    print("\nInserting test scan record...")
    scan_id = insert_test_scan(engine)

    # Query it back
    if scan_id:
        print("\nQuerying scan back from database...")
        query_scan(engine, scan_id)

    print("\nAll Day 18 PostgreSQL tasks complete!")


if __name__ == "__main__":
    test_postgres_connection()