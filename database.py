# database.py
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from pymongo import MongoClient

# This physically loads the variables from your .env file into Python
load_dotenv()

# ==========================================
# POSTGRESQL (Structured Metadata)
# ==========================================
POSTGRES_USER = os.getenv("POSTGRES_USER", "mysterylad")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "Mysterylad!23")
POSTGRES_DB = os.getenv("POSTGRES_DB", "vulkn")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")

# Construct the URL: postgresql://mysterylad:Mysterylad!23@localhost:5432/vulkn
POSTGRES_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:5432/{POSTGRES_DB}"

try:
    engine = create_engine(POSTGRES_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
except Exception as e:
    print(f"[!] PostgreSQL Connection Error: {e}")

# Dependency to inject Postgres session into FastAPI routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# MONGODB (Unstructured JSON/Reports)
# ==========================================
# Grabs the exact connection string from your .env
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017/vulkn")

try:
    mongo_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    # Use the 'vulkn' database from the URL
    mongo_db = mongo_client.get_database() 
    findings_collection = mongo_db["scan_findings"] 
except Exception as e:
    print(f"[!] MongoDB Connection Error: {e}")