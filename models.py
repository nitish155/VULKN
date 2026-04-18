from sqlalchemy import Column, String, DateTime
from database import Base
import datetime

class ScanTask(Base):
    __tablename__ = "scan_tasks"

    scan_id = Column(String, primary_key=True, index=True)
    target_url = Column(String, nullable=False)
    status = Column(String, default="Queued") 
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)