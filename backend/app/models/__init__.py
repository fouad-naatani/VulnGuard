"""SQLAlchemy models package.
 
Importing this package registers every ORM model on the shared ``Base``
metadata, which Alembic autogeneration relies on.
"""
 
from app.models.asset import Asset
from app.models.report import Report
from app.models.scan import Scan, ScanLog
from app.models.setting import Setting
from app.models.user import User
from app.models.vulnerability import Vulnerability
 
__all__ = ["Asset", "Report", "Scan", "ScanLog", "Setting", "User", "Vulnerability"]