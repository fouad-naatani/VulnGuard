"""Scan schemas."""
 
from __future__ import annotations
 
from datetime import datetime
 
from pydantic import BaseModel, ConfigDict, Field
 
from app.models.scan import ScannerType, ScanStatus
 
 
class ScanCreate(BaseModel):
    """Payload for creating a scan job."""
 
    name: str = Field(min_length=1, max_length=255)
    scanner: ScannerType = ScannerType.TRIVY
    target: str = Field(min_length=1, max_length=512)
    asset_id: int | None = None
    start_immediately: bool = True
 
 
class ScanLogRead(BaseModel):
    """A single scan log line."""
 
    model_config = ConfigDict(from_attributes=True)
 
    id: int
    level: str
    message: str
    created_at: datetime
 
 
class ScanRead(BaseModel):
    """Scan representation returned by list endpoints."""
 
    model_config = ConfigDict(from_attributes=True)
 
    id: int
    name: str
    scanner: ScannerType
    target: str
    status: ScanStatus
    progress: int
    asset_id: int | None = None
    asset_hostname: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    error_message: str | None = None
    packages_found: int = 0
    vulnerability_count: int = 0
    created_at: datetime
 
 
class ScanDetail(ScanRead):
    """Scan representation including its log stream."""
 
    logs: list[ScanLogRead] = Field(default_factory=list)