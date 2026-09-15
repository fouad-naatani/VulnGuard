"""Report schemas."""
 
from __future__ import annotations
 
from datetime import datetime
 
from pydantic import BaseModel, ConfigDict, Field
 
from app.models.report import ReportFormat, ReportStatus
 
 
class ReportCreate(BaseModel):
    """Payload used to request a new report."""
 
    name: str = Field(min_length=1, max_length=255)
    format: ReportFormat = ReportFormat.PDF
    scope: str = Field(default="all", pattern="^(all|asset|scan|correlation)$")
    scope_id: int | None = None


class CorrelationCandidateRead(BaseModel):
    """Asset eligible for a Wazuh/Nessus correlation report."""

    id: int
    hostname: str
    ip_address: str
    matched_count: int
    wazuh_only_count: int
    nessus_only_count: int
    critical_high_count: int
 
 
class ReportRead(BaseModel):
    """Report metadata returned by the API."""
 
    model_config = ConfigDict(from_attributes=True)
 
    id: int
    name: str
    format: ReportFormat
    status: ReportStatus
    file_size: int
    scope: str
    scope_id: int | None = None
    error_message: str | None = None
    created_at: datetime