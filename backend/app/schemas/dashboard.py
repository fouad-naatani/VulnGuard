"""Dashboard aggregation schemas."""
 
from __future__ import annotations
 
from pydantic import BaseModel, Field
 
from app.schemas.asset import AssetRead
from app.schemas.scan import ScanRead
from app.schemas.vulnerability import VulnerabilityRead
 
 
class DashboardStats(BaseModel):
    """Headline counters displayed on the dashboard cards."""
 
    total_assets: int = 0
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    running_scans: int = 0
    finished_scans: int = 0
 
 
class ChartSeries(BaseModel):
    """Generic labelled series consumed by Chart.js."""
 
    labels: list[str] = Field(default_factory=list)
    values: list[float] = Field(default_factory=list)
 
 
class DashboardResponse(BaseModel):
    """Complete dashboard payload fetched in a single request."""
 
    stats: DashboardStats
    severity_distribution: ChartSeries
    cvss_distribution: ChartSeries
    monthly_scans: ChartSeries
    recent_assets: list[AssetRead] = Field(default_factory=list)
    recent_vulnerabilities: list[VulnerabilityRead] = Field(default_factory=list)
    recent_scans: list[ScanRead] = Field(default_factory=list)