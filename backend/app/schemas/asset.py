"""Asset schemas."""
 
from __future__ import annotations
 
from datetime import datetime
 
from pydantic import BaseModel, ConfigDict, Field, field_validator
 
from app.models.asset import AgentStatus
from app.utils.validators import validate_hostname, validate_ip_address
 
 
class AssetBase(BaseModel):
    """Editable asset fields."""
 
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=3, max_length=45)
    operating_system: str | None = Field(default=None, max_length=255)
    owner: str | None = Field(default=None, max_length=255)
    tags: list[str] = Field(default_factory=list)
    agent_status: AgentStatus = AgentStatus.NEVER_CONNECTED
    description: str | None = None
 
    @field_validator("hostname")
    @classmethod
    def _check_hostname(cls, value: str) -> str:
        return validate_hostname(value)
 
    @field_validator("ip_address")
    @classmethod
    def _check_ip(cls, value: str) -> str:
        return validate_ip_address(value)
 
 
class AssetCreate(AssetBase):
    """Payload for creating an asset."""
 
 
class AssetUpdate(BaseModel):
    """Partial update of an asset."""
 
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    ip_address: str | None = Field(default=None, min_length=3, max_length=45)
    operating_system: str | None = None
    owner: str | None = None
    tags: list[str] | None = None
    agent_status: AgentStatus | None = None
    description: str | None = None
 
    @field_validator("hostname")
    @classmethod
    def _check_hostname(cls, value: str | None) -> str | None:
        return validate_hostname(value) if value else value
 
    @field_validator("ip_address")
    @classmethod
    def _check_ip(cls, value: str | None) -> str | None:
        return validate_ip_address(value) if value else value
 
 
class AssetRead(BaseModel):
    """Asset representation returned by the API."""
 
    model_config = ConfigDict(from_attributes=True)
 
    id: int
    hostname: str
    ip_address: str
    operating_system: str | None = None
    owner: str | None = None
    tags: list[str] = Field(default_factory=list)
    agent_status: AgentStatus
    description: str | None = None
    last_scan_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    vulnerability_count: int = 0
    critical_count: int = 0