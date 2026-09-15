"""Settings schemas."""
 
from __future__ import annotations
 
from pydantic import BaseModel, ConfigDict
 
 
class SettingRead(BaseModel):
    """A configuration entry; secret values are masked by the API layer."""
 
    model_config = ConfigDict(from_attributes=True)
 
    key: str
    value: str | None = None
    category: str
    is_secret: bool
 
 
class SettingUpdate(BaseModel):
    """Upsert payload for a configuration entry."""
 
    key: str
    value: str | None = None
    category: str = "general"
    is_secret: bool = False