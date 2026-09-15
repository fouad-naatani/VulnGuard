"""Schemas shared by several endpoints."""
 
from __future__ import annotations
 
from typing import Generic, TypeVar
 
from pydantic import BaseModel, Field
 
ItemT = TypeVar("ItemT")
 
 
class Message(BaseModel):
    """Simple message envelope returned by side-effect endpoints."""
 
    detail: str
 
 
class Page(BaseModel, Generic[ItemT]):
    """Paginated collection envelope used by every list endpoint."""
 
    items: list[ItemT]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
 
    @property
    def pages(self) -> int:
        """Total number of pages available for the current page size."""
        return max(1, -(-self.total // self.page_size))