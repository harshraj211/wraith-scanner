from pydantic import BaseModel, HttpUrl, Field, ValidationError
from typing import Optional, List, Dict, Any
from enum import Enum

class SafetyMode(str, Enum):
    SAFE = "safe"
    INTRUSIVE = "intrusive"
    LAB = "lab"

class ScanRequestSchema(BaseModel):
    url: HttpUrl  # Automatically validates that it's a real http/https URL
    depth: Optional[int] = Field(default=3, ge=0, le=10)  # Must be between 0 and 10
    timeout: Optional[int] = Field(default=10, ge=1, le=60) # Must be between 1 and 60
    safety_mode: Optional[SafetyMode] = SafetyMode.SAFE
    allow_private_targets: Optional[bool] = False
    auth: Optional[Dict[str, Any]] = None
    imports: Optional[Dict[str, Any]] = None
    sequence_workflows: Optional[List[Dict[str, Any]]] = None

class FindingRetestSchema(BaseModel):
    finding_id: str = Field(..., min_length=1)
