from pydantic import BaseModel, Field, field_validator
from typing import Any, Dict, Union
from datetime import datetime
import re

try:
    from pydantic import ConfigDict
except Exception:
    ConfigDict = None
try:
    from pydantic.version import VERSION as PYDANTIC_VERSION
except Exception:
    PYDANTIC_VERSION = "1"
from typing import List, Optional

# Matches the "message" object in the tester's JSON
class MessageContent(BaseModel):
    if ConfigDict and PYDANTIC_VERSION.startswith("2"):
        model_config = ConfigDict(populate_by_name=True, extra="ignore")
    else:
        class Config:
            allow_population_by_field_name = True
            extra = "ignore"

    sender: str
    text: str
    timestamp: Union[int, str] = 0  # Epoch time in ms OR ISO 8601 string

    @field_validator('timestamp', mode='before')
    def parse_timestamp(cls, v):
        """Convert ISO 8601 and various formats to epoch ms."""
        if isinstance(v, int):
            return v
        if not v or v == 0:
            return 0
        if isinstance(v, str):
            # Try ISO 8601 format (e.g., "2025-02-11T10:30:00Z")
            iso_patterns = [
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?$',  # ISO with or without Z
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$',  # ISO with timezone
            ]
            if any(re.match(p, v) for p in iso_patterns):
                try:
                    dt = datetime.fromisoformat(v.replace('Z', '+00:00'))
                    return int(dt.timestamp() * 1000)
                except (ValueError, AttributeError):
                    pass
            # Try parsing as plain int string
            try:
                return int(v)
            except ValueError:
                return 0
        return 0

class MessageMetadata(BaseModel):
    if ConfigDict and PYDANTIC_VERSION.startswith("2"):
        model_config = ConfigDict(populate_by_name=True, extra="ignore")
    else:
        class Config:
            allow_population_by_field_name = True
            extra = "ignore"

    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

# The main request body
class MessageRequest(BaseModel):
    if ConfigDict and PYDANTIC_VERSION.startswith("2"):
        model_config = ConfigDict(populate_by_name=True, extra="ignore")
    else:
        class Config:
            allow_population_by_field_name = True
            extra = "ignore"

    session_id: Optional[str] = Field(default=None, alias="sessionId")
    message: Optional[MessageContent] = None
    conversationHistory: Optional[List[MessageContent]] = Field(default_factory=list)
    metadata: Optional[MessageMetadata] = None
    # Accept any extra data without rejecting the request
    extra_payload: Optional[Dict[str, Any]] = None

# The EXACT response format the tester expects
class HoneypotResponse(BaseModel):
    status: str = "success"
    reply: str
    scam_detected: bool = False
    confidence_score: float = 0.0
    extracted_intelligence: Dict[str, Any] = Field(default_factory=dict)
    sophistication_level: str = "low"
    intelligence_value_score: int = 0
    campaign_detected: bool = False
    campaign_strength: int = 1
    priority_level: str = "low"
    investigator_summary: Dict[str, Any] = Field(default_factory=dict)


# Reply-only response (do not expose internal scam analysis fields)
class HoneypotReplyResponse(BaseModel):
    status: str = "success"
    reply: str
