from pydantic import BaseModel, Field
from typing import Any, Dict
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
    timestamp: int  # Epoch time in ms

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
