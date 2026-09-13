from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    MESSAGE = "message"
    PHONE = "phone"
    URL = "url"
    IMAGE = "image"
    DOCUMENT = "document"


class Evidence(BaseModel):
    evidence_type: EvidenceType
    content: Optional[str] = None
    filename: Optional[str] = None
    metadata: dict = Field(default_factory=dict)