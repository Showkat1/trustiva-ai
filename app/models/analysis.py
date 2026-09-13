from typing import List, Optional

from pydantic import BaseModel, Field


class RiskSignal(BaseModel):
    name: str
    severity: str
    explanation: str


class EvidenceReference(BaseModel):
    source: str
    excerpt: str
    relevance: str


class Claim(BaseModel):
    claim: str

    verification_status: str = "unknown"

    supporting_evidence: List[str] = Field(
        default_factory=list
    )

    evidence_references: List[EvidenceReference] = Field(
        default_factory=list
    )


class Entity(BaseModel):
    entity_type: str
    value: str


class InvestigationResult(BaseModel):
    threat_category: str

    intent: List[str] = Field(
        default_factory=list
    )

    entities: List[Entity] = Field(
        default_factory=list
    )

    claims: List[Claim] = Field(
        default_factory=list
    )

    risk_signals: List[RiskSignal] = Field(
        default_factory=list
    )

    summary: Optional[str] = None