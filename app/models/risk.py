from pydantic import BaseModel


class RiskResult(BaseModel):
    score: int
    level: str
    explanation: str