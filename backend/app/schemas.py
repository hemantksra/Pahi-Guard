from typing import Literal

from pydantic import BaseModel, Field


RiskLevel = Literal["safe", "suspicious", "dangerous"]


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


class Signal(BaseModel):
    label: str
    detail: str
    impact: Literal["low", "medium", "high"]


class UrlParts(BaseModel):
    normalized_url: str
    scheme: str
    host: str
    path: str


class AnalyzeResponse(BaseModel):
    url: str
    prediction: RiskLevel
    phishing_probability: float
    confidence: float
    verdict: str
    signals: list[Signal]
    safe_signals: list[Signal]
    parts: UrlParts


class BatchAnalyzeRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=25)


class BatchAnalyzeResponse(BaseModel):
    results: list[AnalyzeResponse]
