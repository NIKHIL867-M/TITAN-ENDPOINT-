"""Typed knowledge documents and retrieval results."""

from __future__ import annotations

from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, Field, model_validator


DocumentType = Literal[
    "platform_caveat",
    "event_schema",
    "rule_pattern",
    "verified_example",
    "rejection_lesson",
    "response_policy",
]
TrustLevel = Literal["core", "curated", "verified", "untrusted"]


class KnowledgeDocument(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    type: DocumentType
    title: str = Field(min_length=3, max_length=160)
    body: str = Field(min_length=10, max_length=12_000)
    event_types: list[str] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)
    collectors: list[str] = Field(default_factory=list)
    pattern_type: str | None = None
    trust_level: TrustLevel
    schema_version: int = Field(default=1, ge=1)
    enabled: bool = True
    source: str = "builtin"
    checksum: str = ""

    @model_validator(mode="after")
    def set_checksum(self) -> "KnowledgeDocument":
        material = self.model_dump(exclude={"checksum"}, mode="json")
        import json

        calculated = sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if self.checksum and self.checksum != calculated:
            raise ValueError("Knowledge document checksum mismatch")
        self.checksum = calculated
        return self


class RetrievalHit(BaseModel):
    id: str
    type: DocumentType
    title: str
    body: str
    score: float
    reason: str
    checksum: str
    trust_level: TrustLevel
    event_types: list[str] = Field(default_factory=list)


class RetrievalTrace(BaseModel):
    enabled: bool = True
    mode: str = "active"
    index_version: str = ""
    query_terms: list[str] = Field(default_factory=list)
    elapsed_ms: float = 0.0
    documents: list[RetrievalHit] = Field(default_factory=list)
    fallback_reason: str | None = None
