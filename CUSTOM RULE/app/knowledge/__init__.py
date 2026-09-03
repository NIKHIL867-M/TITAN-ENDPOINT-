"""Authoring-time retrieval for GEKKO.

This package is intentionally never imported by the watcher.  It supplies
grounding to the NL-to-IR authoring API; deterministic validation and runtime
matching remain the authority.
"""

from app.knowledge.service import KnowledgeService

__all__ = ["KnowledgeService"]
