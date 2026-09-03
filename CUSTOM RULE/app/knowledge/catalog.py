"""Build the controlled knowledge catalog from live code-owned schemas."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.context_builder import (
    EVENT_COLLECTORS,
    EVENT_FIELD_TYPES,
    OPERATORS_BY_FIELD_TYPE,
    DeploymentContext,
)
from app.knowledge.models import KnowledgeDocument


def _schema_documents(context: DeploymentContext) -> list[KnowledgeDocument]:
    status = context.agent_status or {}
    active_events = set(status.get("supported_events", []))
    active_collectors = set(status.get("active_collectors", []))
    documents: list[KnowledgeDocument] = []
    for event, fields in sorted(EVENT_FIELD_TYPES.items()):
        collectors = EVENT_COLLECTORS.get(event, [])
        availability = (
            "available"
            if event in active_events
            else "unavailable in the current live deployment"
        )
        field_rows = [
            {
                "name": name,
                "type": field_type,
                "operators": OPERATORS_BY_FIELD_TYPE[field_type],
            }
            for name, field_type in fields.items()
        ]
        body = {
            "event": event,
            "availability": availability,
            "required_collectors": collectors,
            "active_collectors": [c for c in collectors if c in active_collectors],
            "fields": field_rows,
            "rule": "Use only these fields and operators for this event.",
        }
        documents.append(
            KnowledgeDocument(
                id=f"schema.{event}.v1",
                type="event_schema",
                title=f"{event} executable event schema",
                body=json.dumps(body, separators=(",", ":"), ensure_ascii=False),
                event_types=[event],
                fields=list(fields),
                collectors=collectors,
                trust_level="core",
                source="generated:context_builder",
            )
        )
    return documents


def _builtin_documents() -> list[KnowledgeDocument]:
    raw: list[dict[str, Any]] = [
        {
            "id": "caveat.windows.execution_aliases.v1",
            "type": "platform_caveat",
            "title": "Windows packaged-app execution aliases",
            "body": (
                "Windows launch names can be aliases rather than the persistent process. "
                "Normalize Calculator requests from calc.exe to CalculatorApp.exe. Treat "
                "launcher shims as telemetry facts, not separate user intent. Preserve "
                "is_launcher_shim and shim_target evidence when available; never guess a "
                "new alias without a code-owned mapping."
            ),
            "event_types": ["process.start"],
            "fields": ["name", "is_launcher_shim", "shim_target"],
            "pattern_type": "alias_normalization",
            "trust_level": "core",
        },
        {
            "id": "caveat.process.identity.v1",
            "type": "platform_caveat",
            "title": "Process identity and PID reuse",
            "body": (
                "Use ProcessGuid/parent_guid for process ancestry when telemetry provides "
                "them. A raw PID can be reused and is weaker across multi-minute windows. "
                "For process.start to network.connect, the executable IR currently joins "
                "on pid, while runtime state must remain bounded by the correlation window."
            ),
            "event_types": ["process.start", "network.connect"],
            "fields": ["pid", "ppid", "guid", "parent_guid"],
            "pattern_type": "identity",
            "trust_level": "core",
        },
        {
            "id": "caveat.wmi.polling.v1",
            "type": "platform_caveat",
            "title": "WMI process polling blind spot",
            "body": (
                "WMI process collection is periodic at roughly one-second resolution. "
                "Very short-lived processes may start and exit between polls. Do not claim "
                "lossless process telemetry when WMI is the only active provider."
            ),
            "event_types": ["process.start"],
            "collectors": ["wmi"],
            "trust_level": "core",
        },
        {
            "id": "caveat.telemetry.prerequisites.v1",
            "type": "platform_caveat",
            "title": "Sysmon and Security telemetry prerequisites",
            "body": (
                "Sysmon-backed events such as network.connect, dns.query, file.create, "
                "registry.set, image.load and process access are unavailable unless Sysmon "
                "is installed, its channel is readable, and the event class is enabled. "
                "Security-backed events require the relevant Windows audit policy and "
                "suitable privileges. Warn before approval when live capability is absent."
            ),
            "event_types": [
                "network.connect",
                "dns.query",
                "file.create",
                "registry.set",
                "image.load",
                "auth.login_failure",
                "auth.login_success",
            ],
            "collectors": ["sysmon", "security"],
            "trust_level": "core",
        },
        {
            "id": "pattern.single_event.v1",
            "type": "rule_pattern",
            "title": "Immediate single-event rule",
            "body": (
                "Use one trigger_event and one or more conditions. aggregation, correlation "
                "and sustain_for are null. This fires once for each qualifying event."
            ),
            "pattern_type": "single_event",
            "trust_level": "curated",
        },
        {
            "id": "pattern.sustained_process.v1",
            "type": "rule_pattern",
            "title": "Sustained process liveness",
            "body": (
                "For remains open, stays running, or continues longer than a duration: use "
                "trigger_event process.start, process conditions, sustain_for such as 1m, "
                "and no aggregation. Runtime must re-check the same process identity after "
                "the duration; starting the process alone is not a completed match."
            ),
            "event_types": ["process.start"],
            "fields": ["name", "pid"],
            "pattern_type": "sustain",
            "trust_level": "curated",
        },
        {
            "id": "pattern.ordered_correlation.v1",
            "type": "rule_pattern",
            "title": "Ordered multi-stage correlation",
            "body": (
                "For A then B or process chains, use correlation.stages in stated order, "
                "ordered true, a bounded within duration, and a valid join_on. Each stage "
                "retains its own event and conditions; do not flatten stage conditions."
            ),
            "pattern_type": "ordered_correlation",
            "trust_level": "curated",
        },
        {
            "id": "pattern.cooccurrence.v1",
            "type": "rule_pattern",
            "title": "Unordered co-occurrence",
            "body": (
                "For A and B running at the same time, use correlation stages with ordered "
                "false, join_on host, and a bounded within window. Do not convert this into "
                "a single process condition or require one process event to name both apps."
            ),
            "event_types": ["process.start"],
            "fields": ["name", "host"],
            "pattern_type": "cooccurrence",
            "trust_level": "curated",
        },
        {
            "id": "pattern.aggregation.v1",
            "type": "rule_pattern",
            "title": "Threshold aggregation",
            "body": (
                "For more than N events in a period, use aggregation.key, aggregation.window "
                "and aggregation.threshold. Aggregation counts discrete events; it is not "
                "the representation for a process remaining alive."
            ),
            "pattern_type": "aggregation",
            "trust_level": "curated",
        },
        {
            "id": "policy.human_response.v1",
            "type": "response_policy",
            "title": "Human-approved response actions",
            "body": (
                "The model may suggest alert, kill_process, or isolate_host, but must leave "
                "response_actions empty. A human selects actions, and deterministic approval "
                "validation remains authoritative. Retrieval never authorizes an action."
            ),
            "trust_level": "core",
        },
    ]
    return [KnowledgeDocument.model_validate(item) for item in raw]


def _load_promoted(promoted_dir: Path) -> list[KnowledgeDocument]:
    documents: list[KnowledgeDocument] = []
    if not promoted_dir.exists():
        return documents
    for path in sorted(promoted_dir.glob("*.json")):
        try:
            document = KnowledgeDocument.model_validate_json(
                path.read_text(encoding="utf-8")
            )
            if document.type == "verified_example" and document.trust_level == "verified":
                documents.append(document)
        except (OSError, ValueError):
            continue
    return documents


def build_catalog(
    context: DeploymentContext, promoted_dir: Path
) -> list[KnowledgeDocument]:
    documents = _schema_documents(context) + _builtin_documents() + _load_promoted(
        promoted_dir
    )
    seen: set[str] = set()
    for document in documents:
        if document.id in seen:
            raise ValueError(f"Duplicate knowledge document id: {document.id}")
        seen.add(document.id)
        unknown_events = set(document.event_types) - set(EVENT_FIELD_TYPES)
        if unknown_events:
            raise ValueError(
                f"{document.id} references unknown events: {sorted(unknown_events)}"
            )
        known_fields = {
            field
            for event in document.event_types
            for field in EVENT_FIELD_TYPES.get(event, {})
        }
        # Caveats may mention normalized evidence-only identity fields.
        allowed_evidence_fields = {"guid", "parent_guid"}
        unknown_fields = set(document.fields) - known_fields - allowed_evidence_fields
        if document.event_types and unknown_fields:
            raise ValueError(
                f"{document.id} references unknown fields: {sorted(unknown_fields)}"
            )
    return documents
