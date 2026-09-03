"""
FastAPI application — server entry point.

Startup sequence:
  1. Validate GROQ_API_KEY via pydantic-settings (fails with clear message)
  2. Attempt /models discovery → update config if successful, keep defaults if not
  3. Mount static files, include routers, start

Endpoints:
  POST /api/parse-rule    — full NL→IR pipeline (rate-limited)
  POST /api/rules/approve — persist approved rule (rate-limited)
  POST /api/rules/reject  — log rejection with reason (rate-limited)
  GET  /api/rules         — list approved rules (paginated)
  GET  /api/context       — current deployment context
  GET  /api/health        — health + memory usage

Middleware: security headers → CORS → rate limiter → body size gate → routes
"""
import logging
import sys
import os
import hmac
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import Settings, get_settings, set_settings
from app.context_builder import build_context, EVENT_FIELD_TYPES, OPERATORS_BY_FIELD_TYPE, EVENT_COLLECTORS
from app.injection_screener import screen
from app.groq_client import parse_rule, discover_models, create_client, set_shared_client
from app.semantic_validator import validate_structure, validate_against_context
from app.capability_checker import check_capabilities
from app.rule_simulator import simulate
from app.rule_normalizer import normalize_rule_ir
from app.yaml_rules import parse_yaml_rule
from app.rule_store import (
    create_rule_record,
    create_rejection_record,
    append_rule,
    append_rejection,
    list_rules,
    list_recent_rules,
    count_rules,
    find_semantic_duplicate,
    delete_semantic_duplicates,
    delete_rule,
    delete_all_rules,
    list_rejections,
    get_rule_by_id,
    migrate_rule_integrity,
)
from app.knowledge import KnowledgeService
from shared.action_types import (
    ActionType,
    ACTION_LABELS,
    ACTION_DESCRIPTIONS,
    SEVERITY_SUGGESTED_ACTION,
    validate_actions,
)
from shared.integrity import verify_record

import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_COLLECTOR_STATUS_FILE = _DATA_DIR / "collector_status.json"
_WATCHER_RUNTIME_FILE = _DATA_DIR / "watcher_runtime.json"
_WATCHER_ACTIVITY_FILE = _DATA_DIR / "watcher_activity.jsonl"
_WATCHER_SAVED_ACTIVITY_FILE = _DATA_DIR / "watcher_saved_activity.jsonl"
_WATCHER_CONTROL_FILE = _DATA_DIR / "watcher_control.json"
_KNOWLEDGE: KnowledgeService | None = None


def _knowledge() -> KnowledgeService:
    """Return the authoring-only knowledge service with configured bounds."""
    global _KNOWLEDGE
    if _KNOWLEDGE is None:
        settings = get_settings()
        _KNOWLEDGE = KnowledgeService(
            max_documents=settings.rag_max_documents,
            max_context_chars=settings.rag_max_context_chars,
            min_score=settings.rag_min_score,
        )
    return _KNOWLEDGE


# ═══════════════════════════════════════════════════════════════════════
# Logging setup
# ═══════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# Rate limiter
# ═══════════════════════════════════════════════════════════════════════

limiter = Limiter(key_func=get_remote_address)


# ═══════════════════════════════════════════════════════════════════════
# Lifespan — startup & shutdown
# ═══════════════════════════════════════════════════════════════════════


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup:
      1. Validate settings (GROQ_API_KEY)
      2. Discover models from Groq /models endpoint
    """
    # Step 1: Validate settings
    try:
        settings = Settings()
        set_settings(settings)
        global _KNOWLEDGE
        _KNOWLEDGE = KnowledgeService(
            max_documents=settings.rag_max_documents,
            max_context_chars=settings.rag_max_context_chars,
            min_score=settings.rag_min_score,
        )
        app.state.settings = settings
        app.state.groq_client = create_client(settings.groq_api_key, float(settings.request_timeout_s))
        set_shared_client(app.state.groq_client)
        logger.info("Settings validated — GROQ_API_KEY is set")
        logger.info("Primary model: %s", settings.primary_model)
        logger.info("Fallback model: %s", settings.fallback_model)
        logger.info("Environment: %s", settings.env)
        migrated = migrate_rule_integrity()
        if migrated:
            logger.info("Added integrity protection to %d legacy approved rule(s)", migrated)
    except Exception as e:
        logger.critical("STARTUP FAILED — configuration error: %s", e)
        logger.critical(
            "Make sure GROQ_API_KEY is set in .env or environment variables"
        )
        sys.exit(1)

    # Step 2: Discover models (non-blocking, never fails startup)
    if settings.rag_enabled:
        try:
            knowledge_status = _knowledge().ensure_index(build_context())
            logger.info(
                "Authoring knowledge ready: %s documents, %s",
                knowledge_status.get("document_count", 0),
                knowledge_status.get("version", "unknown"),
            )
        except Exception as exc:
            # Static prompt fallback preserves existing authoring behaviour.
            logger.warning("Knowledge index unavailable; using static prompt: %s", exc)

    try:
        models = await discover_models()
        if models:
            logger.info("Available Groq models: %s", ", ".join(models[:10]))
            # Check if configured models actually exist
            if settings.primary_model not in models:
                logger.warning(
                    "Primary model '%s' not found in available models",
                    settings.primary_model,
                )
            if settings.fallback_model not in models:
                logger.warning(
                    "Fallback model '%s' not found in available models",
                    settings.fallback_model,
                )
        else:
            logger.info(
                "Model discovery returned no results — using configured defaults"
            )
    except Exception as e:
        logger.warning("Model discovery failed (using defaults): %s", e)

    logger.info("Server ready on port %d", settings.port)
    yield
    set_shared_client(None)
    await app.state.groq_client.close()
    logger.info("Server shutting down")


# ═══════════════════════════════════════════════════════════════════════
# FastAPI app
# ═══════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="AI Understanding Layer v5",
    description="NL → IR rule conversion using Groq LLM",
    version="1.0.0",
    lifespan=lifespan,
)

# Rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8765", "http://localhost:8765",
        "http://127.0.0.1:3000", "http://localhost:3000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-GEKKO-Token"],
)


# ═══════════════════════════════════════════════════════════════════════
# Security headers middleware
# ═══════════════════════════════════════════════════════════════════════


_unauthenticated_launch_warned = False


@app.middleware("http")
async def local_api_auth(request: Request, call_next):
    """
    Require the per-launch desktop token when hardened native mode is active.

    FIX (fail-closed): previously, if GEKKO_API_TOKEN simply wasn't set —
    e.g. a standalone `uvicorn app.main:app` launch outside desktop.py,
    which is the README's own Quick Start command — this check silently
    no-op'd and every /api/* route was fully unauthenticated. Now: no token
    means refuse /api/* with 503 UNLESS gekko_allow_unauthenticated_local is
    explicitly set true in .env (a deliberate, logged, local-dev-only choice).
    """
    global _unauthenticated_launch_warned
    if not request.url.path.startswith("/api/") or request.url.path == "/api/health":
        return await call_next(request)

    expected = os.environ.get("GEKKO_API_TOKEN", "")
    if expected:
        if not hmac.compare_digest(request.headers.get("X-GEKKO-Token", ""), expected):
            return JSONResponse(status_code=401, content={"error": "Local GEKKO authorization required"})
        return await call_next(request)

    if get_settings().gekko_allow_unauthenticated_local:
        if not _unauthenticated_launch_warned:
            logger.warning(
                "SECURITY: GEKKO_API_TOKEN is not set and "
                "GEKKO_ALLOW_UNAUTHENTICATED_LOCAL=true — /api/* is running "
                "WITHOUT authentication. Only intended for local development."
            )
            _unauthenticated_launch_warned = True
        return await call_next(request)

    return JSONResponse(
        status_code=503,
        content={
            "error": "unauthenticated_launch_refused",
            "message": (
                "No GEKKO_API_TOKEN is set for this launch. Start via desktop.py "
                "(sets one automatically), or set GEKKO_ALLOW_UNAUTHENTICATED_LOCAL=true "
                "in .env to explicitly allow an unauthenticated local launch."
            ),
        },
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Equivalent of helmet — adds security headers to every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# ═══════════════════════════════════════════════════════════════════════
# Content-Length gate middleware
# ═══════════════════════════════════════════════════════════════════════

MAX_BODY_BYTES = 64 * 1024  # bounded support for detailed multi-stage rules


@app.middleware("http")
async def body_size_gate(request: Request, call_next):
    """Reject oversized request bodies before they're read into memory."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"error": f"Request body too large (max {MAX_BODY_BYTES // 1024}KB)"},
        )
    return await call_next(request)


# ═══════════════════════════════════════════════════════════════════════
# Request / Response models
# ═══════════════════════════════════════════════════════════════════════


class ParseRuleRequest(BaseModel):
    rule_text: str = Field(..., max_length=12000, min_length=1)


class ApproveRequest(BaseModel):
    rule_text: str
    ir: dict
    injection_flags: list[str] = []
    capability_gaps: list[str] = []
    # Human-selected response actions — validated against ActionType enum.
    # Empty list means the human accepted the LLM suggestion as-is, which is
    # fine for alert-only rules. The UI should always pre-fill from suggested_action.
    response_actions: list[str] = []
    original_ir: dict | None = None
    edit_mode: str | None = Field(default=None, pattern=r"^(intermediate|expert)$")
    retrieval_trace: dict | None = None


class DraftCheckRequest(BaseModel):
    draft: dict


class RejectRequest(BaseModel):
    rule_text: str
    ir: dict | None = None
    reason: str = Field(..., min_length=1)
    injection_flags: list[str] = []


def _parse_draft(draft: dict):
    """Run structural, contextual and deployment checks for a RuleIR draft."""
    normalized, _ = normalize_rule_ir(draft)
    if not normalized.get("conditions") and not normalized.get("correlation") and not normalized.get("aggregation"):
        return None, ["Unsafe match-all rule: add at least one condition, aggregation, or correlation stage"], None
    wrapped = {"status": "ok", "clarification": None, "ir": normalized, "explanation": None}
    structural = validate_structure(wrapped)
    if not structural.valid or structural.parsed is None:
        return None, structural.errors, None
    context = build_context()
    contextual = validate_against_context(structural.parsed, context)
    if not contextual.valid:
        return None, contextual.errors, None
    capability = check_capabilities(structural.parsed, context)
    if not capability.capable:
        return None, capability.gaps, capability
    return structural.parsed, [], capability


@app.post("/api/rules/draft-check")
@limiter.limit("30/minute")
async def draft_check(request: Request, body: DraftCheckRequest = Body(...)):
    """Validate capabilities and freshly simulate the exact current draft."""
    parsed, errors, capability = _parse_draft(body.draft)
    if errors or parsed is None:
        return {"valid": False, "errors": errors, "simulation": None,
                "capability": capability.model_dump() if capability else None}
    return {"valid": True, "errors": [], "simulation": simulate(parsed).model_dump(),
            "capability": capability.model_dump() if capability else {"capable": True, "gaps": []},
            "normalized_draft": parsed.ir.model_dump() if parsed.ir else body.draft}


class YamlRuleRequest(BaseModel):
    yaml_text: str = Field(..., min_length=1, max_length=8000)


@app.post("/api/rules/from-yaml")
@limiter.limit("30/minute")
async def rules_from_yaml(request: Request, body: YamlRuleRequest = Body(...)):
    """
    Author a rule directly in YAML, bypassing the LLM entirely — for when
    the Groq API limit/quota is hit, or for offline/scripted authoring.

    Runs through the EXACT SAME structural + contextual + capability +
    simulation pipeline as an LLM-produced draft (_parse_draft) — see
    app/yaml_rules.py's module docstring for the schema and rationale. On
    success, returns the identical response shape as /api/rules/draft-check,
    so the same review UI and /api/rules/approve flow both work unmodified —
    a YAML rule is reviewed and approved exactly like an LLM one.
    """
    draft, yaml_errors = parse_yaml_rule(body.yaml_text)
    if draft is None:
        return {"valid": False, "errors": yaml_errors, "simulation": None, "capability": None}
    parsed, errors, capability = _parse_draft(draft)
    if errors or parsed is None:
        return {"valid": False, "errors": errors, "simulation": None,
                "capability": capability.model_dump() if capability else None}
    return {"valid": True, "errors": [], "simulation": simulate(parsed).model_dump(),
            "capability": capability.model_dump() if capability else {"capable": True, "gaps": []},
            "normalized_draft": parsed.ir.model_dump() if parsed.ir else draft}


@app.get("/api/ir-schema-options")
async def ir_schema_options():
    """Backend-owned options for the safe Intermediate editor."""
    return {
        "events": sorted(EVENT_FIELD_TYPES),
        "fields_by_event": {event: [{"name": name, "type": kind} for name, kind in fields.items()]
                            for event, fields in EVENT_FIELD_TYPES.items()},
        "operators_by_field_type": OPERATORS_BY_FIELD_TYPE,
        "actions": [a.value for a in ActionType],
        "severities": ["low", "medium", "high", "critical"],
        "priorities": list(range(1, 11)),
    }


@app.get("/api/watcher-capabilities")
async def watcher_capabilities():
    """Complete top-down watcher coverage with live availability state."""
    status = {}
    if _COLLECTOR_STATUS_FILE.exists():
        try:
            status = json.loads(_COLLECTOR_STATUS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            status = {}
    active_collectors = set(status.get("active_collectors", []))
    configured_collectors = set(status.get("configured_collectors", active_collectors | set(status.get("failed_collectors", {}))))
    failed_collectors = status.get("failed_collectors", {})
    active_events = set(status.get("supported_events", []))
    events = []
    for event_name, field_types in EVENT_FIELD_TYPES.items():
        collectors = EVENT_COLLECTORS.get(event_name, [])
        events.append({
            "event": event_name,
            "available": event_name in active_events,
            "collectors": collectors,
            "active_collectors": [name for name in collectors if name in active_collectors],
            "failed_collectors": {name: failed_collectors[name] for name in collectors if name in failed_collectors},
            "disabled_collectors": [name for name in collectors if name not in configured_collectors],
            "fields": [{"name": name, "type": kind} for name, kind in field_types.items()],
        })
    runtime = _read_json(_WATCHER_RUNTIME_FILE)
    heartbeat = runtime.get("heartbeat_at", "")
    try:
        heartbeat_age = (datetime.now(timezone.utc) - datetime.fromisoformat(heartbeat.replace("Z", "+00:00"))).total_seconds()
    except (ValueError, TypeError):
        heartbeat_age = 999999
    try:
        import psutil
        pid_alive = psutil.pid_exists(int(runtime.get("pid", 0)))
    except (ValueError, TypeError):
        pid_alive = False
    running = runtime.get("state") in {"watching", "paused"} and pid_alive and heartbeat_age < 15
    details = {item.get("name"): item for item in status.get("collector_details", [])}
    for item in events:
        active = item["active_collectors"]
        modes = [details.get(name, {}) for name in active]
        item["collection_mode"] = "periodic" if any(m.get("collection_mode") == "periodic" for m in modes) else "realtime"
        intervals = [m.get("poll_interval_s") for m in modes if m.get("poll_interval_s")]
        item["poll_interval_s"] = min(intervals) if intervals else None
    return {
        "watcher_running": running,
        "runtime": runtime,
        "heartbeat_age_s": round(heartbeat_age, 1),
        "active_collectors": sorted(active_collectors),
        "failed_collectors": failed_collectors,
        "events": sorted(events, key=lambda item: (not item["available"], item["event"])),
        "storage_policy": {
            "unmatched_events": "transient_only",
            "matched_events": "evidence_json_plus_alert_summary",
            "evidence_directory": "data/evidence",
            "alerts_file": "data/alerts.jsonl",
        },
    }


def _read_json(path: Path) -> dict:
    try: return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError): return {}


@app.get("/api/watcher-runtime")
async def watcher_runtime():
    runtime = _read_json(_WATCHER_RUNTIME_FILE)
    try:
        heartbeat = datetime.fromisoformat(str(runtime.get("heartbeat_at", "")).replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - heartbeat).total_seconds()
    except (ValueError, TypeError):
        age = 999999
    try:
        import psutil
        alive = psutil.pid_exists(int(runtime.get("pid", 0)))
    except (ValueError, TypeError):
        alive = False
    runtime["heartbeat_age_s"] = round(age, 1)
    runtime["running"] = bool(alive and age < 15 and runtime.get("state") in {"watching", "paused"})
    return runtime


@app.get("/api/watcher-activity")
async def watcher_activity(limit: int = 200, compact: bool = True):
    limit = max(1, min(limit, 500))
    # Read only a bounded tail instead of allocating the complete rotating
    # activity file on every GUI refresh.
    read_limit = min(5000, limit * 10) if compact else limit
    rows = _tail_jsonl(_WATCHER_ACTIVITY_FILE, read_limit)
    if compact:
        rows = _compact_activity_rows(rows)
    return {
        "activity": list(reversed(rows[-limit:])),
        "storage": "bounded diagnostic summaries; unmatched raw events are not retained",
        "compacted": compact,
    }


# ── Save Logs (Santosh, 2026-08-06): opt-in, one consolidated file, off by ──
# ── default, live-toggleable without a watcher restart. See watcher/activity ─
# ── .py's SavedActivityLog and watcher/main.py's control-file poll. ─────────

@app.get("/api/watcher/save-logs")
async def get_save_logs_status():
    state = _read_json(_WATCHER_CONTROL_FILE)
    return {"enabled": bool(state.get("save_activity_log", False))}


class SaveLogsRequest(BaseModel):
    enabled: bool


@app.post("/api/watcher/save-logs")
@limiter.limit("20/minute")
async def set_save_logs_status(request: Request, body: SaveLogsRequest = Body(...)):
    _WATCHER_CONTROL_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _WATCHER_CONTROL_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"save_activity_log": body.enabled}), encoding="utf-8")
    os.replace(tmp, _WATCHER_CONTROL_FILE)
    return {"enabled": body.enabled}


@app.get("/api/watcher-saved-activity")
async def watcher_saved_activity(limit: int = 200):
    limit = max(1, min(limit, 1000))
    rows = _tail_jsonl(_WATCHER_SAVED_ACTIVITY_FILE, limit)
    size_bytes = _WATCHER_SAVED_ACTIVITY_FILE.stat().st_size if _WATCHER_SAVED_ACTIVITY_FILE.exists() else 0
    return {
        "activity": list(reversed(rows[-limit:])),
        "storage": "opt-in consolidated archive; one file, consecutive repeats compacted with a count",
        "file_size_bytes": size_bytes,
    }


def _tail_jsonl(path: Path, limit: int, max_bytes: int = 256 * 1024) -> list[dict]:
    """Read recent valid JSONL rows with bounded transient memory."""
    if limit <= 0:
        return []
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            read_size = min(size, max_bytes)
            handle.seek(-read_size, os.SEEK_END)
            payload = handle.read(read_size)
    except OSError:
        return []
    if read_size < size:
        newline = payload.find(b"\n")
        payload = payload[newline + 1:] if newline >= 0 else b""
    newest_first: list[dict] = []
    for line in reversed(payload.splitlines()):
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                newest_first.append(value)
                if len(newest_first) >= limit:
                    break
        except (ValueError, UnicodeDecodeError):
            continue
    return list(reversed(newest_first))


def _compact_activity_rows(rows: list[dict]) -> list[dict]:
    """Collapse display-only telemetry bursts; matching remains untouched."""
    compacted: list[dict] = []
    for source in rows:
        row = dict(source)
        key_subject = (
            None
            if row.get("event_type") == "powershell.script_block"
            else row.get("subject")
        )
        key = (
            row.get("kind"),
            row.get("event_type"),
            row.get("collector"),
            row.get("process_name"),
            row.get("pid"),
            key_subject,
        )
        previous = compacted[-1] if compacted else None
        previous_key = previous.get("_compact_key") if previous else None
        if row.get("kind") == "event_observed" and previous_key == key:
            previous["repeat_count"] = int(previous.get("repeat_count", 1)) + 1
            previous["at"] = row.get("at", previous.get("at"))
            continue
        row["_compact_key"] = key
        compacted.append(row)
    for row in compacted:
        row.pop("_compact_key", None)
    return compacted


# ═══════════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════════


@app.post("/api/parse-rule")
@limiter.limit("10/minute")
async def parse_rule_endpoint(request: Request, body: ParseRuleRequest = Body(...)):
    """
    Full NL → IR pipeline:
      1. Bounded input length check
      2. Injection screening
      3. Context building
      4. Groq API call with retry/fallback
      5. Semantic validation
      6. Capability checking
      7. Rule simulation
    """
    rule_text = body.rule_text.strip()

    # ── 1. Input length (already enforced by Pydantic, belt-and-suspenders) ─
    settings = get_settings()
    if len(rule_text) > settings.max_rule_length:
        raise HTTPException(
            status_code=400,
            detail=f"Rule text exceeds {settings.max_rule_length} characters",
        )

    # ── 2. Injection screening ─────────────────────────────────────
    screen_result = screen(rule_text)

    if not screen_result.safe:
        # HIGH-confidence injection — BLOCK, LLM never called
        return JSONResponse(
            status_code=400,
            content={
                "stage": "injection_screening",
                "blocked": True,
                "flags": screen_result.flags,
                "message": (
                    "Input blocked: high-confidence injection patterns detected. "
                    "The original input and flags are shown below for review."
                ),
                "original_input": screen_result.flagged_input,
            },
        )

    # ── 3. Context building ────────────────────────────────────────
    context = build_context()

    # Authoring-time retrieval only. It is computed once and reused by all
    # Groq correction retries. Any index failure falls back to the previous
    # static prompt and can never weaken deterministic validation.
    retrieval_context = ""
    retrieval_trace = {
        "enabled": False,
        "mode": "disabled",
        "documents": [],
    }
    if settings.rag_enabled:
        mode = "shadow" if settings.rag_shadow_mode else "active"
        retrieval_context, trace = _knowledge().retrieve(
            rule_text, context, mode=mode
        )
        retrieval_trace = trace.model_dump()
        if settings.rag_shadow_mode:
            retrieval_context = ""

    # ── 4. Groq API call ───────────────────────────────────────────
    injection_flags = screen_result.flags if screen_result.pass_with_warnings else None

    result = await parse_rule(
        rule_text,
        context,
        injection_flags,
        retrieval_context=retrieval_context or None,
    )

    if result.data and isinstance(result.data.get("ir"), dict):
        normalized_ir, normalization_notes = normalize_rule_ir(result.data["ir"])
        result.data["ir"] = normalized_ir
        if normalization_notes:
            explanation = result.data.setdefault("explanation", {})
            assumptions = explanation.setdefault("assumptions_made", [])
            assumptions.extend(note for note in normalization_notes if note not in assumptions)

    if not result.success and result.data is None:
        status_code = 503 if result.error == "service_unavailable" else 500
        response_data = {
            "stage": "llm_parsing",
            "success": False,
            "error": result.error,
            "budget_used": result.budget_used,
            "retrieval": retrieval_trace,
        }
        if result.retry_after:
            response_data["retry_after"] = result.retry_after
        return JSONResponse(status_code=status_code, content=response_data)

    # ── 5. Capability checking ─────────────────────────────────────
    capability_result = {"capable": False, "gaps": []}
    parsed_struct = None
    validation_errors: list[str] = []
    if result.data and isinstance(result.data.get("ir"), dict):
        parsed_struct, validation_errors, cap_result = _parse_draft(result.data["ir"])
        capability_result = cap_result.model_dump() if cap_result else {
            "capable": not validation_errors,
            "gaps": validation_errors,
        }
        if validation_errors:
            result.data["_validation_errors"] = validation_errors
        else:
            result.data.pop("_validation_errors", None)

    # ── 6. Simulation ─────────────────────────────────────────────
    simulation_result = {"events": [], "summary": "N/A"}
    if parsed_struct:
        sim = simulate(parsed_struct)
        simulation_result = sim.model_dump()

    # ── 7. Assemble response ──────────────────────────────────────
    return {
        "stage": "complete",
        "success": parsed_struct is not None and not validation_errors,
        "ir": result.data,
        "error": None if not validation_errors else "Draft validation failed: " + "; ".join(validation_errors),
        "validation": {"valid": not validation_errors, "errors": validation_errors},
        "injection_flags": screen_result.flags if screen_result.flags else [],
        "capability": capability_result,
        "simulation": simulation_result,
        "retrieval": retrieval_trace,
        "meta": {
            "budget_used": result.budget_used,
            "response_time_ms": round(result.response_time_ms, 1),
            "model_used": result.model_used,
        },
    }


@app.post("/api/rules/approve")
@limiter.limit("10/minute")
async def approve_rule(request: Request, body: ApproveRequest = Body(...)):
    """Persist an approved rule to data/rules.jsonl.

    The human-selected response_actions are validated against ActionType enum
    before storage. Empty list is rejected — the human must pick at least one.

    After action validation, a capability check runs against the deployment
    context with the human-chosen actions — this is the only point where
    real actions exist, so it's the only meaningful place for this check.
    """
    # ── Fix 1: Strict validation — empty list is rejected at approval ──
    action_errors = validate_actions(body.response_actions, strict=True)
    if action_errors:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_response_actions", "messages": action_errors},
        )

    # ── Fix 2: Capability check at approval time ──────────────────────
    # Re-run capability check with human-selected actions injected into
    # the IR. This closes the gap left by response_actions being empty
    # at parse time — it's the only point where real actions exist.
    if body.ir and isinstance(body.ir.get("ir"), dict):
        try:
            from app.semantic_validator import validate_structure
            # Build a copy of the IR with the human-selected actions
            ir_for_check = dict(body.ir)
            ir_inner = dict(ir_for_check.get("ir", {}))
            ir_inner["response_actions"] = [
                {"type": a, "duration": None} for a in body.response_actions
            ]
            ir_for_check["ir"] = ir_inner

            struct = validate_structure(ir_for_check)
            if struct.valid and struct.parsed:
                context = build_context()
                cap_result = check_capabilities(struct.parsed, context)
                if not cap_result.capable:
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "capability_gaps",
                            "messages": cap_result.gaps,
                        },
                    )
        except HTTPException:
            raise  # re-raise our own 400
        except Exception as exc:
            logger.warning(
                "Capability check at approval failed (non-blocking): %s", exc
            )

    # Inject human-selected actions into the IR before storage
    ir_with_actions = dict(body.ir)
    if isinstance(ir_with_actions.get("ir"), dict):
        ir_with_actions["ir"] = dict(ir_with_actions["ir"])
        ir_with_actions["ir"]["response_actions"] = [
            {"type": a, "duration": None} for a in body.response_actions
        ] if body.response_actions else [{"type": ActionType.ALERT.value, "duration": None}]

    # Mandatory final check. This deliberately runs even if the earlier
    # advisory capability pass could not parse the supplied object.
    final_inner = ir_with_actions.get("ir")
    if not isinstance(final_inner, dict):
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_ir", "messages": ["Expected a complete IR object"]},
        )
    parsed, errors, _ = _parse_draft(final_inner)
    if errors or parsed is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "draft_check_failed", "messages": errors},
        )
    ir_with_actions["ir"] = parsed.ir.model_dump() if parsed.ir else final_inner

    existing = find_semantic_duplicate(ir_with_actions)
    if existing:
        logger.info("Duplicate approval suppressed; existing rule: %s", existing.get("id"))
        return {"status": "already_approved", "rule_id": existing.get("id")}

    record = create_rule_record(
        ir_dict=ir_with_actions,
        rule_text=body.rule_text,
        injection_flags=body.injection_flags,
        capability_gaps=body.capability_gaps,
        original_ir=body.original_ir,
        edit_mode=body.edit_mode,
        retrieval_trace=body.retrieval_trace,
    )
    append_rule(record)
    logger.info("Rule approved: %s actions=%s", record["id"], body.response_actions)
    return {"status": "approved", "rule_id": record["id"]}


class KnowledgeSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=4000)


@app.get("/api/knowledge/status")
async def knowledge_status():
    """Return bounded authoring-index diagnostics; watcher never loads it."""
    settings = get_settings()
    if not settings.rag_enabled:
        return {"ready": False, "enabled": False, "watcher_loaded": False}
    status = _knowledge().ensure_index(build_context())
    return {"enabled": True, "shadow_mode": settings.rag_shadow_mode, **status}


@app.post("/api/knowledge/search")
async def knowledge_search(body: KnowledgeSearchRequest):
    """Read-only retrieval diagnostic used by tests and the native GUI."""
    prompt_context, trace = _knowledge().retrieve(
        body.query.strip(), build_context(), mode="diagnostic"
    )
    return {
        "trace": trace.model_dump(),
        "context_chars": len(prompt_context),
    }


@app.post("/api/knowledge/rebuild")
async def rebuild_knowledge():
    """Atomically rebuild generated schemas and curated authoring guidance."""
    return _knowledge().ensure_index(build_context(), force=True)


@app.get("/api/knowledge/rejection-candidates")
async def rejection_lesson_candidates(limit: int = 200):
    """Surface repeated rejection themes; never auto-promote them."""
    safe_limit = min(max(limit, 2), 500)
    records: list[dict] = []
    page = 0
    while len(records) < safe_limit:
        batch = list_rejections(page=page, limit=min(100, safe_limit - len(records)))
        if not batch:
            break
        records.extend(batch)
        page += 1
    return {
        "candidates": _knowledge().rejection_candidates(records),
        "records_reviewed": len(records),
        "automatic_promotion": False,
    }


@app.post("/api/knowledge/promote/{rule_id}")
async def promote_approved_rule(rule_id: str):
    """Explicitly sanitize and promote one approved rule as a verified example."""
    record = get_rule_by_id(rule_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Approved rule not found")
    try:
        document = _knowledge().promote_rule(record)
        status = _knowledge().ensure_index(build_context(), force=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Approved rule promoted to knowledge: %s", document.id)
    return {
        "status": "promoted",
        "document": document.model_dump(exclude={"body"}),
        "index": status,
    }


@app.post("/api/rules/reject")
@limiter.limit("10/minute")
async def reject_rule(request: Request, body: RejectRequest = Body(...)):
    """Log a rejection with reason to data/rejections.jsonl."""
    record = create_rejection_record(
        ir_dict=body.ir,
        rule_text=body.rule_text,
        reason=body.reason,
        injection_flags=body.injection_flags,
    )
    append_rejection(record)
    logger.info("Rule rejected: %s reason=%s", record["id"], body.reason[:50])
    return {"status": "rejected", "rejection_id": record["id"]}


@app.get("/api/rules")
async def get_rules(page: int = 0, limit: int = 20, newest: bool = False):
    """List approved rules, paginated. Never loads the full file."""
    safe_limit = min(max(limit, 1), 100)
    rules = list_recent_rules(safe_limit) if newest and page == 0 else list_rules(page=page, limit=safe_limit)
    total = count_rules()
    return {
        "rules": rules,
        "page": page,
        "limit": limit,
        "total": total,
    }


@app.delete("/api/rules/{rule_id}")
async def remove_rule(rule_id: str):
    """Delete one approved rule; watcher hot-reload observes the atomic update."""
    if not delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Approved rule not found")
    logger.info("Rule deleted: %s", rule_id)
    return {"status": "deleted", "rule_id": rule_id}


@app.delete("/api/rules")
async def remove_all_rules():
    """Delete all approved rules after confirmation in the native GUI."""
    deleted = delete_all_rules()
    logger.info("All approved rules deleted: count=%d", deleted)
    return {"status": "deleted", "deleted": deleted}


@app.delete("/api/rule-maintenance/duplicates")
async def remove_duplicate_rule_records():
    """Remove stored semantic duplicates while retaining the oldest rule ID."""
    result = delete_semantic_duplicates()
    logger.info("Duplicate rule cleanup: deleted=%d kept=%d", result["deleted"], result["kept"])
    return {"status": "cleaned", **result}


@app.get("/api/context")
async def get_context():
    """Return the current deployment context."""
    return build_context().model_dump()


@app.get("/api/agent-status")
async def get_agent_status():
    """Return the live collector status written by the Watcher Agent."""
    if _COLLECTOR_STATUS_FILE.exists():
        try:
            with open(_COLLECTOR_STATUS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("Failed to read collector_status.json: %s", exc)
    return {
        "active_collectors": [],
        "failed_collectors": {},
        "supported_events": [],
        "unsupported_events": [],
        "status": "agent_not_running",
    }


@app.get("/api/rejections")
async def get_rejections(page: int = 0, limit: int = 20):
    """List rejected rules, paginated."""
    rejections = list_rejections(page=page, limit=min(limit, 100))
    return {
        "rejections": rejections,
        "page": page,
        "limit": limit,
    }


# ═══════════════════════════════════════════════════════════════════
# Action options (Backend_Action_Evidence_Upgrade_Plan §A.3)
# ═══════════════════════════════════════════════════════════════════


@app.get("/api/action-options")
async def action_options():
    """Return the fixed set of valid response actions.

    The review UI calls this once to render checkboxes — it never hardcodes
    the list client-side. Change the enum in shared/action_types.py and the
    UI updates without a frontend deploy.
    """
    return [
        {
            "value": a.value,
            "label": ACTION_LABELS[a],
            "description": ACTION_DESCRIPTIONS[a],
            "destructive": a.value in ("kill_process", "isolate_host"),
        }
        for a in ActionType
    ]


@app.get("/api/severity-suggestions")
async def severity_suggestions():
    """Return the LLM severity → suggested action mapping.

    Used by the review UI to pre-fill the ActionSelector based on the
    severity the LLM assigned. The human always makes the final choice.
    """
    return {
        severity: [a.value for a in actions]
        for severity, actions in SEVERITY_SUGGESTED_ACTION.items()
    }


# ═══════════════════════════════════════════════════════════════════
# Alerts feed (Backend_Action_Evidence_Upgrade_Plan §B + Frontend plan)
# ═══════════════════════════════════════════════════════════════════

_ALERTS_FILE = _DATA_DIR / "alerts.jsonl"


@app.get("/api/alerts")
async def get_alerts(
    page: int = 0,
    limit: int = 50,
    since: str | None = None,
):
    """Return alerts from data/alerts.jsonl.

    Supports:
      - Pagination via page/limit
      - Filtering via ?since=ISO8601 timestamp (returns only alerts after that time)

    The Tauri frontend polls this every few seconds (v1 approach) to fire
    native notifications for new alerts — see Frontend_Tauri_Desktop_Plan.
    """
    if not _ALERTS_FILE.exists():
        return {"alerts": [], "total": 0, "page": page, "limit": limit}

    page = max(0, min(page, 100))
    page_size = max(1, min(limit, 100))
    # The file is append-ordered. Keep only enough newest rows to serve this
    # page instead of materializing and sorting the entire alert history.
    retained: deque[dict] = deque(maxlen=(page + 1) * page_size)
    total = 0

    try:
        with open(_ALERTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    alert["integrity_status"] = verify_record(alert, _DATA_DIR, "alert")
                    # Apply since filter
                    if since and alert.get("fired_at", "") <= since:
                        continue
                    retained.append(alert)
                    total += 1
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        logger.warning("Failed to read alerts.jsonl: %s", exc)
        return {"alerts": [], "total": 0, "page": page, "limit": limit}

    newest = list(reversed(retained))
    start = page * page_size
    paginated = newest[start : start + page_size]

    return {
        "alerts": paginated,
        "total": total,
        "page": page,
        "limit": page_size,
    }


# ═══════════════════════════════════════════════════════════════════
# Evidence viewer (Backend_Action_Evidence_Upgrade_Plan §B.2)
# ═══════════════════════════════════════════════════════════════════

_EVIDENCE_DIR = _DATA_DIR / "evidence"


@app.get("/api/evidence/{instance_id}")
async def get_evidence(instance_id: str):
    """Return the full evidence JSON for a specific rule match instance.

    Evidence files live at data/evidence/{instance_id}.json.
    Returns 404 if the file doesn't exist yet (still being written) or has
    already been cleaned up by the retention policy.
    """
    # Sanitise instance_id to prevent path traversal
    safe_id = Path(instance_id).name  # strips any directory component
    evidence_file = _EVIDENCE_DIR / f"{safe_id}.json"

    if not evidence_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Evidence file not found for instance_id='{safe_id}'",
        )

    try:
        with open(evidence_file, "r", encoding="utf-8") as f:
            record = json.load(f)
        record["integrity_status"] = verify_record(record, _DATA_DIR, "evidence")
        return record
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to read evidence file %s: %s", evidence_file, exc)
        raise HTTPException(status_code=500, detail="Failed to read evidence file")


@app.get("/api/health")
async def health():
    """Health check with memory usage reporting."""
    mem_mb = -1.0
    try:
        if sys.platform == "win32":
            # psutil is already required and handles Windows structure sizing.
            import psutil
            mem_mb = psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
        else:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            mem_mb = usage.ru_maxrss / 1024  # KB → MB on Linux
    except Exception:
        mem_mb = -1.0

    return {
        "status": "healthy",
        "memory_mb": round(mem_mb, 2),
        "rules_count": count_rules(),
    }


# ═══════════════════════════════════════════════════════════════════════
# Mount static files (public/) — must be LAST so it doesn't shadow API
# ═══════════════════════════════════════════════════════════════════════

_static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "public")
if os.path.isdir(_static_dir):
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")
