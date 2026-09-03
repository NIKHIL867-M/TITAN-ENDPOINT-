"""
Groq API client (execute.txt §7 + §8).

Handles the full retry/fallback chain:
  1. Primary model call (temperature=0, structured output if supported)
  2. HTTP 429 → wait retry-after → retry primary → still 429 → fallback model
  3. Fallback 429 → terminal failure: {"error": "service_unavailable"}
  4. Non-JSON output → json_extractor → still fails → retry with correction
  5. Valid JSON, invalid IR → retry with validator errors → still invalid → needs_clarification

Budget: max 3 LLM calls per request, tracked in a per-request CallBudget
object — NOT a module-level variable (that would be shared mutable state
across every concurrent request on the async event loop).

Timeout: asyncio.wait_for() on every call — a hung request can't sit
holding memory indefinitely.

Logging: dev-only, redacted (IPs → [REDACTED_IP]), truncated (>500 chars),
written to stdout via logging module — no in-memory accumulation.
"""


import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field

from groq import AsyncGroq, APIStatusError, APITimeoutError, APIConnectionError

from app.config import get_settings
from app.context_builder import DeploymentContext
from app.json_extractor import extract_json
from app.prompt_builder import (
    build_messages,
    build_correction_message,
    build_validation_feedback_message,
)
from app.semantic_validator import validate_structure, validate_against_context

logger = logging.getLogger(__name__)
_shared_client: AsyncGroq | None = None


def create_client(api_key: str, timeout_s: float) -> AsyncGroq:
    return AsyncGroq(api_key=api_key, timeout=timeout_s)


def set_shared_client(client: AsyncGroq | None) -> None:
    global _shared_client
    _shared_client = client


# ═══════════════════════════════════════════════════════════════════════
# Per-request data structures
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class CallBudget:
    """
    Per-request LLM call budget.

    This is instantiated inside parse_rule() — NEVER at module level.
    A module-level counter would be shared across all concurrent requests
    on the same async worker, which is the exact bug the plan calls out.
    """

    remaining: int
    total_calls: int = 0
    total_tokens: int = 0
    response_times_ms: list[float] = field(default_factory=list)

    def consume(self) -> bool:
        """Consume one call from the budget. Returns False if exhausted."""
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        self.total_calls += 1
        return True


@dataclass
class ParseRuleResult:
    """Complete result from the rule-parsing pipeline."""

    success: bool
    data: dict | None = None
    error: str | None = None
    retry_after: int | None = None
    budget_used: int = 0
    response_time_ms: float = 0
    model_used: str | None = None


# ═══════════════════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════════════════

_IP_PATTERN = re.compile(r"\d+\.\d+\.\d+\.\d+")


def _redact(text: str) -> str:
    """Redact IPs and truncate for safe logging."""
    text = _IP_PATTERN.sub("[REDACTED_IP]", text)
    if len(text) > 500:
        text = text[:500] + "...[TRUNCATED]"
    return text


async def _call_groq(
    client: AsyncGroq,
    messages: list[dict],
    model: str,
    budget: CallBudget,
    timeout_s: int,
    use_json_mode: bool = True,
) -> tuple[str | None, str | None, int | None]:
    """
    Make a single Groq API call.

    Returns: (content, error_type, retry_after_seconds)
      - On success:     (content, None, None)
      - On rate limit:  (None, "rate_limited", N)
      - On other error: (None, "error description", None)
    """
    if not budget.consume():
        return None, "LLM call budget exhausted (max per request reached)", None

    settings = get_settings()
    start = time.monotonic()

    try:
        kwargs: dict = {
            "model": model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": settings.max_llm_output_tokens,
        }
        if use_json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        coro = client.chat.completions.create(**kwargs)
        response = await asyncio.wait_for(coro, timeout=timeout_s)

        elapsed_ms = (time.monotonic() - start) * 1000
        budget.response_times_ms.append(elapsed_ms)

        content = response.choices[0].message.content or ""

        if response.usage:
            budget.total_tokens += response.usage.total_tokens

        if settings.is_development:
            logger.info(
                "Groq call OK: model=%s tokens=%s time=%.0fms content=%s",
                model,
                response.usage.total_tokens if response.usage else "?",
                elapsed_ms,
                _redact(content),
            )

        return content, None, None

    except APIStatusError as e:
        elapsed_ms = (time.monotonic() - start) * 1000
        budget.response_times_ms.append(elapsed_ms)

        if e.status_code == 429:
            retry_after = 5
            if hasattr(e, "response") and e.response is not None:
                retry_after = int(
                    e.response.headers.get("retry-after", 5)
                )
            if settings.is_development:
                logger.warning(
                    "Groq 429: model=%s retry_after=%ds", model, retry_after
                )
            return None, "rate_limited", retry_after

        err_msg = f"API error {e.status_code}: {str(e)[:200]}"
        if settings.is_development:
            logger.error("Groq error: %s", err_msg)
        return None, err_msg, None

    except (asyncio.TimeoutError, APITimeoutError):
        if settings.is_development:
            logger.warning("Groq timeout: model=%s timeout=%ds", model, timeout_s)
        return None, f"Request timed out after {timeout_s}s", None

    except APIConnectionError:
        if settings.is_development:
            logger.error("Groq connection error")
        return None, "Cannot connect to Groq API — check network", None

    except Exception as e:
        if settings.is_development:
            logger.exception("Unexpected Groq error")
        return None, f"Unexpected error: {str(e)[:200]}", None


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════


async def parse_rule(
    rule_text: str,
    context: DeploymentContext,
    injection_flags: list[str] | None = None,
    retrieval_context: str | None = None,
) -> ParseRuleResult:
    """
    Full NL → IR parsing pipeline with retry logic.

    This is the only public entry point. It:
      1. Builds the prompt
      2. Calls the primary model
      3. Handles 429 → retry → fallback
      4. Handles bad JSON → extract → correction retry
      5. Handles invalid IR → validation retry
      6. Returns terminal failure if all retries exhausted

    The CallBudget is instantiated here (per-request scope) — never
    shared across requests.
    """
    settings = get_settings()
    budget = CallBudget(remaining=settings.max_llm_calls_per_request)
    overall_start = time.monotonic()
    model = settings.primary_model

    client = _shared_client or create_client(settings.groq_api_key, float(settings.request_timeout_s))
    owns_client = _shared_client is None

    # Retrieval is performed by the endpoint exactly once per submission.
    # Every retry reuses this same immutable message context.
    messages = build_messages(
        context, rule_text, injection_flags, retrieval_context=retrieval_context
    )

    try:
        # ── Step 1: First call ─────────────────────────────────────
        content, error, retry_after = await _call_groq(
            client, messages, model, budget, settings.request_timeout_s
        )

        # ── Handle rate limit chain ────────────────────────────────
        if error == "rate_limited":
            # Retry primary once after waiting
            wait = min(retry_after or 5, 10)
            await asyncio.sleep(wait)

            content, error, retry_after = await _call_groq(
                client, messages, model, budget, settings.request_timeout_s
            )

            if error == "rate_limited":
                # Fall back to smaller model
                model = settings.fallback_model
                wait = min(retry_after or 5, 10)
                await asyncio.sleep(wait)

                content, error, retry_after = await _call_groq(
                    client, messages, model, budget, settings.request_timeout_s
                )

                if error == "rate_limited":
                    # Terminal failure — all models rate-limited
                    return ParseRuleResult(
                        success=False,
                        error="service_unavailable",
                        retry_after=retry_after or 60,
                        budget_used=budget.total_calls,
                        model_used=model,
                    )

        # Non-rate-limit error from any call
        if error and error != "rate_limited":
            return ParseRuleResult(
                success=False,
                error=error,
                budget_used=budget.total_calls,
                model_used=model,
            )

        if not content:
            return ParseRuleResult(
                success=False,
                error="Empty response from LLM",
                budget_used=budget.total_calls,
                model_used=model,
            )

        # ── Step 2: Extract JSON ───────────────────────────────────
        parsed_dict = extract_json(content)

        if parsed_dict is None and budget.remaining > 0:
            # Retry with correction prompt
            messages.append({"role": "assistant", "content": content})
            messages.append(
                build_correction_message("Could not parse as valid JSON")
            )

            content, error, _ = await _call_groq(
                client, messages, model, budget, settings.request_timeout_s
            )

            if error or not content:
                return ParseRuleResult(
                    success=False,
                    error=f"JSON extraction failed after retry: {error or 'empty response'}",
                    budget_used=budget.total_calls,
                    model_used=model,
                )

            parsed_dict = extract_json(content)

        if parsed_dict is None:
            return ParseRuleResult(
                success=False,
                error="LLM output is not valid JSON even after correction retry",
                budget_used=budget.total_calls,
                model_used=model,
            )

        # ── Step 3: Structural validation (Pydantic) ───────────────
        struct_result = validate_structure(parsed_dict)

        if not struct_result.valid and budget.remaining > 0:
            # Feed validation errors back to LLM once
            messages.append(
                {"role": "assistant", "content": json.dumps(parsed_dict)}
            )
            messages.append(
                build_validation_feedback_message(struct_result.errors)
            )

            content, error, _ = await _call_groq(
                client, messages, model, budget, settings.request_timeout_s
            )

            if not error and content:
                retry_dict = extract_json(content)
                if retry_dict:
                    retry_result = validate_structure(retry_dict)
                    if retry_result.valid:
                        parsed_dict = retry_dict
                        struct_result = retry_result

        if not struct_result.valid:
            return ParseRuleResult(
                success=False,
                data=parsed_dict,
                error=(
                    "Structural validation failed: "
                    + "; ".join(struct_result.errors)
                ),
                budget_used=budget.total_calls,
                model_used=model,
            )

        # ── Step 4: Context validation ─────────────────────────────
        ctx_result = validate_against_context(struct_result.parsed, context)

        if not ctx_result.valid and budget.remaining > 0:
            messages.append(
                {"role": "assistant", "content": json.dumps(parsed_dict)}
            )
            messages.append(
                build_validation_feedback_message(ctx_result.errors)
            )

            content, error, _ = await _call_groq(
                client, messages, model, budget, settings.request_timeout_s
            )

            if not error and content:
                retry_dict = extract_json(content)
                if retry_dict:
                    retry_struct = validate_structure(retry_dict)
                    if retry_struct.valid:
                        retry_ctx = validate_against_context(
                            retry_struct.parsed, context
                        )
                        if retry_ctx.valid:
                            parsed_dict = retry_dict
                            ctx_result = retry_ctx

        # Even if context validation has issues, return what we have
        # with the errors attached — the human reviewer is the backstop
        elapsed = (time.monotonic() - overall_start) * 1000

        if not ctx_result.valid:
            parsed_dict["_validation_errors"] = ctx_result.errors

        return ParseRuleResult(
            success=True,
            data=parsed_dict,
            error=(
                f"Context validation issues (review needed): "
                f"{'; '.join(ctx_result.errors)}"
                if not ctx_result.valid
                else None
            ),
            budget_used=budget.total_calls,
            response_time_ms=elapsed,
            model_used=model,
        )

    finally:
        if owns_client:
            await client.close()


async def discover_models() -> list[str]:
    """
    Call Groq's /models endpoint to discover available models.
    Used at startup — returns empty list on failure (never blocks startup).
    """
    settings = get_settings()
    client = _shared_client or AsyncGroq(
        api_key=settings.groq_api_key,
        timeout=5.0,  # short timeout — don't block startup
    )
    owns_client = _shared_client is None
    try:
        models = await asyncio.wait_for(
            client.models.list(), timeout=5.0
        )
        return [m.id for m in models.data]
    except Exception as e:
        logger.warning("Model discovery failed (using defaults): %s", str(e)[:100])
        return []
    finally:
        if owns_client:
            await client.close()
