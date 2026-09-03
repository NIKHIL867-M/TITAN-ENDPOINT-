"""
Capability checker (v5 §4 consistency fix — flaw #11).

Cross-references the IR's referenced collectors/fields against
installed_collectors, and checks user permissions for the rule's
severity level and response actions.

Runs BEFORE human review so the reviewer sees any capability gaps
before approving — otherwise they'd be approving a rule that might
reference an uninstalled collector or require permissions they lack.
"""


from pydantic import BaseModel

from app.context_builder import DeploymentContext
from app.semantic_validator import ParseResult
from shared.windows_aliases import executable_aliases


class CapabilityResult(BaseModel):
    """Outcome of capability checking — gaps are shown in the review UI."""

    capable: bool
    gaps: list[str]


# ── Mapping: log source type → which collectors can provide it ─────────
# Uses actual collector names from watcher/collectors/__init__.py COLLECTOR_REGISTRY
_SOURCE_TO_COLLECTORS: dict[str, list[str]] = {
    "process": ["sysmon", "wmi", "security"],
    "auth": ["security"],
    "authentication": ["security"],
    "network": ["sysmon"],
    "service": ["system", "security"],
    "registry": ["sysmon", "registry_fim"],
    "file": ["sysmon", "security"],
    "image": ["sysmon"],
    "inventory": ["inventory"],
}

# ── Mapping: severity → required permission ────────────────────────────
_SEVERITY_PERMISSIONS: dict[str, str] = {
    "low": "approve_low_severity",
    "medium": "approve_medium_severity",
    "high": "approve_high_severity",
    "critical": "approve_critical_severity",
}

# ── Mapping: action type → required permission ─────────────────────────
_ACTION_PERMISSIONS: dict[str, str] = {
    "alert": "create_rule",           # base permission — always available
    "webhook": "create_rule",         # base permission
    "kill_process": "execute_kill_process",
    "isolate_host": "execute_isolate_host",
    "block_auth": "execute_block_auth",
    "quarantine": "execute_quarantine",
}


# ── UWP Execution Alias Suggestions ───────────────────────────────────
def check_capabilities(
    parsed: ParseResult,
    context: DeploymentContext,
) -> CapabilityResult:
    """
    Verify that:
      1. The deployment has the collectors needed for this rule's event type
      2. The referenced log sources are selected / active
      3. The user has permissions for the rule's severity level
      4. The user has permissions for each response action
      5. The deployed agent currently has an active collector producing the event type (live check)
      6. No UWP execution alias stubs are referenced without warnings (UWP warning check)
    """
    gaps: list[str] = []

    if parsed.status == "needs_clarification" or parsed.ir is None:
        return CapabilityResult(capable=True, gaps=[])

    ir = parsed.ir

    # ── 1. Check trigger event → required collectors ───────────────
    event_source = (
        ir.trigger_event.split(".")[0]
        if "." in ir.trigger_event
        else ir.trigger_event
    )
    for source_name, required_collectors in _SOURCE_TO_COLLECTORS.items():
        if event_source in source_name or source_name in event_source:
            has_any = any(
                c in context.installed_collectors for c in required_collectors
            )
            if not has_any:
                gaps.append(
                    f"Trigger event '{ir.trigger_event}' likely requires one of "
                    f"{required_collectors}, but installed collectors are: "
                    f"{context.installed_collectors}"
                )

    # ── 1b. Check live agent capabilities (flaws #2 and #5) ──────────
    required_events = [ir.trigger_event]
    if ir.correlation:
        required_events = [stage.event for stage in ir.correlation.stages]
    if context.agent_status:
        active_events = context.agent_status.get("supported_events", [])
        for required_event in required_events:
            if required_event in active_events:
                continue
            msg = (
                f"Required event '{required_event}' is not supported by any active collector "
                f"on the deployed agent."
            )
            failed = context.agent_status.get("failed_collectors", {})
            if failed:
                msg += " Failed collectors on the agent:\n"
                for cname, probs in failed.items():
                    msg += f"  - [{cname}]: " + ", ".join(probs)
            else:
                msg += f" (Active collectors: {context.agent_status.get('active_collectors', [])})"
            gaps.append(msg)

    # ── 2. Check fields against selected log sources ───────────────
    # Field validity is event-specific and enforced by the semantic validator;
    # provider availability is checked above from the live agent. The legacy
    # broad source groups overlap (for example ``path`` belongs to registry,
    # file, Defender, and driver events), so they are not an approval gate.

    # ── 2b. UWP execution alias stub warning (flaw #3) ─────────
    all_conditions = list(ir.conditions)
    if ir.correlation:
        all_conditions.extend(cond for stage in ir.correlation.stages for cond in stage.conditions)
    for cond in all_conditions:
        if cond.field in ("name", "process.name") and cond.operator == "==":
            val_lower = str(cond.value).lower()
            suggestion = executable_aliases().get(val_lower)
            if suggestion:
                gaps.append(
                    f"Condition '{cond.field} == {cond.value}' matches a Windows UWP execution "
                    f"alias stub. Stubs execute and exit instantly and are missed by polling collectors. "
                    f"Consider matching the actual running process name instead: '{suggestion}'."
                )

    # ── 3. Check severity permissions ──────────────────────────────
    severity_perm = _SEVERITY_PERMISSIONS.get(ir.severity)
    if severity_perm and severity_perm not in context.user_permissions:
        if "approve_all_severity" not in context.user_permissions:
            gaps.append(
                f"Rule severity '{ir.severity}' requires permission "
                f"'{severity_perm}', which the current user does not have. "
                f"User permissions: {context.user_permissions}"
            )

    # ── 4. Check action permissions ────────────────────────────────
    for action in ir.response_actions:
        action_perm = _ACTION_PERMISSIONS.get(action.type)
        if action_perm and action_perm not in context.user_permissions:
            if action_perm != "create_rule":  # don't flag base permission
                gaps.append(
                    f"Action '{action.type}' requires permission "
                    f"'{action_perm}', which the current user does not have. "
                    f"User permissions: {context.user_permissions}"
                )

    return CapabilityResult(capable=len(gaps) == 0, gaps=gaps)
