"""
Context builder (execute.txt §5).

Assembles deployment context fresh for every rule-parse request. This is
what grounds the LLM — without it, the model would invent fields,
operators, and actions that don't exist in the deployment.

Returns a Pydantic model, not a plain dict, so the shape is enforced at
the type level rather than assumed.

In production, the reference data below would come from the capability
manager's state (v5 §4) or a config store. For this v1, it's a
well-typed constant that can be swapped later without changing the
interface.
"""


import json
from pathlib import Path
from pydantic import BaseModel


from shared.action_types import ActionType


# Event-specific field metadata used by validation and the editable review UI.
# Keep this backend-owned so the browser cannot construct combinations that the
# deployed rule engine does not understand.
EVENT_FIELD_TYPES: dict[str, dict[str, str]] = {
    "process.start": {
        "pid": "integer", "ppid": "integer", "name": "string",
        "command_line": "string", "parent_name": "string", "hash": "string",
        "user": "string", "host": "string", "is_launcher_shim": "boolean", "shim_target": "string",
    },
    "auth.login_success": {"username": "string", "source_ip": "string", "result": "string", "method": "string", "host": "string"},
    "auth.login_failure": {"username": "string", "source_ip": "string", "result": "string", "method": "string", "host": "string"},
    "auth.runas": {"username": "string", "source_ip": "string", "result": "string", "method": "string", "host": "string"},
    "network.connect": {"dest_ip": "string", "dest_port": "integer", "src_ip": "string", "src_port": "integer", "protocol": "string", "name": "string", "pid": "integer", "host": "string"},
    "service.install": {"name": "string", "service_name": "string", "image_path": "string", "user": "string", "host": "string"},
    "service.state_change": {"name": "string", "service_name": "string", "state": "string", "host": "string"},
    "file.create": {"path": "string", "name": "string", "pid": "integer", "user": "string", "host": "string"},
    "registry.set": {"path": "string", "value_name": "string", "value": "string", "pid": "integer", "user": "string", "host": "string"},
    "image.load": {"name": "string", "path": "string", "hash": "string", "pid": "integer", "host": "string"},
    "registry.change": {"path": "string", "value_name": "string", "change_type": "string", "old_hash": "string", "new_hash": "string", "host": "string"},
    "inventory.change": {"category": "string", "item": "string", "change_type": "string", "old_hash": "string", "new_hash": "string", "host": "string"},
    "file.audit": {"path": "string", "access_mask": "string", "user_sid": "string", "username": "string", "process_name": "string", "pid": "integer", "host": "string"},
    "dns.query": {"query_name": "string", "query_status": "string", "query_results": "string", "name": "string", "pid": "integer", "host": "string"},
    "powershell.script_block": {"script_text": "string", "script_block_id": "string", "path": "string", "host": "string"},
    "credential.access_attempt": {"source_process.name": "string", "target_process.name": "string", "granted_access": "string", "host": "string"},
    "process.access": {"source_process.name": "string", "target_process.name": "string", "granted_access": "string", "host": "string"},
    "task.create": {"task_name": "string", "task_path": "string", "command": "string", "user": "string", "host": "string"},
    "task.update": {"task_name": "string", "task_path": "string", "command": "string", "user": "string", "host": "string"},
    "task.delete": {"task_name": "string", "task_path": "string", "user": "string", "host": "string"},
    "task.run": {"task_name": "string", "command": "string", "user": "string", "host": "string"},
    "wmi.persistence": {"operation": "string", "name": "string", "query": "string", "destination": "string", "host": "string"},
    "usb.device_connect": {"device_name": "string", "device_id": "string", "vendor_id": "string", "product_id": "string", "host": "string"},
    "usb.device_query": {"device_name": "string", "device_id": "string", "vendor_id": "string", "product_id": "string", "host": "string"},
    "firewall.rule_change": {"rule_name": "string", "operation": "string", "host": "string"},
    "file.delete": {"path": "string", "name": "string", "pid": "integer", "host": "string"},
    "named_pipe.create": {"pipe_name": "string", "name": "string", "pid": "integer", "host": "string"},
    "named_pipe.connect": {"pipe_name": "string", "name": "string", "pid": "integer", "host": "string"},
    "driver.load": {"path": "string", "hash": "string", "signed": "string", "signature": "string", "signature_status": "string", "host": "string"},
    "process.tamper": {"name": "string", "pid": "integer", "tamper_type": "string", "host": "string"},
    "defender.detection": {"threat_name": "string", "severity": "string", "category": "string", "path": "string", "status": "string", "host": "string"},
    "defender.remediation": {"threat_name": "string", "severity": "string", "category": "string", "path": "string", "action": "string", "status": "string", "host": "string"},
    # ── titan_sensors: the 5 native TITAN ENDPOINT C++ sensors + Correlator ──
    "titan.process.stop": {"pid": "integer", "name": "string", "exit_time": "string", "host": "string"},
    "titan.file.modify": {"path": "string", "old_path": "string", "action": "string", "pid": "integer", "process_name": "string", "protected": "boolean", "executable": "boolean", "document": "boolean", "sha256": "string", "hash_status": "string", "host": "string"},
    "titan.network.http": {"http_method": "string", "http_target": "string", "http_host": "string", "http_status_code": "integer", "http_reason": "string", "dest_ip": "string", "dest_port": "integer", "pid": "integer", "host": "string"},
    "titan.usb.session": {"session_id": "string", "vendor_id": "string", "product_id": "string", "device_name": "string", "device_id": "string", "mount_point": "string", "reads": "integer", "writes": "integer", "deletes": "integer", "executes": "integer", "bytes_written": "integer", "host": "string"},
    "titan.usb.hid_event": {"vendor_id": "string", "product_id": "string", "device_name": "string", "device_id": "string", "manufacturer": "string", "raw_input_resolved": "boolean", "host": "string"},
    "titan.usb.injection_alert": {"vendor_id": "string", "product_id": "string", "device_id": "string", "hid_injection_suspected": "boolean", "sample_count": "integer", "mean_interval_ms": "integer", "stddev_interval_ms": "integer", "host": "string"},
    "titan.application.detection": {"source": "string", "event_id": "string", "summary": "string", "script_content": "string", "script_path": "string", "encoded_decoded": "string", "network_activity": "string", "pattern_hits": "integer", "credential_access": "boolean", "amsi_bypass": "boolean", "process_injection": "boolean", "pid": "integer", "host": "string"},
    "titan.correlator.session_timeline": {"host": "string"},
}

# process.start also carries these TITAN-only extras when produced by
# titan_sensors (not by wmi/security/sysmon) — additive, harmless to list
# here since a field only matters when the active collector actually sets it.
EVENT_FIELD_TYPES["process.start"].update({
    "signature_valid": "boolean",
    "integrity": "string",
    "elevation": "string",
    "persistence_touched": "boolean",
})

OPERATORS_BY_FIELD_TYPE: dict[str, list[str]] = {
    "string": ["==", "!=", "contains", "not_contains", "starts_with", "ends_with", "regex", "is_public_ip"],
    "integer": ["==", "!=", ">", ">=", "<", "<="],
    "boolean": ["==", "!="],
}

EVENT_COLLECTORS: dict[str, list[str]] = {
    "process.start": ["wmi", "security", "sysmon", "titan_sensors"],
    "auth.login_success": ["security"],
    "auth.login_failure": ["security"],
    "auth.runas": ["security"],
    "network.connect": ["sysmon", "titan_sensors"],
    "service.install": ["system", "security"],
    "service.state_change": ["system"],
    "file.create": ["sysmon", "titan_sensors"],
    "registry.set": ["sysmon"],
    "image.load": ["sysmon"],
    "registry.change": ["registry_fim"],
    "inventory.change": ["inventory"],
    "file.audit": ["security"],
    "dns.query": ["sysmon", "titan_sensors"], "powershell.script_block": ["powershell"],
    "credential.access_attempt": ["sysmon"],
    "process.access": ["sysmon"],
    "task.create": ["scheduled_tasks"], "task.update": ["scheduled_tasks"], "task.delete": ["scheduled_tasks"], "task.run": ["scheduled_tasks"],
    "wmi.persistence": ["sysmon"], "usb.device_connect": ["usb"], "usb.device_query": ["usb"],
    "firewall.rule_change": ["firewall"], "file.delete": ["sysmon", "titan_sensors"],
    "named_pipe.create": ["sysmon"], "named_pipe.connect": ["sysmon"],
    "driver.load": ["sysmon"], "process.tamper": ["sysmon"],
    "defender.detection": ["defender"], "defender.remediation": ["defender"],
    # ── titan_sensors-only event types ──
    "titan.process.stop": ["titan_sensors"],
    "titan.file.modify": ["titan_sensors"],
    "titan.network.http": ["titan_sensors"],
    "titan.usb.session": ["titan_sensors"],
    "titan.usb.hid_event": ["titan_sensors"],
    "titan.usb.injection_alert": ["titan_sensors"],
    "titan.application.detection": ["titan_sensors"],
    "titan.correlator.session_timeline": ["titan_sensors"],
}


class DeploymentContext(BaseModel):
    """Typed representation of the deployment context sent to the LLM."""

    os: str
    installed_collectors: list[str]
    selected_log_sources: list[str]
    supported_fields: dict[str, list[str]]
    supported_operators: list[str]
    supported_actions: list[str]
    user_permissions: list[str]
    agent_status: dict | None = None


# ── Reference context from the spec ────────────────────────────────────
# This is the single source of truth for what this deployment supports.
# The prompt builder injects this verbatim, and the semantic validator +
# capability checker cross-reference against it.

_DEFAULT_CONTEXT = DeploymentContext(
    os="windows",
    # Matches the actual COLLECTOR_REGISTRY in watcher/collectors/__init__.py
    installed_collectors=["security", "system", "sysmon", "wmi", "registry_fim", "inventory", "powershell", "scheduled_tasks", "usb", "firewall", "defender", "titan_sensors"],
    selected_log_sources=["process", "authentication", "network"],
    supported_fields={
        "process": [
            "pid",
            "ppid",
            "name",
            "command_line",
            "parent_name",
            "hash",
            "is_launcher_shim",
            "shim_target",
        ],
        "authentication": [
            "username",
            "source_ip",
            "result",
            "method",
        ],
        "network": [
            "pid",
            "name",
            "dest_ip",
            "dest_port",
            "src_ip",
            "src_port",
            "protocol",
        ],
        "registry_integrity": ["path", "value_name", "change_type", "old_hash", "new_hash"],
        "inventory": ["category", "item", "change_type", "old_hash", "new_hash"],
        "file_audit": ["path", "access_mask", "user_sid", "username", "process_name", "pid"],
    },
    supported_operators=sorted({op for values in OPERATORS_BY_FIELD_TYPE.values() for op in values}),
    # ── Aligned to shared/action_types.py ActionType enum ──
    supported_actions=[e.value for e in ActionType],
    user_permissions=[
        "create_rule",
        "execute_kill_process",
        # FOUND LIVE (real, previously-unknown gap): execute_isolate_host was missing here while
        # execute_kill_process was present, so capability_checker.py rejected every isolate_host
        # rule at approval time with "requires permission 'execute_isolate_host'" -- even though the
        # wizard's own Stage 4 UI fully supports selecting isolate_host and confirming it as a
        # destructive action, and watcher/action_engine.py fully implements it with its own
        # dedicated, heavily-guarded runtime path (self-isolation block, verified-local-host check,
        # active-management-session refusal, circuit breaker). Nothing in this codebase's tests or
        # history treats the missing permission itself as intentional policy -- it reads as an
        # oversight relative to execute_kill_process, not a deliberate "isolate can never be
        # authored" restriction. Granting authoring permission here does not weaken runtime safety:
        # action_engine._do_isolate_host's self-isolation guard still refuses to actually isolate
        # this (single-host) deployment unless WATCHER_ALLOW_SELF_ISOLATE=true is explicitly set,
        # which it is not by default.
        "execute_isolate_host",
        "approve_low_severity",
        "approve_medium_severity",
        "approve_high_severity",
    ],
)


def build_context() -> DeploymentContext:
    """
    Build deployment context for the current request.

    Reads the live agent status from data/collector_status.json if present
    to align Layer 2 validation with active Layer 4/8 capabilities.
    """
    ctx = _DEFAULT_CONTEXT.model_copy()
    status_file = Path(__file__).resolve().parent.parent / "data" / "collector_status.json"
    if status_file.exists():
        try:
            with open(status_file, "r", encoding="utf-8") as f:
                ctx.agent_status = json.load(f)
        except Exception:
            # Non-blocking, keep default None status
            pass
    return ctx
