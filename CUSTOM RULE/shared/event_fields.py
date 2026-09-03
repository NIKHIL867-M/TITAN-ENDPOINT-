"""Canonical IR field aliases used by the runtime matcher.

Event-specific validity remains described by app.context_builder.EVENT_FIELD_TYPES;
this module owns the cross-process canonicalization that turns those public IR
names into normalized event paths.
"""

IR_FIELD_PATHS: dict[str, str] = {
    "name": "process.name", "command_line": "process.command_line",
    "pid": "process.pid", "ppid": "process.ppid", "process_name": "process.name",
    "is_launcher_shim": "process.is_launcher_shim", "shim_target": "process.shim_target",
    "dest_ip": "network.dest_ip", "dest_port": "network.dest_port",
    "src_ip": "network.src_ip", "src_port": "network.src_port",
    "host": "host", "user": "user", "event_type": "event_type", "timestamp": "timestamp",
}

PLUGIN_FIELD_BLOCKS = ("process", "network", "registry", "inventory", "file_audit", "raw")
