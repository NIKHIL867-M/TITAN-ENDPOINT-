"""
Tests for watcher/collectors/titan_sensors.py — the bridge between CUSTOM
RULE and the 5 native TITAN ENDPOINT sensors + Correlator.

Sample JSON lines below are minimal but field-accurate reproductions of
what each endpoint's real C++ JSON builder emits (verified against
PROCESS ENDPOINT/titan_fixed/event.cpp, FILEEE/file_processor.cpp,
NETOWRK ENDPOINT/event.cpp, PORT ENDPOINT/src_usb/usb_session.cpp +
usb_monitor.cpp, APP/src/applog_decoder.cpp, and
CORRELATOR/correlation_engine.cpp), not invented shapes.
"""
import json

from watcher.collectors.titan_sensors import (
    TitanSensorCollector,
    load_source_directories,
    _SourceTailer,
    _FileBookmark,
)


def _collector() -> TitanSensorCollector:
    return TitanSensorCollector()


def _decode(source_name: str, rec: dict):
    return _collector().decode({"source_name": source_name, "line": json.dumps(rec)})


# ═══════════════════════════════════════════════════════════════════════
# load_source_directories — reuses CORRELATOR/correlator_config.txt as-is
# ═══════════════════════════════════════════════════════════════════════


def test_load_source_directories_parses_known_names_only(tmp_path):
    config = tmp_path / "correlator_config.txt"
    config.write_text(
        "# comment\n"
        "\n"
        "port=C:\\ProgramData\\TitanUSB\\logs\n"
        "process=C:\\Titan\\process\\logs\n"
        "unknown_future_source=C:\\somewhere\n",
        encoding="utf-8",
    )
    sources = load_source_directories(config)
    assert set(sources) == {"port", "process"}
    assert str(sources["port"]) == "C:\\ProgramData\\TitanUSB\\logs"


def test_load_source_directories_strips_bom(tmp_path):
    config = tmp_path / "correlator_config.txt"
    config.write_bytes(b"\xef\xbb\xbfprocess=C:\\Titan\\process\\logs\n")
    sources = load_source_directories(config)
    assert "process" in sources


def test_load_source_directories_missing_file_returns_empty(tmp_path):
    sources = load_source_directories(tmp_path / "does_not_exist.txt")
    assert sources == {}


def test_load_source_directories_adds_correlator_log_dir(tmp_path):
    config = tmp_path / "correlator_config.txt"
    config.write_text("process=C:\\Titan\\process\\logs\n", encoding="utf-8")
    sources = load_source_directories(config, correlator_log_dir="C:\\Titan\\correlator\\logs")
    assert str(sources["correlator"]) == "C:\\Titan\\correlator\\logs"


# ═══════════════════════════════════════════════════════════════════════
# decode() — Process endpoint
# ═══════════════════════════════════════════════════════════════════════


def test_decode_process_start_maps_to_process_start():
    rec = {
        "ts": "2026-08-01T00:00:00.000000Z", "event_type": "FORWARD",
        "event_subtype": "process_start", "pid": 4242, "process_name": "calc.exe",
        "canonical_path": "C:\\Windows\\System32\\calc.exe", "parent_pid": 1000,
        "parent_name": "explorer.exe", "command_line_raw": "calc.exe",
        "signature_valid": True, "integrity": "medium", "elevation": "default",
        "persistence_touched": False, "user_name": "SANTOSH", "t_unix_ms": 1234567890000,
        "log_time": "2026-08-01T00:00:00Z",
    }
    event = _decode("process", rec)
    assert event["event_type"] == "process.start"
    assert event["process"]["pid"] == 4242
    assert event["process"]["ppid"] == 1000
    assert event["process"]["name"] == "calc.exe"
    assert event["process"]["parent_name"] == "explorer.exe"
    assert event["signature_valid"] is True
    assert event["persistence_touched"] is False
    assert event["user"] == "SANTOSH"


def test_decode_process_persistence_touched_flag_survives():
    rec = {
        "event_subtype": "process_start", "pid": 55, "process_name": "reg.exe",
        "parent_pid": 1, "persistence_touched": True, "t_unix_ms": 1,
    }
    event = _decode("process", rec)
    assert event["persistence_touched"] is True


def test_decode_process_stop_maps_to_titan_namespaced_type():
    rec = {"event_subtype": "process_stop", "pid": 99, "process_name": "notepad.exe", "exit_time": "2026-08-01T00:01:00Z"}
    event = _decode("process", rec)
    assert event["event_type"] == "titan.process.stop"
    assert event["process"]["pid"] == 99


def test_decode_process_snapshot_also_maps_to_process_start():
    rec = {"event_subtype": "process_snapshot", "pid": 1, "process_name": "svchost.exe"}
    assert _decode("process", rec)["event_type"] == "process.start"


def test_decode_process_unknown_subtype_returns_none():
    assert _decode("process", {"event_subtype": "something_else"}) is None


# ═══════════════════════════════════════════════════════════════════════
# decode() — File Integrity endpoint
# ═══════════════════════════════════════════════════════════════════════


def test_decode_file_create_maps_to_file_create():
    rec = {
        "endpoint": "file_integrity", "action": "create", "path": "C:\\Temp\\evil.exe",
        "pid": 10, "tid": 11, "process": "powershell.exe", "timestamp": "2026-08-01T00:00:00Z",
        "t_unix_ms": 1, "protected": False, "executable": True, "document": False,
        "sha256": "deadbeef",
    }
    event = _decode("file_integrity", rec)
    assert event["event_type"] == "file.create"
    assert event["path"] == "C:\\Temp\\evil.exe"
    assert event["process"]["pid"] == 10
    assert event["process"]["tid"] == 11
    assert event["executable"] is True
    assert event["sha256"] == "deadbeef"


def test_decode_file_delete_maps_to_file_delete():
    rec = {"action": "delete", "path": "C:\\Temp\\a.txt", "pid": 1, "tid": 2, "process": "explorer.exe"}
    assert _decode("file_integrity", rec)["event_type"] == "file.delete"


def test_decode_file_write_maps_to_titan_file_modify():
    rec = {"action": "write", "path": "C:\\Temp\\a.txt", "pid": 1, "tid": 2, "process": "explorer.exe"}
    event = _decode("file_integrity", rec)
    assert event["event_type"] == "titan.file.modify"
    assert event["action"] == "write"


def test_decode_file_integrity_sub_record_without_action_dropped():
    # temp_related_activity / temp_lifecycle / etc. — not mapped in this pass
    assert _decode("file_integrity", {"type": "temp_related_activity", "pid": 1}) is None


# ═══════════════════════════════════════════════════════════════════════
# decode() — Network endpoint
# ═══════════════════════════════════════════════════════════════════════


def test_decode_network_connect():
    rec = {
        "ts": "2026-08-01T00:00:00Z", "event_type": "FORWARD", "record_type": "network_packet",
        "pid": 500, "process_name": "chrome.exe", "local_ip": "10.0.0.5", "local_port": 51000,
        "remote_ip": "93.184.216.34", "remote_port": 443, "protocol": "HTTPS_TLS",
    }
    event = _decode("network", rec)
    assert event["event_type"] == "network.connect"
    assert event["network"]["dest_ip"] == "93.184.216.34"
    assert event["network"]["dest_port"] == 443
    assert event["network"]["protocol"] == "HTTPS_TLS"
    assert event["process"]["pid"] == 500


def test_decode_network_dns_query():
    rec = {
        "record_type": "network_packet", "pid": 500, "process_name": "chrome.exe",
        "dns_query": "example.com", "dns_query_type": 1, "dns_answers": "93.184.216.34",
    }
    event = _decode("network", rec)
    assert event["event_type"] == "dns.query"
    assert event["query_name"] == "example.com"
    assert event["query_status"] == "success"


def test_decode_network_http():
    rec = {
        "record_type": "network_packet", "pid": 500, "process_name": "chrome.exe",
        "remote_ip": "93.184.216.34", "remote_port": 80, "local_ip": "10.0.0.5", "local_port": 51000,
        "http_method": "GET", "http_target": "/", "http_host": "example.com",
    }
    event = _decode("network", rec)
    assert event["event_type"] == "titan.network.http"
    assert event["http_method"] == "GET"


def test_decode_network_wrong_record_type_dropped():
    assert _decode("network", {"record_type": "something_else"}) is None


# ═══════════════════════════════════════════════════════════════════════
# decode() — Port (USB) endpoint
# ═══════════════════════════════════════════════════════════════════════


def test_decode_usb_hid_event():
    rec = {
        "timestamp": "2026-08-01T00:00:00Z", "endpoint": "usb_monitor", "type": "usb_hid_event",
        "event_type": "USB_HID_KEYBOARD_ARRIVED", "vid": "046D", "pid": "C31C",
        "manufacturer": "Logitech", "product": "USB Keyboard", "instance_id": "USB\\VID_046D&PID_C31C\\1",
        "raw_input_resolved": True,
    }
    event = _decode("port", rec)
    assert event["event_type"] == "titan.usb.hid_event"
    assert event["vendor_id"] == "046D"
    assert event["product_id"] == "C31C"


def test_decode_usb_injection_alert_carries_timing_evidence():
    rec = {
        "timestamp": "2026-08-01T00:00:00Z", "endpoint": "usb_monitor", "type": "usb_injection_alert",
        "vid": "1234", "pid": "5678", "instance_id": "USB\\VID_1234&PID_5678\\1",
        "hid_injection_suspected": True, "sample_count": 32,
        "mean_interval_ms": 12.0, "stddev_interval_ms": 3.0, "min_interval_ms": 8.0,
    }
    event = _decode("port", rec)
    assert event["event_type"] == "titan.usb.injection_alert"
    assert event["hid_injection_suspected"] is True
    assert event["sample_count"] == 32


def test_decode_usb_session_end_has_no_process_attribution():
    rec = {
        "timestamp": "2026-08-01T00:00:00Z", "t_unix_ms": 1, "endpoint": "usb_monitor",
        "event_type": "USB_SESSION_END", "session_id": "sess-1",
        "device": {"vid": "0951", "pid": "1666", "serial": "ABC", "manufacturer": "Kingston",
                    "product": "DataTraveler", "instance_id": "USB\\...\\1", "device_path": "\\\\?\\..."},
        "mount_point": "E:\\", "activity": {"reads": 3, "writes": 1, "deletes": 0, "executes": 0,
                                              "bytes_read": 1024, "bytes_written": 512},
        "file_extensions": {},
    }
    event = _decode("port", rec)
    assert event["event_type"] == "titan.usb.session"
    assert event["process"] is None  # USB device "pid" is a Product ID, never a process pid
    assert event["vendor_id"] == "0951"
    assert event["product_id"] == "1666"
    assert event["writes"] == 1


def test_decode_usb_collector_health_dropped():
    assert _decode("port", {"endpoint": "usb_monitor", "type": "collector_health", "status": "healthy"}) is None


# ═══════════════════════════════════════════════════════════════════════
# decode() — Application endpoint
# ═══════════════════════════════════════════════════════════════════════


def test_decode_application_log():
    rec = {
        "endpoint": "application", "type": "application_log", "source": "PowerShell",
        "event_id": "4104", "timestamp": "2026-08-01T00:00:00Z", "t_unix_ms": 1,
        "pid": 777, "tid": 1, "summary": "encoded command detected",
        "script_content": "IEX (...)", "script_path": "", "encoded_decoded": "Invoke-Expression ...",
        "network_activity": "", "pattern_hits": 2, "credential_access": False,
        "amsi_bypass": True, "process_injection": False, "content_truncated": False,
    }
    event = _decode("application", rec)
    assert event["event_type"] == "titan.application.detection"
    assert event["amsi_bypass"] is True
    assert event["process"]["pid"] == 777


def test_decode_application_without_pid_has_no_process_block():
    rec = {"type": "application_log", "source": "WMI", "event_id": "1", "summary": "x"}
    event = _decode("application", rec)
    assert event["process"] is None


# ═══════════════════════════════════════════════════════════════════════
# decode() — Correlator
# ═══════════════════════════════════════════════════════════════════════


def test_decode_correlator_session_timeline():
    rec = {
        "type": "session_timeline", "t_unix_ms": 123,
        "members": [
            {"endpoint": "process", "record_type": "FORWARD", "t_unix_ms": 100, "pid": 1, "parent_pid": 0},
            {"endpoint": "file_integrity", "record_type": "", "t_unix_ms": 101, "pid": 1, "parent_pid": 0},
        ],
    }
    event = _decode("correlator", rec)
    assert event["event_type"] == "titan.correlator.session_timeline"
    assert len(event["members"]) == 2


def test_decode_correlator_health_dropped():
    assert _decode("correlator", {"type": "collector_health", "status": "healthy"}) is None


# ═══════════════════════════════════════════════════════════════════════
# decode() — malformed input never raises
# ═══════════════════════════════════════════════════════════════════════


def test_decode_malformed_json_returns_none():
    assert _collector().decode({"source_name": "process", "line": "{not json"}) is None


def test_decode_non_object_json_returns_none():
    assert _collector().decode({"source_name": "process", "line": "[1,2,3]"}) is None


def test_decode_unknown_source_returns_none():
    assert _collector().decode({"source_name": "made_up_source", "line": "{}"}) is None


# ═══════════════════════════════════════════════════════════════════════
# _SourceTailer — incremental byte-offset tailing
# ═══════════════════════════════════════════════════════════════════════


def test_source_tailer_reads_only_new_lines_across_calls(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    bookmark_dir = tmp_path / "bookmarks"
    log_file = log_dir / "titan_process_0001.jsonl"
    log_file.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")

    tailer = _SourceTailer("process", log_dir, bookmark_dir)
    first = tailer.read_new_lines()
    assert first == ['{"a":1}', '{"a":2}']

    # Nothing new yet.
    assert tailer.read_new_lines() == []

    with open(log_file, "a", encoding="utf-8") as f:
        f.write('{"a":3}\n')
    assert tailer.read_new_lines() == ['{"a":3}']


def test_source_tailer_holds_back_partial_line(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_file = log_dir / "titan_process_0001.jsonl"
    log_file.write_text('{"a":1}\n{"partial":', encoding="utf-8")

    tailer = _SourceTailer("process", log_dir, tmp_path / "bookmarks")
    assert tailer.read_new_lines() == ['{"a":1}']

    with open(log_file, "a", encoding="utf-8") as f:
        f.write('true}\n')
    assert tailer.read_new_lines() == ['{"partial":true}']


def test_source_tailer_ignores_files_not_matching_hint(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "unrelated.txt").write_text('{"a":1}\n', encoding="utf-8")

    tailer = _SourceTailer("process", log_dir, tmp_path / "bookmarks")  # hint = "titan_"
    assert tailer.read_new_lines() == []


def test_source_tailer_survives_missing_directory(tmp_path):
    tailer = _SourceTailer("process", tmp_path / "does_not_exist", tmp_path / "bookmarks")
    assert tailer.read_new_lines() == []


def test_source_tailer_flush_bookmarks_forces_all_pending_saves(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    bookmark_dir = tmp_path / "bookmarks"
    log_file = log_dir / "titan_process_0001.jsonl"
    log_file.write_text('{"a":1}\n', encoding="utf-8")

    tailer = _SourceTailer("process", log_dir, bookmark_dir)
    tailer.read_new_lines()  # first save goes through immediately

    with open(log_file, "a", encoding="utf-8") as f:
        f.write('{"a":2}\n')
    tailer.read_new_lines()  # second save is debounced -- stays pending

    tailer.flush_bookmarks()
    key = "titan_process_0001.jsonl"
    persisted_offset, _ = tailer._bookmarks[key].load()
    assert persisted_offset == log_file.stat().st_size, "flush must persist the latest offset, not the debounced-away one"


def test_source_tailer_persists_offset_across_instances(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    bookmark_dir = tmp_path / "bookmarks"
    log_file = log_dir / "titan_process_0001.jsonl"
    log_file.write_text('{"a":1}\n', encoding="utf-8")

    tailer1 = _SourceTailer("process", log_dir, bookmark_dir)
    assert tailer1.read_new_lines() == ['{"a":1}']

    with open(log_file, "a", encoding="utf-8") as f:
        f.write('{"a":2}\n')

    # A brand-new tailer instance (simulating a watcher restart) must not
    # re-emit the line already consumed before restart.
    tailer2 = _SourceTailer("process", log_dir, bookmark_dir)
    assert tailer2.read_new_lines() == ['{"a":2}']


# ═══════════════════════════════════════════════════════════════════════
# _FileBookmark
# ═══════════════════════════════════════════════════════════════════════


def test_file_bookmark_round_trips_offset(tmp_path):
    bookmark = _FileBookmark(tmp_path, "process", "titan_process_0001.jsonl")
    assert bookmark.load() == (0, None)
    bookmark.save(1234, 987)
    assert _FileBookmark(tmp_path, "process", "titan_process_0001.jsonl").load() == (1234, 987)


def test_file_bookmark_missing_file_defaults_to_zero(tmp_path):
    assert _FileBookmark(tmp_path, "x", "y.jsonl").load() == (0, None)


def test_file_bookmark_debounces_rapid_saves(tmp_path):
    """
    Regression for the observed-live feedback loop: File Integrity saw this
    collector's OWN bookmark writes as file activity, which grew the very
    log this collector tails, triggering more saves -- measured at ~48% of
    FIM's entire log volume. Rapid successive saves within the debounce
    window must only actually write to disk once.
    """
    bookmark = _FileBookmark(tmp_path, "file_integrity", "fim_events.json")
    bookmark.save(100, 1)  # first save always goes through (no prior save time)
    first_mtime = bookmark._path.stat().st_mtime_ns

    bookmark.save(200, 1)  # within the debounce window -- must NOT hit disk
    bookmark.save(300, 1)
    assert bookmark._path.stat().st_mtime_ns == first_mtime, "debounced saves must not write to disk"
    # But the in-memory pending value is remembered for the eventual flush.
    assert bookmark._pending_offset == 300


def test_file_bookmark_flush_forces_pending_save(tmp_path):
    bookmark = _FileBookmark(tmp_path, "file_integrity", "fim_events.json")
    bookmark.save(100, 1)
    bookmark.save(999, 42)  # debounced -- not yet on disk
    assert bookmark.load() == (100, 1)

    bookmark.flush()
    assert bookmark.load() == (999, 42)


def test_file_bookmark_flush_is_a_noop_with_nothing_pending(tmp_path):
    bookmark = _FileBookmark(tmp_path, "x", "y.jsonl")
    bookmark.flush()  # must not raise or create a file out of nothing
    assert not bookmark._path.exists()


# ═══════════════════════════════════════════════════════════════════════
# _SourceTailer — file-identity (filename reuse) + bounded partial line
# ═══════════════════════════════════════════════════════════════════════


def test_source_tailer_detects_filename_reused_by_a_different_file(tmp_path):
    """A persisted offset from a PREVIOUS watcher run must not be replayed
    against a NEW file that happens to reuse the same filename."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    bookmark_dir = tmp_path / "bookmarks"
    log_file = log_dir / "titan_process_0001.jsonl"
    log_file.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")

    tailer1 = _SourceTailer("process", log_dir, bookmark_dir)
    assert tailer1.read_new_lines() == ['{"a":1}', '{"a":2}']

    # Simulate the old file being deleted and a NEW, unrelated file created
    # with the identical name (different file identity on disk).
    log_file.unlink()
    log_file.write_text('{"b":1}\n', encoding="utf-8")

    tailer2 = _SourceTailer("process", log_dir, bookmark_dir)
    # Must read the new file's content from the start, not skip it as
    # "already consumed" based on the stale byte offset.
    assert tailer2.read_new_lines() == ['{"b":1}']


def test_source_tailer_detects_filename_reused_mid_session(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_file = log_dir / "titan_process_0001.jsonl"
    log_file.write_text('{"a":1}\n', encoding="utf-8")

    tailer = _SourceTailer("process", log_dir, tmp_path / "bookmarks")
    assert tailer.read_new_lines() == ['{"a":1}']

    log_file.unlink()
    log_file.write_text('{"b":1}\n', encoding="utf-8")
    assert tailer.read_new_lines() == ['{"b":1}']


def test_source_tailer_drops_partial_line_past_bound(tmp_path, monkeypatch):
    import watcher.collectors.titan_sensors as titan_sensors_mod
    monkeypatch.setattr(titan_sensors_mod, "_MAX_PARTIAL_BYTES", 16)

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_file = log_dir / "titan_process_0001.jsonl"
    log_file.write_text("x" * 100, encoding="utf-8")  # no newline at all

    tailer = _SourceTailer("process", log_dir, tmp_path / "bookmarks")
    lines = tailer.read_new_lines()
    assert lines == []  # nothing complete yet
    assert tailer._partial["titan_process_0001.jsonl"] == ""  # dropped, not accumulated
    assert tailer._partial_dropped == 1
