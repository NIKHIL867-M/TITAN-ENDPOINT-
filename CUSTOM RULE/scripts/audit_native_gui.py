"""Render and verify every GEKKO tab against the live local API."""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from native_gui import GEKKO_STYLE, MainWindow


def wait_until(app: QApplication, predicate, timeout_ms: int = 12_000) -> bool:
    elapsed = 0
    while elapsed < timeout_ms:
        app.processEvents()
        if predicate():
            return True
        QTest.qWait(100)
        elapsed += 100
    return False


def main() -> None:
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(GEKKO_STYLE)
    window = MainWindow("http://127.0.0.1:8765")
    window.resize(1320, 880); window.show()

    assert wait_until(app, lambda: bool(window.schema) and hasattr(window, "coverage_data") and hasattr(window, "history_data") and hasattr(window, "alert_data")), "initial API data did not load"
    assert wait_until(app, lambda: window.runtime_label.text() != "RUNTIME: CHECKING"), "runtime status did not load"

    results = {
        "rule_authoring": {
            "schema_events": window.event_combo.count(),
            "review_modes": window.review_tabs.count(),
            "approve_locked_initially": not window.approve_button.isEnabled(),
        },
        "watcher_coverage": {
            "rows": window.coverage_table.rowCount(),
            "details_present": bool(window.coverage_details.toPlainText()),
            "summary": window.coverage_summary.text(),
        },
        "approved_rules": {
            "visible": window.history_list.count(),
            "total": getattr(window, "history_total", 0),
            "delete_requires_selection": not window.delete_rule_button.isEnabled(),
        },
        "matched_evidence": {"alerts": window.alert_list.count()},
        "watcher_activity": {
            "rows": window.activity_table.rowCount(),
            "runtime": window.runtime_label.text(),
        },
        "response_outcomes": {"rows": window.outcome_table.rowCount()},
    }

    assert results["rule_authoring"]["schema_events"] > 0
    assert results["rule_authoring"]["review_modes"] == 3
    assert results["watcher_coverage"]["rows"] > 0
    assert results["watcher_coverage"]["details_present"]
    assert results["approved_rules"]["visible"] == min(100, results["approved_rules"]["total"])
    assert results["matched_evidence"]["alerts"] == results["response_outcomes"]["rows"]
    assert "CHECKING" not in results["watcher_activity"]["runtime"]

    output = ROOT / "data" / "gui_audit"
    output.mkdir(parents=True, exist_ok=True)
    for index in range(window.main_tabs.count()):
        window.main_tabs.setCurrentIndex(index); QTest.qWait(150); app.processEvents()
        window.grab().save(str(output / f"tab_{index + 1}.png"))

    if window.alert_list.count():
        window.main_tabs.setCurrentIndex(3); window.alert_list.setCurrentRow(0)
        assert wait_until(app, lambda: window.evidence_detail.toPlainText() not in {"", "Loading evidence..."}), "selected evidence did not resolve"
        results["matched_evidence"]["selection_resolved"] = True
        detail = window.evidence_detail.toPlainText()
        selected = window.alert_data[0] if window.alert_data else {}
        if selected.get("rule_text", "").startswith("Alert if Command Prompt"):
            assert "CORRELATION STAGES (3 contributing events)" in detail
            assert all(f"Stage {index}: process.start" in detail for index in (1, 2, 3))
            results["matched_evidence"]["correlation_stages_visible"] = True

    print(results)
    window.close(); window.pool.waitForDone(5_000); app.processEvents()


if __name__ == "__main__":
    main()
