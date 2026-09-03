"""Native GEKKO desktop interface for the Windows IR application."""
from __future__ import annotations

import json
import os
import random
import socket
import urllib.error
import urllib.request
import urllib.parse
from datetime import datetime
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, QSignalBlocker, Qt, QThreadPool, Signal, QTimer
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QCheckBox, QComboBox, QFormLayout, QGridLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
    QHeaderView, QPushButton, QSpinBox, QSplitter, QTabWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)


GEKKO_STYLE = """
QWidget { background:transparent; color:#b8ffd0; font-family:'Segoe UI'; font-size:13px; }
QMainWindow { background:#010704; }
QTabWidget::pane { background:rgba(2,8,6,224); border:1px solid #145c31; }
QWidget#contentPage { background:rgba(2,8,6,218); }
QGroupBox { border:1px solid #126b36; border-radius:7px; margin-top:12px; padding:12px; font-weight:600; color:#49ff84; }
QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 5px; }
QLineEdit, QTextEdit, QComboBox, QSpinBox, QTableWidget, QListWidget {
  background:#03120b; color:#caffd8; border:1px solid #145c31; border-radius:5px;
  selection-background-color:#0f6b35; padding:6px;
}
QComboBox QAbstractItemView { background:#03120b; color:#caffd8; selection-background-color:#0f6b35; }
QPushButton { background:#082a18; color:#65ff98; border:1px solid #1aa34e; border-radius:5px; padding:8px 14px; font-weight:600; }
QPushButton:hover { background:#0d4325; border-color:#54ff87; }
QPushButton:disabled { color:#416b4d; border-color:#23442e; background:#07120b; }
QPushButton#danger { color:#ff8a8a; border-color:#a53a3a; background:#2a0d0d; }
QPushButton#primary { background:#0a4d27; }
QTabBar::tab { background:#06150d; color:#71c98d; border:1px solid #145c31; padding:9px 16px; }
QTabBar::tab:selected { background:#0b3b20; color:#69ff99; }
QHeaderView::section { background:#082a18; color:#69ff99; border:1px solid #145c31; padding:5px; }
QLabel#title { color:#54ff87; font-size:25px; font-weight:700; }
QLabel#subtitle { color:#67a77b; }
QLabel#ok { color:#54ff87; font-weight:600; }
QLabel#warn { color:#ffd166; font-weight:600; }
QLabel#error { color:#ff7070; font-weight:600; }
QProgressBar { background:#03120b; border:1px solid #145c31; height:5px; }
QProgressBar::chunk { background:#36ff78; }
QCheckBox { spacing:7px; }
QLabel#matched { color:#ffe066; font-weight:700; }
QLabel#alerted { color:#4cc9ff; font-weight:700; }
QLabel#acted { color:#ff9f43; font-weight:700; }
"""


class GekkoBackdrop(QWidget):
    """Visible, lightweight digital rain with bounded CPU and no image assets."""
    GLYPHS = "01ABCDEFGHIJKLMNOPQRSTUVWXYZ#$%&*+<>"

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("matrixRoot")
        self._drops: list[int] = []
        self._timer = QTimer(self); self._timer.setInterval(75); self._timer.timeout.connect(self._tick); self._timer.start()

    def _tick(self) -> None:
        columns = max(1, self.width() // 24)
        if len(self._drops) != columns:
            self._drops = [random.randint(-35, 0) for _ in range(columns)]
        for index in range(columns):
            self._drops[index] += 1
            if self._drops[index] * 22 > self.height() and random.random() < 0.08:
                self._drops[index] = random.randint(-25, -2)
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(1, 7, 4))
        painter.setFont(QFont("Consolas", 10))
        for column, head in enumerate(self._drops):
            x = column * 24 + 7
            for trail in range(12):
                y = (head - trail) * 22
                if 0 <= y <= self.height():
                    alpha = max(18, 118 - trail * 9)
                    painter.setPen(QColor(30, 255, 105, alpha))
                    painter.drawText(x, y, random.choice(self.GLYPHS))
        painter.end()


def api_call(base_url: str, method: str, path: str, payload: dict | None = None, timeout: float = 45) -> dict:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("GEKKO_API_TOKEN")
    if token:
        headers["X-GEKKO-Token"] = token
    request = urllib.request.Request(
        base_url + path, data=body, method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8"))
        except Exception:
            detail = {"detail": str(exc)}
        raise RuntimeError(_error_text(detail)) from exc
    except (TimeoutError, socket.timeout) as exc:
        raise RuntimeError("Rule service timed out. Check the internet/model service and retry; the watcher remains active.") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach the local GEKKO service: {exc.reason}") from exc


def _error_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, list):
        return "; ".join(_error_text(item) for item in payload)
    if isinstance(payload, dict):
        detail = payload.get("detail", payload)
        if detail is not payload:
            return _error_text(detail)
        messages = payload.get("messages")
        if messages:
            label = str(payload.get("error", "Validation failed")).replace("_", " ")
            return f"{label}: {_error_text(messages)}"
        if payload.get("error"):
            return _error_text(payload["error"])
        return json.dumps(payload, ensure_ascii=False)
    return str(payload)


def _local_time(value: str, include_date: bool = False) -> str:
    """Render an ISO timestamp in the computer's local timezone."""
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone()
        pattern = "%Y-%m-%d %H:%M:%S %Z" if include_date else "%H:%M:%S %Z"
        return parsed.strftime(pattern).strip()
    except (TypeError, ValueError):
        return value


class WorkerSignals(QObject):
    success = Signal(object)
    failure = Signal(str)


class ApiWorker(QRunnable):
    def __init__(self, operation: Callable[[], Any]) -> None:
        super().__init__()
        self.operation = operation
        self.signals = WorkerSignals()

    def run(self) -> None:
        try:
            self.signals.success.emit(self.operation())
        except Exception as exc:
            self.signals.failure.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url.rstrip("/")
        self.pool = QThreadPool.globalInstance()
        # Polling needs only a few workers. Bounding this avoids reserving a
        # thread stack for every CPU on high-core systems.
        self.pool.setMaxThreadCount(4)
        self._workers: set[ApiWorker] = set()
        self.current_result: dict | None = None
        self.original_draft: dict | None = None
        self.current_draft: dict | None = None
        self.schema: dict = {}
        self.draft_validated = False
        self.edit_mode: str | None = None
        self._loading_editor = False
        self._live_activity = True
        self._initial_alert_load = True
        self._runtime_pending = False
        self._alerts_pending = False
        self._activity_pending = False
        self._coverage_pending = False
        self._history_pending = False
        self._activity_fingerprint: str | None = None
        self.setWindowTitle("GEKKO // Windows Rule Monitor")
        self.resize(1320, 880)
        self.setMinimumSize(980, 680)
        self.setCentralWidget(self._build_ui())
        self.health_timer = QTimer(self); self.health_timer.setInterval(2500); self.health_timer.timeout.connect(self.refresh_runtime); self.health_timer.start()
        self.alert_timer = QTimer(self); self.alert_timer.setInterval(4000); self.alert_timer.timeout.connect(self.load_alerts); self.alert_timer.start()
        self._load_initial_data()

    def _build_ui(self) -> QWidget:
        root = GekkoBackdrop()
        layout = QVBoxLayout(root)
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("GEKKO")
        title.setObjectName("title")
        subtitle = QLabel("Natural-language Windows detection, evidence, and response")
        subtitle.setObjectName("subtitle")
        title_box.addWidget(title); title_box.addWidget(subtitle)
        header.addLayout(title_box); header.addStretch()
        self.agent_badge = QLabel("AGENT: CHECKING")
        self.agent_badge.setObjectName("warn")
        header.addWidget(self.agent_badge)
        layout.addLayout(header)
        self.alert_banner = QLabel(""); self.alert_banner.setObjectName("alerted"); self.alert_banner.setWordWrap(True); self.alert_banner.hide(); layout.addWidget(self.alert_banner)
        self.global_status = QLabel("Connecting to the local service...")
        self.global_status.setObjectName("warn"); self.global_status.setWordWrap(True); layout.addWidget(self.global_status)

        self.main_tabs = QTabWidget()
        self.main_tabs.addTab(self._build_author_tab(), "RULE AUTHORING")
        self.main_tabs.addTab(self._build_coverage_tab(), "WATCHER COVERAGE")
        self.main_tabs.addTab(self._build_history_tab(), "APPROVED RULES")
        self.main_tabs.addTab(self._build_evidence_tab(), "MATCHED EVIDENCE")
        self.main_tabs.addTab(self._build_activity_tab(), "WATCHER ACTIVITY")
        self.main_tabs.addTab(self._build_outcomes_tab(), "RESPONSE OUTCOMES")
        self.main_tabs.currentChanged.connect(self._main_tab_changed)
        layout.addWidget(self.main_tabs, 1)
        self._main_tab_changed(self.main_tabs.currentIndex())
        return root

    def _build_author_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        input_group = QGroupBox("ENGLISH RULE")
        input_layout = QVBoxLayout(input_group)
        self.rule_input = QTextEdit()
        self.rule_input.setMaximumHeight(115)
        self.rule_input.setPlaceholderText("Describe any Windows event condition, investigation, and response...")
        input_layout.addWidget(self.rule_input)
        buttons = QHBoxLayout()
        self.parse_button = QPushButton("PARSE + SIMULATE")
        self.parse_button.setObjectName("primary")
        self.parse_button.clicked.connect(self.parse_rule)
        buttons.addWidget(self.parse_button)
        buttons.addStretch()
        input_layout.addLayout(buttons); layout.addWidget(input_group)

        retrieval_group = QGroupBox("RETRIEVED AUTHORING GUIDANCE")
        retrieval_layout = QVBoxLayout(retrieval_group)
        self.retrieval_view = QTextEdit()
        self.retrieval_view.setReadOnly(True)
        self.retrieval_view.setMaximumHeight(125)
        self.retrieval_view.setPlaceholderText(
            "Relevant live schemas, rule patterns, and platform caveats will appear here."
        )
        retrieval_layout.addWidget(self.retrieval_view)
        layout.addWidget(retrieval_group)

        self.review_tabs = QTabWidget()
        self.readonly_view = QTextEdit(); self.readonly_view.setReadOnly(True)
        self.review_tabs.addTab(self.readonly_view, "BEGINNER / READ ONLY")
        self.review_tabs.addTab(self._build_guided_editor(), "INTERMEDIATE / GUIDED")
        self.expert_editor = QTextEdit()
        self.expert_editor.setFont(QFont("Consolas", 10))
        self.expert_editor.textChanged.connect(lambda: self._mark_dirty("expert"))
        self.review_tabs.addTab(self.expert_editor, "EXPERT / JSON")
        layout.addWidget(self.review_tabs, 1)

        response_group = QGroupBox("HUMAN RESPONSE APPROVAL")
        response_layout = QHBoxLayout(response_group)
        self.action_checks: dict[str, QCheckBox] = {}
        for action, label in (("alert", "Alert"), ("kill_process", "Kill process"), ("isolate_host", "Isolate host")):
            checkbox = QCheckBox(label)
            checkbox.stateChanged.connect(self._actions_changed)
            self.action_checks[action] = checkbox
            response_layout.addWidget(checkbox)
        response_layout.addStretch()
        self.recheck_button = QPushButton("RE-VALIDATE + SIMULATE")
        self.recheck_button.clicked.connect(self.recheck_draft)
        self.approve_button = QPushButton("APPROVE RULE")
        self.approve_button.setEnabled(False)
        self.approve_button.clicked.connect(self.approve_rule)
        response_layout.addWidget(self.recheck_button); response_layout.addWidget(self.approve_button)
        layout.addWidget(response_group)
        self.author_status = QLabel("Enter a rule to begin.")
        self.author_status.setWordWrap(True)
        layout.addWidget(self.author_status)
        return page

    def _build_activity_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        info = QLabel("Bounded, sanitized watcher diagnostics. This proves whether a real event was observed, a rule matched, and an alert/evidence record was saved; it does not retain unmatched raw logs.")
        info.setWordWrap(True); layout.addWidget(info)
        bar = QHBoxLayout(); self.activity_toggle = QPushButton("PAUSE LIVE VIEW"); self.activity_toggle.clicked.connect(self.toggle_activity)
        refresh = QPushButton("REFRESH ONCE"); refresh.clicked.connect(self.load_activity)
        self.runtime_label = QLabel("RUNTIME: CHECKING"); self.runtime_label.setObjectName("warn")
        bar.addWidget(self.activity_toggle); bar.addWidget(refresh); bar.addStretch(); bar.addWidget(self.runtime_label); layout.addLayout(bar)
        self.activity_table = QTableWidget(0, 6); self.activity_table.setHorizontalHeaderLabels(["TIME", "STATUS", "EVENT", "PROCESS / ENTITY", "RULE", "OUTCOME"])
        self.activity_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.activity_table.verticalHeader().setVisible(False)
        self.activity_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.activity_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch); layout.addWidget(self.activity_table, 1)
        self.activity_timer = QTimer(self); self.activity_timer.setInterval(3000); self.activity_timer.timeout.connect(self.load_activity)
        return page

    def _main_tab_changed(self, index: int) -> None:
        """Poll the high-volume activity feed only while it is visible."""
        if not hasattr(self, "activity_timer"):
            return
        if index == 4 and self._live_activity:
            self.activity_timer.start()
            self.load_activity()
        else:
            self.activity_timer.stop()

    def _build_outcomes_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        info = QLabel("One row per real rule firing. MATCHED, ALERT SAVED, and ACTION RESULT are separate so response completion is unambiguous.")
        info.setWordWrap(True); layout.addWidget(info)
        refresh = QPushButton("REFRESH RESPONSE OUTCOMES"); refresh.clicked.connect(self.load_alerts); layout.addWidget(refresh, alignment=Qt.AlignmentFlag.AlignLeft)
        self.outcome_table = QTableWidget(0, 7)
        self.outcome_table.setHorizontalHeaderLabels(["TIME", "SEVERITY", "RULE", "MATCH", "ALERT", "ACTIONS", "MODE"])
        self.outcome_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.outcome_table.verticalHeader().setVisible(False)
        self.outcome_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.outcome_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.outcome_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch); layout.addWidget(self.outcome_table, 1)
        return page

    def _build_guided_editor(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        form = QFormLayout()
        self.event_combo = QComboBox(); self.severity_combo = QComboBox()
        self.severity_combo.addItems(["low", "medium", "high", "critical"])
        self.priority_spin = QSpinBox(); self.priority_spin.setRange(1, 10)
        form.addRow("Trigger event", self.event_combo)
        form.addRow("Severity", self.severity_combo)
        form.addRow("Priority", self.priority_spin)
        layout.addLayout(form)
        self.conditions_table = QTableWidget(0, 3)
        self.conditions_table.setHorizontalHeaderLabels(["Field", "Operator", "Value"])
        self.conditions_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.conditions_table)
        row_buttons = QHBoxLayout()
        add = QPushButton("+ CONDITION"); remove = QPushButton("- CONDITION")
        add.clicked.connect(self._add_condition); remove.clicked.connect(self._remove_condition)
        apply_button = QPushButton("APPLY GUIDED CHANGES")
        apply_button.clicked.connect(self._apply_guided)
        row_buttons.addWidget(add); row_buttons.addWidget(remove); row_buttons.addStretch(); row_buttons.addWidget(apply_button)
        layout.addLayout(row_buttons)
        return page

    def _build_coverage_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        info = QLabel("Complete watcher capability map. Every known event, collector, availability state, collection mode, latency, and field count is visible together.")
        info.setWordWrap(True); layout.addWidget(info)
        bar = QHBoxLayout()
        refresh = QPushButton("REFRESH COVERAGE"); refresh.clicked.connect(self.load_coverage)
        self.coverage_summary = QLabel("COLLECTORS: CHECKING"); self.coverage_summary.setObjectName("warn")
        bar.addWidget(self.coverage_summary, 1); bar.addWidget(refresh); layout.addLayout(bar)
        self.coverage_table = QTableWidget(0, 7)
        self.coverage_table.setHorizontalHeaderLabels(["EVENT / WATCH AREA", "STATUS", "COLLECTOR", "MODE", "LATENCY", "FIELDS", "REASON / REQUIREMENT"])
        self.coverage_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers); self.coverage_table.verticalHeader().setVisible(False)
        self.coverage_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.coverage_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.coverage_table.currentCellChanged.connect(lambda row, *_: self._show_coverage_item(row))
        layout.addWidget(self.coverage_table, 2)
        self.coverage_details = QTextEdit(); self.coverage_details.setReadOnly(True)
        self.coverage_details.setMaximumHeight(190); layout.addWidget(self.coverage_details)
        storage = QLabel("STORAGE POLICY: unmatched events are transient. Completed matches save normalized/raw contributing events and investigation evidence under data/evidence, plus an alert summary in data/alerts.jsonl.")
        storage.setObjectName("ok"); storage.setWordWrap(True); layout.addWidget(storage)
        return page

    def _build_history_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        bar = QHBoxLayout()
        refresh = QPushButton("REFRESH APPROVED RULES"); refresh.clicked.connect(self.load_history)
        self.promote_rule_button = QPushButton("PROMOTE TO KNOWLEDGE")
        self.promote_rule_button.clicked.connect(self.promote_selected_rule)
        self.promote_rule_button.setEnabled(False)
        self.delete_rule_button = QPushButton("DELETE SELECTED RULE"); self.delete_rule_button.setObjectName("danger")
        self.delete_rule_button.clicked.connect(self.delete_selected_rule); self.delete_rule_button.setEnabled(False)
        self.cleanup_duplicates_button = QPushButton("DELETE DUPLICATE RECORDS"); self.cleanup_duplicates_button.setObjectName("danger")
        self.cleanup_duplicates_button.clicked.connect(self.delete_duplicate_rules)
        self.delete_all_rules_button = QPushButton("DELETE ALL RULES"); self.delete_all_rules_button.setObjectName("danger")
        self.delete_all_rules_button.clicked.connect(self.delete_all_approved_rules)
        bar.addWidget(refresh); bar.addWidget(self.promote_rule_button); bar.addStretch(); bar.addWidget(self.cleanup_duplicates_button); bar.addWidget(self.delete_rule_button); bar.addWidget(self.delete_all_rules_button)
        layout.addLayout(bar)
        self.history_list = QListWidget(); self.history_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff); self.history_list.currentRowChanged.connect(self._show_history)
        self.history_detail = QTextEdit(); self.history_detail.setReadOnly(True)
        split = QSplitter(); split.addWidget(self.history_list); split.addWidget(self.history_detail); split.setSizes([380, 800])
        layout.addWidget(split, 1); return page

    def _build_evidence_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        refresh = QPushButton("REFRESH MATCHED EVIDENCE"); refresh.clicked.connect(self.load_alerts)
        layout.addWidget(refresh, alignment=Qt.AlignmentFlag.AlignLeft)
        self.alert_list = QListWidget(); self.alert_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff); self.alert_list.currentRowChanged.connect(self._load_selected_evidence)
        self.evidence_detail = QTextEdit(); self.evidence_detail.setReadOnly(True); self.evidence_detail.setFont(QFont("Consolas", 9))
        split = QSplitter(); split.addWidget(self.alert_list); split.addWidget(self.evidence_detail); split.setSizes([410, 780])
        layout.addWidget(split, 1); return page

    def _run(self, operation: Callable[[], Any], success: Callable[[Any], None], busy: str | None = None,
             finished: Callable[[], None] | None = None, failure: Callable[[str], None] | None = None) -> None:
        if busy: self._set_status(busy, "warn")
        worker = ApiWorker(operation)
        self._workers.add(worker)
        def on_success(result: Any) -> None:
            self._workers.discard(worker)
            if finished: finished()
            success(result)
        def on_failure(error: str) -> None:
            self._workers.discard(worker)
            if finished: finished()
            if failure: failure(error)
            else: self._set_status(error, "error")
        worker.signals.success.connect(on_success)
        worker.signals.failure.connect(on_failure)
        self.pool.start(worker)

    def _load_initial_data(self) -> None:
        self._run(lambda: api_call(self.base_url, "GET", "/api/ir-schema-options"), self._schema_loaded)
        self._run(
            lambda: api_call(self.base_url, "GET", "/api/knowledge/status"),
            self._knowledge_status_loaded,
        )
        self.load_coverage(); self.load_history(); self.load_alerts(); self.load_activity()

    def _knowledge_status_loaded(self, status: dict) -> None:
        if status.get("ready"):
            self.retrieval_view.setPlainText(
                f"Knowledge index {status.get('version')} ready: "
                f"{status.get('document_count', 0)} controlled documents. "
                "The watcher does not load this index."
            )
        elif not status.get("enabled", True):
            self.retrieval_view.setPlainText("Authoring retrieval is disabled by configuration.")
        else:
            self.retrieval_view.setPlainText("Knowledge index unavailable; static authoring fallback is active.")

    def _schema_loaded(self, schema: dict) -> None:
        self.schema = schema
        self.event_combo.clear(); self.event_combo.addItems(schema.get("events", []))
        self._set_status("GEKKO is ready. Enter an English rule or inspect the monitoring tabs.", "ok")

    def parse_rule(self) -> None:
        text = self.rule_input.toPlainText().strip()
        if not text:
            self._set_status("Enter an English rule before parsing.", "warn"); return
        self.parse_button.setEnabled(False)
        self.draft_validated = False; self.approve_button.setEnabled(False)
        # Backend may perform up to three bounded 30-second model calls.
        self._run(lambda: api_call(self.base_url, "POST", "/api/parse-rule", {"rule_text": text}, timeout=105), self._parse_complete,
                  "Parsing, validating, and simulating...", finished=lambda: self.parse_button.setEnabled(True),
                  failure=self._parse_failed)

    def _parse_failed(self, error: str) -> None:
        self.draft_validated = False; self.approve_button.setEnabled(False)
        self._set_status(error, "error")

    def _parse_complete(self, result: dict) -> None:
        trace = result.get("retrieval") or {}
        documents = trace.get("documents", [])
        lines = [
            f"Mode: {trace.get('mode', 'disabled').upper()} | "
            f"Index: {trace.get('index_version') or 'n/a'} | "
            f"Retrieval: {trace.get('elapsed_ms', 0)} ms"
        ]
        if trace.get("fallback_reason"):
            lines.append(trace["fallback_reason"])
        for item in documents:
            lines.append(
                f"[{item.get('type', '').upper()}] {item.get('title', item.get('id'))} "
                f"(score {item.get('score', 0):.2f}) — {item.get('reason', '')}"
            )
        if not documents and not trace.get("fallback_reason"):
            lines.append("No document passed the relevance floor; no padding was added.")
        self.retrieval_view.setPlainText("\n".join(lines))
        wrapper = result.get("ir")
        if not wrapper or not isinstance(wrapper.get("ir"), dict):
            self._set_status(_error_text(result.get("error") or "No executable IR was produced"), "error"); return
        self.current_result = result
        self.original_draft = json.loads(json.dumps(wrapper["ir"]))
        self.current_draft = json.loads(json.dumps(wrapper["ir"]))
        self._populate_editors()
        # Approval is never unlocked from the model response alone. Always run
        # the same exact-draft gate used again by the persistence endpoint.
        self.draft_validated = False
        self.approve_button.setEnabled(False)
        self.recheck_draft()

    def _populate_editors(self) -> None:
        if not self.current_draft: return
        self._loading_editor = True
        self.expert_editor.setPlainText(json.dumps(self.current_draft, indent=2, ensure_ascii=False))
        summary = {
            "event": self.current_draft.get("trigger_event"), "severity": self.current_draft.get("severity"),
            "conditions": self.current_draft.get("conditions"), "correlation": self.current_draft.get("correlation"),
            "simulation": self.current_result.get("simulation") if self.current_result else None,
            "explanation": self.current_result.get("ir", {}).get("explanation") if self.current_result else None,
        }
        self.readonly_view.setPlainText(json.dumps(summary, indent=2, ensure_ascii=False))
        event = self.current_draft.get("trigger_event", "")
        index = self.event_combo.findText(event)
        if index >= 0: self.event_combo.setCurrentIndex(index)
        self.severity_combo.setCurrentText(self.current_draft.get("severity", "medium"))
        self.priority_spin.setValue(int(self.current_draft.get("priority", 5)))
        conditions = self.current_draft.get("conditions", [])
        self.conditions_table.setRowCount(len(conditions))
        for row, condition in enumerate(conditions):
            for column, key in enumerate(("field", "operator", "value")):
                self.conditions_table.setItem(row, column, QTableWidgetItem(str(condition.get(key, ""))))
        suggestions = set(self.current_draft.get("suggested_action", []))
        selected = {item.get("type") for item in self.current_draft.get("response_actions", [])}
        for action, checkbox in self.action_checks.items(): checkbox.setChecked(action in (selected or suggestions or {"alert"}))
        self._loading_editor = False

    def _add_condition(self) -> None:
        row = self.conditions_table.rowCount(); self.conditions_table.insertRow(row)
        for col in range(3): self.conditions_table.setItem(row, col, QTableWidgetItem(""))

    def _remove_condition(self) -> None:
        row = self.conditions_table.currentRow()
        if row >= 0: self.conditions_table.removeRow(row)

    def _apply_guided(self) -> None:
        if not self.current_draft: return
        if self.current_draft.get("correlation"):
            self._set_status("Correlation rules require Expert JSON so stages are never silently lost.", "warn"); return
        conditions = []
        for row in range(self.conditions_table.rowCount()):
            values = [self.conditions_table.item(row, col).text().strip() if self.conditions_table.item(row, col) else "" for col in range(3)]
            if all(values): conditions.append(dict(zip(("field", "operator", "value"), values)))
        self.current_draft.update({"trigger_event": self.event_combo.currentText(), "severity": self.severity_combo.currentText(), "priority": self.priority_spin.value(), "conditions": conditions})
        self._loading_editor = True; self.expert_editor.setPlainText(json.dumps(self.current_draft, indent=2)); self._loading_editor = False
        self._mark_dirty("intermediate")

    def _actions_changed(self) -> None:
        if self._loading_editor or not self.current_draft: return
        selected = [{"type": action, "duration": None} for action, check in self.action_checks.items() if check.isChecked()]
        self.current_draft["response_actions"] = selected
        self._mark_dirty(self.edit_mode or "intermediate")

    def _mark_dirty(self, mode: str) -> None:
        if self._loading_editor or not self.current_draft: return
        self.edit_mode = mode; self.draft_validated = False; self.approve_button.setEnabled(False)
        self._set_status("Draft changed. Re-validation is required before approval.", "warn")

    def _draft_from_active_editor(self) -> dict:
        if self.review_tabs.currentIndex() == 2:
            return json.loads(self.expert_editor.toPlainText())
        return self.current_draft or {}

    def recheck_draft(self) -> None:
        try: draft = self._draft_from_active_editor()
        except json.JSONDecodeError as exc: self._set_status(f"Invalid JSON: {exc}", "error"); return
        self.current_draft = draft
        self.recheck_button.setEnabled(False); self.approve_button.setEnabled(False)
        self._run(lambda: api_call(self.base_url, "POST", "/api/rules/draft-check", {"draft": draft}), self._recheck_complete,
                  "Checking exact draft...", finished=lambda: self.recheck_button.setEnabled(True))

    def _recheck_complete(self, result: dict) -> None:
        if not result.get("valid"):
            self.draft_validated = False; self.approve_button.setEnabled(False)
            self._set_status("Validation failed: " + "; ".join(result.get("errors", [])), "error"); return
        self.current_draft = result.get("normalized_draft", self.current_draft)
        if self.current_result: self.current_result["simulation"] = result.get("simulation")
        self.draft_validated = True; self.approve_button.setEnabled(True); self._populate_editors()
        self._set_status("Exact draft freshly validated and simulated.", "ok")

    def approve_rule(self) -> None:
        if not self.draft_validated or not self.current_result or not self.current_draft: return
        actions = [name for name, check in self.action_checks.items() if check.isChecked()]
        if not actions: self._set_status("Select at least one response action.", "error"); return
        wrapper = dict(self.current_result["ir"]); wrapper["ir"] = self.current_draft
        original = dict(self.current_result["ir"]); original["ir"] = self.original_draft
        payload = {"rule_text": self.rule_input.toPlainText().strip(), "ir": wrapper, "original_ir": original,
                   "edit_mode": self.edit_mode, "response_actions": actions,
                   "injection_flags": self.current_result.get("injection_flags", []),
                   "capability_gaps": self.current_result.get("capability", {}).get("gaps", []),
                   "retrieval_trace": self.current_result.get("retrieval")}
        self.approve_button.setEnabled(False)
        self._run(lambda: api_call(self.base_url, "POST", "/api/rules/approve", payload), self._approve_complete, "Approving rule...",
                  failure=self._approve_failed)

    def _approve_failed(self, error: str) -> None:
        self.approve_button.setEnabled(self.draft_validated)
        self._set_status(error, "error")

    def _approve_complete(self, result: dict) -> None:
        self.draft_validated = False; self.approve_button.setEnabled(False)
        status = result.get("status", "approved")
        prefix = "Rule already exists" if status == "already_approved" else "Rule saved"
        self._set_status(f"{prefix}: {result.get('rule_id')}. Watcher hot-reload is automatic; verify live observation under WATCHER ACTIVITY.", "ok")
        self.load_history(); self.load_activity()

    def toggle_activity(self) -> None:
        self._live_activity = not self._live_activity
        self.activity_toggle.setText("PAUSE LIVE VIEW" if self._live_activity else "START LIVE VIEW")
        if self._live_activity: self.activity_timer.start(); self.load_activity()
        else: self.activity_timer.stop()

    def load_activity(self) -> None:
        if self._activity_pending: return
        self._activity_pending = True
        self._run(lambda: api_call(self.base_url, "GET", "/api/watcher-activity?limit=100&compact=true"), self._activity_loaded,
                  finished=lambda: setattr(self, "_activity_pending", False))
        self.refresh_runtime()

    def _activity_loaded(self, data: dict) -> None:
        rows = data.get("activity", [])
        fingerprint = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if fingerprint == self._activity_fingerprint:
            return
        self._activity_fingerprint = fingerprint
        self.activity_table.setRowCount(len(rows))
        colors = {"event_observed": QColor("#6f9f7b"), "rule_matched": QColor("#ffe066"),
                  "alert_saved": QColor("#4cc9ff"), "event_deduplicated": QColor("#9b7ede"),
                  "rules_reloaded": QColor("#ff9f43"), "sustain_pending": QColor("#ffd166"),
                  "sustain_verified": QColor("#54ff87"), "sustain_not_met": QColor("#7f8c8d"),
                  "rule_reload_degraded": QColor("#ff7070")}
        labels = {"event_observed": "WATCHING", "rule_matched": "MATCHED",
                  "alert_saved": "ALERT SAVED", "event_deduplicated": "DEDUPED", "rules_reloaded": "RULES RELOADED",
                  "sustain_pending": "TIMER STARTED", "sustain_verified": "DURATION MET", "sustain_not_met": "EXITED EARLY"}
        labels["rule_reload_degraded"] = "RULE FILE BLOCKED"
        for row_index, row in enumerate(rows):
            kind = row.get("kind", "")
            outcome = {"alert_saved": "Evidence stored", "rule_matched": "Condition satisfied",
                       "rules_reloaded": "Active rule index updated", "event_deduplicated": "Duplicate telemetry suppressed",
                       "sustain_pending": "Waiting to verify continued process liveness",
                       "sustain_verified": "Process remained alive for the required duration",
                       "sustain_not_met": "Process exited before the duration elapsed",
                       "rule_reload_degraded": "Invalid rule update blocked; last-known-good rules retained"}.get(
                           kind, "Observed only — no active rule matched"
                       )
            repeats = int(row.get("repeat_count", 1) or 1)
            if repeats > 1:
                outcome += f" ({repeats} similar events)"
            subject = row.get("subject")
            if not subject:
                process_name, pid = row.get("process_name"), row.get("pid")
                subject = (
                    f"{process_name} [{pid}]" if process_name
                    else f"{row.get('event_type', 'event')} via {row.get('collector', 'unknown')}"
                )
            values = [_local_time(row.get("at", "")), labels.get(kind, kind.upper()), row.get("event_type", ""),
                      subject, str(row.get("rule_id", ""))[:8] or "—", outcome]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value)); item.setForeground(colors.get(kind, QColor("#b8ffd0"))); self.activity_table.setItem(row_index, column, item)

    def refresh_runtime(self) -> None:
        if self._runtime_pending: return
        self._runtime_pending = True
        self._run(lambda: api_call(self.base_url, "GET", "/api/watcher-runtime", timeout=3), self._runtime_loaded,
                  finished=lambda: setattr(self, "_runtime_pending", False))

    def _runtime_loaded(self, data: dict) -> None:
        running = bool(data.get("running")); state = data.get("state", "offline"); rules = data.get("rules_loaded", 0); dry = data.get("dry_run", True)
        text = f"RUNTIME: {state.upper()} | {rules} ACTIVE UNIQUE RULES | {'DRY-RUN' if dry else 'ENFORCING'} | HEARTBEAT {data.get('heartbeat_age_s','?')}s"
        degraded = bool(data.get("rule_index_degraded"))
        if degraded:
            text += f" | RULE FILE BLOCKED ({data.get('rule_load_errors', 0)} ERRORS)"
        self.runtime_label.setText(text); self.runtime_label.setObjectName("warn" if running and degraded else ("ok" if running else "error")); self.runtime_label.style().polish(self.runtime_label)
        self.agent_badge.setText("AGENT: ONLINE" if running else "AGENT: OFFLINE")
        self.agent_badge.setObjectName("ok" if running else "error"); self.agent_badge.style().polish(self.agent_badge)

    def load_coverage(self) -> None:
        if self._coverage_pending: return
        self._coverage_pending = True
        self._run(lambda: api_call(self.base_url, "GET", "/api/watcher-capabilities"), self._coverage_loaded,
                  finished=lambda: setattr(self, "_coverage_pending", False))

    def _coverage_loaded(self, data: dict) -> None:
        self.coverage_data = data.get("events", [])
        self.coverage_table.setRowCount(len(self.coverage_data))
        for row, item in enumerate(self.coverage_data):
            available = item.get("available"); color = QColor("#54ff87" if available else "#ff7070")
            failed = item.get("failed_collectors", {})
            disabled = item.get("disabled_collectors", [])
            if available:
                reason = "Active: " + ", ".join(item.get("active_collectors", []))
            elif failed:
                reason = "; ".join(f"{name}: {', '.join(messages)}" for name, messages in failed.items())
            elif disabled:
                reason = "Disabled in WATCHER_COLLECTORS: " + ", ".join(disabled)
            else:
                reason = "No active telemetry provider"
            values = [item.get("event"), "AVAILABLE" if available else "UNAVAILABLE", ", ".join(item.get("collectors", [])),
                      item.get("collection_mode", "realtime").upper(), f"~{item.get('poll_interval_s')}s" if item.get("poll_interval_s") else "LIVE",
                      str(len(item.get("fields", []))), reason]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(str(value)); cell.setForeground(color); self.coverage_table.setItem(row, column, cell)
        active = data.get("active_collectors", []); failed = list(data.get("failed_collectors", {}))
        disabled = sorted({name for item in self.coverage_data for name in item.get("disabled_collectors", [])})
        self.coverage_summary.setText(f"ACTIVE ({len(active)}): {', '.join(active) or 'none'}    |    FAILED: {', '.join(failed) or 'none'}    |    DISABLED: {', '.join(disabled) or 'none'}")
        running = data.get("watcher_running")
        self.agent_badge.setText("AGENT: ONLINE" if running else "AGENT: OFFLINE")
        self.agent_badge.setObjectName("ok" if running else "error"); self.agent_badge.style().polish(self.agent_badge)
        if self.coverage_data: self.coverage_table.selectRow(0); self._show_coverage_item(0)

    def _show_coverage_item(self, index: int | None = None) -> None:
        if not getattr(self, "coverage_data", None): return
        if index is None: index = self.coverage_table.currentRow()
        if index < 0 or index >= len(self.coverage_data): return
        item = self.coverage_data[index]
        lines = [f"EVENT: {item['event']}", f"STATUS: {'AVAILABLE' if item['available'] else 'UNAVAILABLE'}",
                 f"REQUIRED COLLECTORS: {', '.join(item['collectors']) or 'none'}",
                 f"ACTIVE PROVIDERS: {', '.join(item['active_collectors']) or 'none'}",
                 f"FAILED PROVIDERS: {', '.join(item.get('failed_collectors', {})) or 'none'}",
                 f"DISABLED PROVIDERS: {', '.join(item.get('disabled_collectors', [])) or 'none'}",
                 f"COLLECTION: {item.get('collection_mode','realtime').upper()}" + (f" (up to ~{item.get('poll_interval_s')}s latency)" if item.get('poll_interval_s') else ""), "", "FIELDS:"]
        lines.extend(f"  - {field['name']} ({field['type']})" for field in item.get("fields", []))
        if item.get("failed_collectors"):
            lines.extend(["", "REQUIREMENTS TO ENABLE:"])
            for provider, messages in item["failed_collectors"].items():
                lines.extend(f"  - {provider}: {message}" for message in messages)
        self.coverage_details.setPlainText("\n".join(lines))

    def load_history(self) -> None:
        if self._history_pending: return
        self._history_pending = True
        self._run(lambda: api_call(self.base_url, "GET", "/api/rules?page=0&limit=100&newest=true"), self._history_loaded,
                  finished=lambda: setattr(self, "_history_pending", False))

    def _history_loaded(self, data: dict) -> None:
        selected_id = None
        current = self.history_list.currentItem()
        if current: selected_id = current.data(Qt.ItemDataRole.UserRole)
        blocker = QSignalBlocker(self.history_list)
        self.history_data = data.get("rules", []); self.history_total = int(data.get("total", len(self.history_data))); self.history_list.clear()
        selected_row = -1
        seen: set[str] = set()
        for row, rule in enumerate(self.history_data):
            inner = rule.get("ir", {}).get("ir", {})
            semantic = json.dumps(inner, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            duplicate = semantic in seen; seen.add(semantic)
            marker = "  [DUPLICATE RECORD - EXECUTED ONCE]" if duplicate else ""
            text = f"{_local_time(rule.get('created_at',''), include_date=True)}  {rule.get('rule_text','')[:90]}{marker}"
            item = QListWidgetItem(text); item.setToolTip(text)
            item.setData(Qt.ItemDataRole.UserRole, rule.get("id")); self.history_list.addItem(item)
            if rule.get("id") == selected_id: selected_row = row
        if selected_row >= 0: self.history_list.setCurrentRow(selected_row)
        del blocker
        if selected_row >= 0: self._show_history(selected_row)
        self.delete_all_rules_button.setEnabled(bool(self.history_data))
        self.delete_rule_button.setEnabled(False)
        self.promote_rule_button.setEnabled(False)
        if selected_row < 0: self.history_detail.setPlainText("No approved rules." if not self.history_data else f"Showing {len(self.history_data)} of {self.history_total} approved records. Semantically identical records execute once. Select one to inspect or delete it.")

    def _show_history(self, row: int) -> None:
        valid = 0 <= row < len(getattr(self, "history_data", []))
        self.delete_rule_button.setEnabled(valid)
        self.promote_rule_button.setEnabled(valid)
        if valid: self.history_detail.setPlainText(json.dumps(self.history_data[row], indent=2, ensure_ascii=False))

    def promote_selected_rule(self) -> None:
        row = self.history_list.currentRow()
        if not 0 <= row < len(getattr(self, "history_data", [])):
            self._set_status("Select an approved rule first.", "warn"); return
        rule = self.history_data[row]
        answer = QMessageBox.question(
            self,
            "Promote verified example",
            "Sanitize and promote this approved rule into the local authoring "
            "knowledge base?\n\nThis is deliberate guidance curation; evidence "
            "and unmatched telemetry are never indexed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        rule_id = str(rule.get("id", ""))
        self.promote_rule_button.setEnabled(False)
        def promoted(result: dict) -> None:
            document = result.get("document", {})
            self.promote_rule_button.setEnabled(True)
            self._set_status(
                f"Promoted sanitized knowledge document: {document.get('id', rule_id)}",
                "ok",
            )
        self._run(
            lambda: api_call(
                self.base_url, "POST", f"/api/knowledge/promote/{rule_id}", {}
            ),
            promoted,
            "Sanitizing and rebuilding the knowledge index...",
            failure=lambda error: (
                self.promote_rule_button.setEnabled(True),
                self._set_status(error, "error"),
            ),
        )

    def delete_selected_rule(self) -> None:
        row = self.history_list.currentRow()
        if not 0 <= row < len(getattr(self, "history_data", [])):
            self._set_status("Select an approved rule first.", "warn"); return
        rule = self.history_data[row]
        answer = QMessageBox.question(
            self, "Delete approved rule",
            f"Delete this rule?\n\n{rule.get('rule_text', '(unnamed rule)')}\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes: return
        rule_id = str(rule.get("id", ""))
        self.delete_rule_button.setEnabled(False)
        self._run(lambda: api_call(self.base_url, "DELETE", f"/api/rules/{rule_id}"),
                  lambda _result: self._rules_deleted(1), "Deleting approved rule...", failure=self._delete_failed)

    def delete_all_approved_rules(self) -> None:
        count = int(getattr(self, "history_total", len(getattr(self, "history_data", []))))
        if not count: return
        answer = QMessageBox.question(
            self, "Delete all approved rules",
            f"Delete all {count} approved rules?\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes: return
        self.delete_all_rules_button.setEnabled(False)
        self._run(lambda: api_call(self.base_url, "DELETE", "/api/rules"),
                  lambda result: self._rules_deleted(int(result.get("deleted", count))), "Deleting all approved rules...", failure=self._delete_failed)

    def delete_duplicate_rules(self) -> None:
        answer = QMessageBox.question(
            self, "Delete duplicate rule records",
            "Delete semantically duplicate approved-rule records?\n\nThe oldest copy and its evidence links will be preserved.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes: return
        self.cleanup_duplicates_button.setEnabled(False)
        def cleaned(result: dict) -> None:
            self.cleanup_duplicates_button.setEnabled(True)
            self._rules_deleted(int(result.get("deleted", 0)))
        self._run(lambda: api_call(self.base_url, "DELETE", "/api/rule-maintenance/duplicates"), cleaned,
                  "Cleaning duplicate rule records...", failure=self._delete_failed)

    def _delete_failed(self, error: str) -> None:
        self.cleanup_duplicates_button.setEnabled(True)
        self.delete_all_rules_button.setEnabled(bool(getattr(self, "history_data", [])))
        self.delete_rule_button.setEnabled(self.history_list.currentRow() >= 0)
        self._set_status(error, "error")

    def _rules_deleted(self, count: int) -> None:
        self._set_status(f"Deleted {count} approved rule{'s' if count != 1 else ''}. Watcher hot-reload is automatic.", "ok")
        self.load_history(); self.load_activity()

    def load_alerts(self) -> None:
        if self._alerts_pending: return
        self._alerts_pending = True
        self._run(lambda: api_call(self.base_url, "GET", "/api/alerts?limit=100", timeout=4), self._alerts_loaded,
                  finished=lambda: setattr(self, "_alerts_pending", False))

    def _alerts_loaded(self, data: dict) -> None:
        previous_id = getattr(self, "_last_alert_id", None)
        selected_id = None
        current = self.alert_list.currentItem()
        if current: selected_id = current.data(Qt.ItemDataRole.UserRole)
        blocker = QSignalBlocker(self.alert_list)
        self.alert_data = data.get("alerts", []); self.alert_list.clear()
        severity_colors = {"critical": QColor("#ff3b3b"), "high": QColor("#ff7070"), "medium": QColor("#ffe066"), "low": QColor("#4cc9ff")}
        selected_row = -1
        for row, alert in enumerate(self.alert_data):
            actions = ", ".join(f"{a.get('action')}:{a.get('result')}" for a in alert.get("action_results", [])) or "none"
            integrity = alert.get("integrity_status", "unknown")
            warning = " [TAMPER WARNING]" if integrity in {"invalid", "unsupported"} else ""
            item = QListWidgetItem(f"[{alert.get('severity','').upper()}]{warning} {_local_time(alert.get('fired_at',''), include_date=True)}  {alert.get('rule_text') or '(unnamed rule)'}  |  ALERT SAVED  |  {actions}")
            item.setData(Qt.ItemDataRole.UserRole, alert.get("id")); item.setToolTip(f"{item.text()}\nIntegrity: {integrity}")
            item.setForeground(QColor("#ff3b3b") if warning else severity_colors.get(alert.get("severity", "").lower(), QColor("#b8ffd0"))); self.alert_list.addItem(item)
            if alert.get("id") == selected_id: selected_row = row
        if selected_row >= 0: self.alert_list.setCurrentRow(selected_row)
        del blocker
        if not self.alert_data: self.evidence_detail.setPlainText("No matched evidence has been saved yet.")
        elif selected_row < 0 and selected_id is None: self.evidence_detail.setPlainText("Select an alert to load its complete evidence.")
        if self.alert_data:
            newest = self.alert_data[0]; self._last_alert_id = newest.get("id")
            if previous_id and previous_id != self._last_alert_id:
                self.alert_banner.setText(f"NEW {newest.get('severity','').upper()} ALERT — {newest.get('rule_text') or newest.get('event_type')} — {newest.get('summary','')}")
                self.alert_banner.show(); QTimer.singleShot(12000, self.alert_banner.hide)
        self._populate_outcomes()

    def _populate_outcomes(self) -> None:
        if not hasattr(self, "outcome_table"): return
        self.outcome_table.setRowCount(len(getattr(self, "alert_data", [])))
        for row, alert in enumerate(self.alert_data):
            results = alert.get("action_results", [])
            action_text = "; ".join(f"{result.get('action','?').upper()}: {result.get('result','unknown').upper()}" for result in results) or "NO ACTION REQUESTED"
            integrity = alert.get("integrity_status", "unknown")
            saved_text = {"verified": "SAVED + VERIFIED", "legacy_unsigned": "SAVED (LEGACY)"}.get(integrity, "TAMPER WARNING")
            values = [_local_time(alert.get("fired_at", "")), alert.get("severity", "").upper(), alert.get("rule_text") or "(unnamed rule)",
                      "MATCHED", saved_text, action_text, "DRY-RUN" if alert.get("dry_run") else "ENFORCING"]
            result_values = {str(item.get("result", "")).lower() for item in results}
            failure = any(value in {"failed", "error", "rate_limited", "no_pid", "unsupported"} for value in result_values)
            colors = [QColor("#b8ffd0"), QColor("#ff7070" if alert.get("severity") in {"high", "critical"} else "#ffe066"), QColor("#b8ffd0"),
                      QColor("#ffe066"), QColor("#4cc9ff" if integrity in {"verified", "legacy_unsigned"} else "#ff3b3b"), QColor("#ff7070" if failure else "#ff9f43"), QColor("#9b7ede" if alert.get("dry_run") else "#54ff87")]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value)); item.setForeground(colors[column]); self.outcome_table.setItem(row, column, item)

    def _load_selected_evidence(self, row: int) -> None:
        if not 0 <= row < len(getattr(self, "alert_data", [])): return
        alert = self.alert_data[row]; instance_id = alert.get("instance_id")
        if not instance_id: self.evidence_detail.setPlainText(json.dumps(alert, indent=2)); return
        self.evidence_detail.setPlainText("Loading evidence...")
        safe_id = urllib.parse.quote(str(instance_id), safe="")
        def show(data: dict) -> None:
            current = self.alert_list.currentRow()
            if 0 <= current < len(self.alert_data) and self.alert_data[current].get("instance_id") == instance_id:
                self.evidence_detail.setPlainText(self._format_evidence(data))
        def failed(error: str) -> None:
            current = self.alert_list.currentRow()
            if 0 <= current < len(self.alert_data) and self.alert_data[current].get("instance_id") == instance_id:
                self.evidence_detail.setPlainText(f"Evidence unavailable: {error}")
        self._run(lambda: api_call(self.base_url, "GET", f"/api/evidence/{safe_id}"), show, failure=failed)

    @staticmethod
    def _format_evidence(data: dict) -> str:
        """Render an operator-first explanation, followed by the lossless JSON."""
        lines = [
            "MATCH SUMMARY",
            f"Rule: {data.get('rule_text') or data.get('rule_name', '')}",
            f"Severity: {str(data.get('severity', '')).upper()}",
            f"Integrity: {str(data.get('integrity_status', 'unknown')).upper()}",
            f"Matched: {_local_time(data.get('matched_at', ''), include_date=True)}",
            f"Collector: {data.get('source_collector', 'unknown')}", "",
        ]
        stages = data.get("correlation_stages", [])
        # Backward-compatible rendering for evidence created before labeled
        # correlation stages were added. The retained contributing events are
        # sufficient to reconstruct the ordered operator view.
        if not stages:
            correlated = data.get("raw_event", {}).get("correlated_events", [])
            flat_conditions = data.get("matched_conditions", [])
            if isinstance(correlated, list) and len(correlated) > 1:
                stages = []
                for index, event in enumerate(correlated):
                    process = event.get("process", {}) if isinstance(event, dict) else {}
                    condition = flat_conditions[index] if index < len(flat_conditions) else {}
                    field = condition.get("field", "")
                    actual = process.get({"name": "name", "pid": "pid", "ppid": "ppid", "command_line": "command_line"}.get(field, field))
                    stages.append({
                        "stage": index + 1, "event_type": event.get("event_type", "unknown"),
                        "process_identity": {key: process.get(key) for key in ("pid", "ppid", "guid", "parent_guid")},
                        "contributing_event": event,
                        "conditions": [{**condition, "actual": actual}] if condition else [],
                    })
        if stages:
            lines.append(f"CORRELATION STAGES ({len(stages)} contributing events)")
            for stage in stages:
                identity = stage.get("process_identity", {})
                lines.extend([
                    f"Stage {stage.get('stage')}: {stage.get('event_type')}",
                    f"  Process identity: PID={identity.get('pid')} PPID={identity.get('ppid')} GUID={identity.get('guid') or 'unavailable'} ParentGUID={identity.get('parent_guid') or 'unavailable'}",
                ])
                event = stage.get("contributing_event", {})
                process = event.get("process", {}) if isinstance(event, dict) else {}
                lines.append(f"  Command line: {process.get('command_line') or '(not captured)'}")
                for condition in stage.get("conditions", []):
                    lines.append(f"  Condition: {condition.get('field')} {condition.get('operator')} {condition.get('expected')!r} -> actual {condition.get('actual')!r}")
            lines.append("")
        else:
            lines.append("SINGLE EVENT MATCH")
            for condition in data.get("matched_conditions", []):
                lines.append(f"  {condition.get('field')} {condition.get('operator')} {condition.get('expected')!r}")
            lines.append("")
        lines.extend(["FULL EVIDENCE JSON", json.dumps(data, indent=2, ensure_ascii=False)])
        return "\n".join(lines)

    def _set_status(self, text: str, state: str) -> None:
        self.author_status.setText(text); self.author_status.setObjectName(state); self.author_status.style().polish(self.author_status)
        if hasattr(self, "global_status"):
            self.global_status.setText(text); self.global_status.setObjectName(state); self.global_status.style().polish(self.global_status)


def run_native_gui(base_url: str) -> int:
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(GEKKO_STYLE)
    window = MainWindow(base_url)
    window.show()
    return app.exec()
