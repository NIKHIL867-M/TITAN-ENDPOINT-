# AI Understanding Layer v5 — Rule Engine

> **Convert plain-English security rules into validated, structured IR
> (Intermediate Representation) using Groq's free-tier LLM API.**

The LLM is called **exactly once per rule** — when a person writes or
edits a rule in English. It is never called on a security event, never
in the runtime path, and has no access to live telemetry.

---

## Run as a Windows desktop application

```powershell
python -m pip install -r requirements.txt
python desktop.py
```

This starts the localhost API and opens a native PySide6/Qt Windows interface.
The PySide6 desktop is the primary and fully supported interface. It does not use
HTML, CSS, JavaScript, WebView, or a browser. `public/` is a legacy compatibility
fallback and is not feature-parity supported.
Configure
`GROQ_API_KEY` in `.env` before parsing natural-language rules. The desktop
launcher starts the watcher automatically. Closing the window leaves the watcher
and tray protection running; use the tray Exit action to stop it deliberately.
Set `DESKTOP_START_WATCHER=false` to manage it separately. Administrator
privileges and Sysmon unlock the Security and network collectors.

Native mode generates a fresh per-launch API token, restricts CORS to declared
loopback origins, and sends the token on every non-health API request. Approved
rules, new alerts, and new evidence records are HMAC-protected; the GUI displays
evidence verification state and raises a visible tamper warning. Existing
unsigned history remains readable and is labeled as legacy.

---

## Architecture

```
Rule Input (English)
    │
    ▼
┌──────────────────┐
│ Input Length Gate │  ← Configurable hard reject (default 4,000 chars)
│   (4,000 chars)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Injection        │  ← Pattern-based, tiered:
│ Screener         │     HIGH confidence → BLOCK (LLM never called)
│                  │     LOW confidence  → WARN (proceed with flags)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Context Builder  │  ← OS, collectors, fields, operators, actions, permissions
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Prompt Builder   │  ← System prompt + schema + examples + context + rule text
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Groq API Client  │  ← temperature=0, budget: max 3 LLM calls per request
│                  │     429 → retry → fallback model → terminal failure
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ JSON Extractor   │  ← Direct parse → strip fences → bracket-depth scan
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Semantic         │  ← Pydantic structural validation + context-based
│ Validator        │     field/operator/action checking
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Capability       │  ← Collectors installed? Permissions sufficient?
│ Checker          │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Rule Simulator   │  ← 3-5 synthetic events: which trigger, which don't
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Human Review UI  │  ← Approve → rules.jsonl  /  Reject → rejections.jsonl
└──────────────────┘
```

---

## Project Structure

```
CUSTOM RULE/
├── app/                        # Python backend (FastAPI) — rule authoring
│   ├── __init__.py
│   ├── config.py               # pydantic-settings configuration
│   ├── main.py                 # FastAPI server, all endpoints
│   ├── context_builder.py      # Deployment context assembly
│   ├── injection_screener.py   # Tiered injection detection
│   ├── json_extractor.py       # Robust JSON extraction from LLM output
│   ├── prompt_builder.py       # System prompt construction
│   ├── semantic_validator.py   # Pydantic IR models + context validation
│   ├── capability_checker.py   # Collector/permission verification
│   ├── rule_simulator.py       # Synthetic event generation & evaluation
│   ├── rule_store.py           # JSONL append-only persistence (thread-safe)
│   └── groq_client.py         # Async Groq client with retry/fallback
├── watcher/                    # Runtime detection agent (Redesigned — Layers 4-8)
│   ├── __init__.py
│   ├── main.py                 # Entry point + main event loop
│   ├── config.py               # Watcher settings (dry-run, collectors...)
│   ├── event_bus.py            # Thread-safe bounded event queue
│   ├── collector_manager.py    # Starts and crash-monitors enabled collectors
│   ├── collectors/             # Self-contained telemetry collectors
│   │   ├── base.py             # Collector ABC (prerequisite check + decode protocol)
│   │   ├── security.py         # Security log collector (EID 4688, 4624, 4625, 4648, 7045)
│   │   ├── system.py           # System log collector (EID 7036, 7045)
│   │   ├── sysmon.py           # Sysmon Operational collector (EID 1, 3, 7, 11, 13, and more)
│   │   ├── wmi.py, registry_fim.py, inventory.py, windows_channels.py
│   │   │                       # WMI process creation, registry FIM, asset inventory,
│   │   │                       # scheduled tasks / USB PnP / firewall / PowerShell / Defender
│   │   ├── titan_sensors.py    # Bridges the 5 native TITAN ENDPOINT C++ sensors
│   │   │                       # (Port/Process/File/Network/Application) + the Correlator's
│   │   │                       # session_timeline — tails their JSONL logs read-only, same
│   │   │                       # contract as the C++ Correlator itself. Log paths are reused
│   │   │                       # from CORRELATOR/correlator_config.txt (one source of truth).
│   │   └── __init__.py         # Registry mapping collector names (12 collectors total)
│   ├── rule_index.py           # Loads + hot-reloads rules.jsonl, indexed by trigger_event
│   ├── aggregation_store.py    # In-memory sliding-window counters + cooldowns (TTL)
│   ├── state_manager.py        # Per-instance rule state machine (waiting→...→closed)
│   ├── investigation.py        # psutil-based process/network evidence capture
│   ├── action_engine.py        # kill / isolate / alert execution + all guardrails
│   ├── notifier.py             # Append to alerts.jsonl + winotify toast
│   ├── tray.py                 # pystray system tray icon
│   └── icon.png                # Tray icon image
├── native_gui.py               # Primary native Matrix-themed Qt interface
├── desktop.py                  # Native launcher + API/watcher lifecycle
├── public/                     # Legacy browser compatibility fallback only
│   ├── index.html              # Single-page review UI
│   ├── index.css               # Dark-mode glassmorphism design
│   └── app.js                  # Frontend logic
├── data/                       # Created at runtime (gitignored)
│   ├── rules.jsonl             # Approved rules (shared read-only by watcher)
│   ├── rejections.jsonl        # Rejected rules with reasons
│   ├── alerts.jsonl            # NEW — every alert fired by the watcher
│   └── evidence/               # NEW — one JSON file per matched rule instance
├── requirements.txt            # Python dependencies (11 packages)
├── .env.example                # Environment variable template
├── .gitignore
├── execute.txt                 # Watcher agent specification document
└── README.md                   # This file
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- A Groq API key (free tier — [console.groq.com](https://console.groq.com))

### Setup

```bash
# 1. Create virtual environment
python -m venv .venv

# 2. Activate it
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure
copy .env.example .env
# Edit .env and set your GROQ_API_KEY

# 5. Run
uvicorn app.main:app --reload --port 3000
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Running the Watcher Agent

The watcher agent is a **separate process** from the FastAPI rule-authoring app.
They share only the `data/` folder.

### Prerequisites

- Python 3.11+ on Windows
- `pywin32` installed (`pip install -r requirements.txt`)
- For the **Security** log channel: run as Administrator or add your account
  to the **Event Log Readers** group
- For **Sysmon** events: [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
  must be installed on the monitored host

### Two-terminal setup

```powershell
# Terminal 1 — rule authoring console (existing)
uvicorn app.main:app --reload --port 3000

# Terminal 2 — the watcher agent (new)
python -m watcher.main
```

### Watcher environment variables (in `.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `WATCHER_DRY_RUN` | `true` | **Safety**: log destructive actions instead of executing them |
| `WATCHER_COLLECTORS` | `system,wmi,registry_fim,inventory` | Enabled plugins; add security/sysmon when privileged and installed |
| `WATCHER_MAX_DESTRUCTIVE_PER_MINUTE` | `5` | Circuit breaker for kill/isolate actions |
| `WATCHER_EVIDENCE_RETENTION_DAYS` | `30` | Auto-delete evidence files after N days |
| `WATCHER_EVIDENCE_MAX_FILES` | `10000` | Oldest-first hard cap on retained evidence files |
| `WATCHER_EVIDENCE_MAX_TOTAL_MB` | `1024` | Oldest-first hard cap on evidence disk usage |
| `WATCHER_LOG_LEVEL` | `INFO` | Logging verbosity |

Authentication rules such as brute-force login detection require the opt-in
`security` collector, Administrator/Event Log Readers access, and the relevant
Windows audit policy. The standard-user default cannot collect Security 4625.

> **Important**: Keep `WATCHER_DRY_RUN=true` until you have validated your rules
> in dry-run mode and are confident they don't produce false positives. Only flip
> this to `false` deliberately — `kill_process` and `isolate_host` are irreversible.

---

If the watcher main loop encounters an unexpected internal exception it tears
down collectors cleanly and restarts with bounded exponential backoff. A tray
Exit, Ctrl+C, or service stop remains a deliberate clean stop and is not
restarted.

Integrity protection detects accidental edits and modification by processes
that cannot read `data/.integrity.key`. It does not claim to resist a local
Administrator who can read or replace both the records and the key. Production
distribution still requires an organization-owned code-signing certificate and
installer signing outside this source repository.

## API Reference

| Method | Path | Description | Rate Limited |
|--------|------|-------------|:------------:|
| `POST` | `/api/parse-rule` | Full NL → IR pipeline | ✅ 10/min/IP |
| `POST` | `/api/rules/from-yaml` | Author a rule directly in YAML — bypasses the LLM entirely (fallback for when the Groq API limit/quota is hit); same validation/simulation pipeline as an LLM draft | ✅ 30/min/IP |
| `POST` | `/api/rules/approve` | Persist approved rule | ✅ 10/min/IP |
| `POST` | `/api/rules/reject` | Log rejection with reason | ✅ 10/min/IP |
| `GET` | `/api/rules` | List approved rules (paginated) | ❌ |
| `GET` | `/api/context` | Current deployment context | ❌ |
| `GET` | `/api/health` | Health + memory usage | ❌ |

### POST /api/parse-rule

**Request:**
```json
{
    "rule_text": "Alert when powershell runs encoded commands"
}
```

**Response (success):**
```json
{
    "stage": "complete",
    "success": true,
    "ir": {
        "status": "ok",
        "clarification": null,
        "ir": {
            "trigger_event": "process.start",
            "aggregation": null,
            "conditions": [
                {"field": "name", "operator": "==", "value": "powershell.exe"},
                {"field": "command_line", "operator": "contains", "value": "-encodedcommand"}
            ],
            "investigation_steps": ["decode_base64_command", "check_parent_process"],
            "response_actions": [{"type": "alert", "duration": null}],
            "severity": "high",
            "priority": 2,
            "tags": ["powershell", "encoded_command"]
        },
        "explanation": {
            "matched_event": "process.start",
            "inferred_threshold": "single event trigger",
            "assumptions_made": ["matched on -encodedcommand flag"]
        }
    },
    "injection_flags": [],
    "capability": {"capable": true, "gaps": []},
    "simulation": {
        "events": [...],
        "summary": "4/5 events evaluated correctly"
    },
    "meta": {
        "budget_used": 1,
        "response_time_ms": 2340.5,
        "model_used": "llama-3.3-70b-versatile"
    }
}
```

### POST /api/rules/approve

**Request:**
```json
{
    "rule_text": "Alert when powershell runs encoded commands",
    "ir": { ... },
    "injection_flags": [],
    "capability_gaps": []
}
```

### POST /api/rules/reject

**Request:**
```json
{
    "rule_text": "...",
    "ir": { ... },
    "reason": "Conditions are too broad, would cause false positives"
}
```

---

## Module Deep Dive

### `app/config.py` — Configuration
- Uses `pydantic-settings` to load from `.env` file
- Validates `GROQ_API_KEY` exists at first use — fails with a clear field-level error, not a stack trace
- Model names are **config values, not constants** — configurable via environment variables
- Lazy singleton pattern: importing the module doesn't crash; `get_settings()` validates on first call

### `app/context_builder.py` — Deployment Context
- Returns a `DeploymentContext` Pydantic model with OS, collectors, fields, operators, actions, permissions
- This is what grounds the LLM — without it, the model would invent capabilities that don't exist
- In production, this would query the capability manager (v5 §4); here it returns the reference config from the spec
- Returns a fresh `.model_copy()` every time — no shared mutable state

### `app/injection_screener.py` — Injection Screening
- **Tiered contract:**
  - HIGH confidence (prompt overrides, role-play, system prompt extraction, base64 injection) → `safe=False` → pipeline STOPS, LLM never called
  - LOW confidence (cross-rule references, control characters, hex encoding, homoglyphs) → `safe=True, pass_with_warnings=True` → pipeline continues with warning badges
- **Never modifies input** — returns original text unchanged as `flagged_input`
- All pattern matching is plain `re` — no heavy NLP library
- Detects: prompt override phrases, role-play attempts, system prompt references, base64-encoded payloads, hex-encoded content, Unicode homoglyphs, control characters

### `app/json_extractor.py` — JSON Extraction
- Three-step fallback for extracting JSON from LLM output:
  1. `json.loads()` directly
  2. Strip markdown fences (`` ```json ... ``` ``) and retry
  3. Bracket-depth scan: find first `{` to matching `}` (handles prose before/after)
- Correctly handles escaped quotes inside JSON strings
- If Groq's model supports `response_format: json_object`, this module is a fallback, not the primary path

### `app/prompt_builder.py` — Prompt Construction
- Strict system prompt with JSON-only output contract
- Full output schema embedded
- Two worked examples (brute-force auth + encoded PowerShell)
- Deployment context injected as JSON
- If low-confidence injection flags exist, they're appended as context for the model
- Includes `build_correction_message()` and `build_validation_feedback_message()` for retry loops

### `app/semantic_validator.py` — IR Validation
- **Layer 1 (Pydantic):** Structural validation via Pydantic models
  - `Condition`, `Aggregation`, `ResponseAction`, `Explanation`, `RuleIR`, `ParseResult`
  - Type checking, severity enum, priority range (1–10), time-window regex (`^\d+[smhd]$`) — all declarations, not hand-written checks
  - `ValidationError` lists exactly which field failed and why → fed back to LLM on retry
- **Layer 2 (Context):** `validate_against_context()` checks:
  - All fields exist in `supported_fields`
  - All operators are in `supported_operators`
  - All response actions are in `supported_actions`
  - Aggregation keys exist in supported fields
  - Duration formats are valid

### `app/capability_checker.py` — Capability Verification
- Cross-references IR's trigger event against `installed_collectors`
- Checks that condition fields come from selected log sources
- Verifies user has permissions for the rule's severity level
- Verifies user has permissions for each response action
- Returns gaps shown in the review UI before the reviewer can approve

### `app/rule_simulator.py` — Synthetic Event Simulation
- Generates 3–5 synthetic events per rule:
  - 2–3 that SHOULD trigger (conditions matched)
  - 1–2 that SHOULD NOT trigger (conditions deliberately mismatched)
- Evaluates conditions against each event using the rule's operators
- All data is request-scoped — nothing persisted or cached
- Results shown in the review UI's simulation table

### `app/rule_store.py` — JSONL Persistence
- **JSON Lines format** — deliberate upgrade over single JSON array:
  - `append_rule()` is O(1): one `open("a")`, one `write()`, done
  - No read → deserialize → append → reserialize → rewrite cycle
  - `list_rules()` paginates via `itertools.islice` — never loads full file
- Storage files: `data/rules.jsonl` (approved), `data/rejections.jsonl` (rejected)
- Each record has UUID, timestamp, status, full IR, rule text, injection flags, capability gaps

### `app/groq_client.py` — Groq API Client
- Uses `groq.AsyncGroq` — async client so a slow Groq call doesn't block other requests
- **Per-request CallBudget:** max 3 LLM calls per request, tracked via a dataclass passed through the call chain — NOT a module-level variable
- **Retry chain:**
  1. Primary model (temperature=0, structured output)
  2. HTTP 429 → wait `retry-after` → retry primary
  3. Still 429 → fallback to smaller model
  4. Fallback 429 → **terminal failure** → `{"error": "service_unavailable"}`
  5. Bad JSON → json_extractor → correction retry
  6. Invalid IR → validation feedback retry
- **Timeout:** `asyncio.wait_for()` with 30s default on every call
- **Logging:** dev-only, IPs redacted, payloads truncated, written to stdout immediately
- **Model discovery:** `discover_models()` at startup, falls back to defaults if it fails

### `app/main.py` — FastAPI Server
- **Startup:** validates config → discovers models → mounts static files
- **Middleware stack:** security headers → CORS → rate limiter → body size gate (10KB)
- **6 endpoints** covering the full workflow
- **Static files** mounted last (at `/`) so API routes aren't shadowed
- **Memory reporting** in health endpoint using Windows-native `ctypes` (no psutil dependency)

### `public/` — Frontend UI
- **Dark-mode glassmorphism** design with animated grid background
- **Pipeline status** with 5 animated steps: Screening → Context → LLM Parse → Validation → Simulation
- **Injection warning banners** (red for blocked, orange for flagged)
- **JSON syntax highlighting** (regex-based, no library)
- **Explanation panel** with matched event, inferred threshold, and assumptions
- **Simulation results table** with expected vs actual trigger verdicts
- **Approve/Reject** actions that persist to server storage
- **Rule history** loaded from server (`GET /api/rules`)
- **Toast notifications** for feedback

---

## Security Design

| Concern | Mitigation |
|---------|------------|
| API key exposure | Server-side only; `.env` file; never in client code |
| Prompt injection | Tiered screener: HIGH → block, LOW → warn. Human review is the real backstop |
| Input abuse | 500-char hard cap (client + server), 10KB body size gate |
| Rate limiting | 10 req/min/IP on all LLM-calling endpoints via `slowapi` |
| Log leakage | IPs redacted, payloads truncated, dev-only gating |
| LLM output trust | Semantic validator + capability checker + human review — no LLM output reaches storage without passing all three |
| Security headers | X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy |

---

## RAM-Efficiency

| Concern | Solution |
|---------|----------|
| Unbounded arrays | No module-level mutable collections |
| Request-scoped state | Call budgets, IR, Groq responses — all local variables, released after response |
| Rule storage | JSONL append-only, paginated reads, never full-file load |
| Logging | `logging` → stdout, no in-memory buffer |
| Body size | 10KB middleware gate before body is read |
| Timeouts | 30s `asyncio.wait_for()` on every Groq call |
| Dependencies | 6 packages total, no heavy frameworks |

---

## Known Gaps

| Gap | Status | Notes |
|-----|--------|-------|
| Authentication | **Deliberate** | No auth on any endpoint — **this is intentional for localhost-only use**. An `X-API-Key` header check is scaffolded and ready to enable the moment this runs on a network. Do not deploy externally without enabling it. |
| Cost estimator | Deferred | v5 §8 — slots in before capability checker |
| Automated tests | **Implemented** | Minimal pytest smoke suite covering strict/permissive validation, dedup guard, and evidence retention |
| Rule history detail view | **Implemented** | Native Approved Rules tab shows complete records |
| Windows service install | Deferred | `pywin32`'s `win32serviceutil.ServiceFramework` — follow-up once manual run is stable |
| Multi-stage correlation rules | **Implemented** | Bounded ordered 2-5 stage correlations with TTL and join fields |
| Redis-backed aggregation | Deferred | Only needed past single-host scale; plain dict is right for v1 |
| Authoring-time RAG retrieval | **Implemented** | `app/knowledge/` — local SQLite FTS5 catalog grounding rule authoring; never loaded by the watcher at runtime. See `GEKKO_RAG_IMPLEMENTATION_REPORT.md`. |
| TITAN ENDPOINT sensor integration | **Implemented** | `watcher/collectors/titan_sensors.py` tails the 5 native C++ sensors + Correlator. Cleanly no-ops until those sensors are actually run (see TITAN ENDPOINT's own `PROJECT_CONTEXT.md`). |

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `fastapi` | ≥0.100.0 | Async web framework |
| `uvicorn[standard]` | ≥0.25.0 | ASGI server |
| `pydantic-settings` | ≥2.0.0 | Typed `.env` config loading |
| `groq` | ≥0.4.0 | Official Groq API client (async) |
| `slowapi` | ≥0.1.9 | Rate limiting (per-IP) |
| `pywin32` | ≥305 | `win32evtlog` — Windows Event Log subscription (watcher only) |
| `psutil` | ≥5.9.0 | Process tree investigation on rule match (watcher only) |
| `winotify` | ≥1.1.0 | Windows toast notifications for alerts (watcher only) |
| `pystray` | ≥0.19.4 | System tray icon (watcher only) |
| `Pillow` | ≥9.0.0 | Image support for pystray (watcher only) |

---

## License

Internal tool — not published.
