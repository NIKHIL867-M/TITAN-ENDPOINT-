/**
 * AI Understanding Layer v5 — Frontend Logic
 *
 * Handles:
 *   - Rule input with char counter (500 max, enforced client + server)
 *   - Pipeline status animation
 *   - API calls via fetch (no heavy HTTP library)
 *   - JSON syntax highlighting (regex-based, no library)
 *   - Approve / Reject / Reset flows
 *   - Rule history from server (GET /api/rules)
 *   - Toast notifications
 */

// ═══════════════════════════════════════════════════════════════════════
// DOM refs
// ═══════════════════════════════════════════════════════════════════════

const DOM = {
    ruleInput:          document.getElementById('rule-input'),
    charCounter:        document.getElementById('char-counter'),
    submitBtn:          document.getElementById('submit-btn'),
    submitText:         document.getElementById('submit-text'),
    submitSpinner:      document.getElementById('submit-spinner'),
    pipeline:           document.getElementById('pipeline'),
    errorBanner:        document.getElementById('error-banner'),
    errorDetail:        document.getElementById('error-detail'),
    injectionWarn:      document.getElementById('injection-warning'),
    injectionTitle:     document.getElementById('injection-title'),
    injectionFlags:     document.getElementById('injection-flags'),
    capabilityGaps:     document.getElementById('capability-gaps'),
    capabilityList:     document.getElementById('capability-list'),
    agentStatusPanel:   document.getElementById('agent-status-panel'),
    agentStatusBadge:   document.getElementById('agent-status-badge'),
    agentStatusBody:    document.getElementById('agent-status-body'),
    results:            document.getElementById('results'),
    irViewer:           document.getElementById('ir-viewer'),
    explEvent:          document.getElementById('expl-event'),
    explThreshold:      document.getElementById('expl-threshold'),
    explAssumptions:    document.getElementById('expl-assumptions'),
    simSummary:         document.getElementById('sim-summary'),
    simTbody:           document.getElementById('sim-tbody'),
    metaBar:            document.getElementById('meta-bar'),
    metaModel:          document.getElementById('meta-model'),
    metaBudget:         document.getElementById('meta-budget'),
    metaTime:           document.getElementById('meta-time'),
    actionBar:          document.getElementById('action-bar'),
    approveBtn:         document.getElementById('approve-btn'),
    rejectReason:       document.getElementById('reject-reason'),
    rejectBtn:          document.getElementById('reject-btn'),
    resetBtn:           document.getElementById('reset-btn'),
    historyContainer:   document.getElementById('history-container'),
    historyCount:       document.getElementById('history-count'),
    toast:              document.getElementById('toast'),
    // — Action Selector panel (Backend_Action_Evidence_Upgrade_Plan §A.4) —
    actionSelectorPanel:   document.getElementById('action-selector-panel'),
    actionSeverityBadge:   document.getElementById('action-severity-badge'),
    actionSuggestionHint:  document.getElementById('action-suggestion-hint'),
    actionCheckboxes:      document.getElementById('action-checkboxes'),
    // — Alerts Feed (Frontend_Tauri_Desktop_Plan) —
    alertsFeedBody:    document.getElementById('alerts-feed-body'),
    alertsCountBadge:  document.getElementById('alerts-count-badge'),
    alertsFeedStatus:  document.getElementById('alerts-feed-status'),
    // — Evidence Modal —
    evidenceModal:      document.getElementById('evidence-modal'),
    evidenceModalTitle: document.getElementById('evidence-modal-title'),
    evidenceModalMeta:  document.getElementById('evidence-modal-meta'),
    evidenceModalContent: document.getElementById('evidence-modal-content'),
    evidenceModalClose:   document.getElementById('evidence-modal-close'),
    evidenceModalBackdrop: document.getElementById('evidence-modal-backdrop'),
    draftStatus:        document.getElementById('draft-status'),
    intermediateEditor: document.getElementById('intermediate-editor'),
    expertJson:         document.getElementById('expert-json'),
    modeWarning:        document.getElementById('mode-warning'),
    draftErrors:        document.getElementById('draft-errors'),
    draftDiff:          document.getElementById('draft-diff'),
    recheckDraft:       document.getElementById('recheck-draft'),
};

// Current parse result (stored for approve/reject)
let currentResult = null;
let currentRuleText = '';
let originalDraft = null;
let currentDraft = null;
let draftValidated = false;
let editMode = null;
let schemaOptions = null;

// ═══════════════════════════════════════════════════════════════════════
// JSON syntax highlighting (regex-based, no library)
// ═══════════════════════════════════════════════════════════════════════

function highlightJSON(obj, indent = 0) {
    const json = JSON.stringify(obj, null, 2);
    return json
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"([^"]+)"(?=\s*:)/g, '<span class="json-key">"$1"</span>')
        .replace(/:\s*"([^"]*?)"/g, ': <span class="json-string">"$1"</span>')
        .replace(/:\s*(\d+\.?\d*)/g, ': <span class="json-number">$1</span>')
        .replace(/:\s*(true|false)/g, ': <span class="json-bool">$1</span>')
        .replace(/:\s*(null)/g, ': <span class="json-null">$1</span>');
}

// ═══════════════════════════════════════════════════════════════════════
// Char counter
// ═══════════════════════════════════════════════════════════════════════

DOM.ruleInput.addEventListener('input', () => {
    const len = DOM.ruleInput.value.length;
    const max = 500;
    DOM.charCounter.textContent = `${len} / ${max}`;
    DOM.charCounter.className = 'char-counter';
    if (len >= max) DOM.charCounter.classList.add('at-limit');
    else if (len >= max * 0.8) DOM.charCounter.classList.add('near-limit');
    DOM.submitBtn.disabled = len === 0 || len > max;
});

// ═══════════════════════════════════════════════════════════════════════
// Example chips
// ═══════════════════════════════════════════════════════════════════════

document.querySelectorAll('.example-chip').forEach(chip => {
    chip.addEventListener('click', () => {
        DOM.ruleInput.value = chip.dataset.rule;
        DOM.ruleInput.dispatchEvent(new Event('input'));
        DOM.ruleInput.focus();
    });
});

// ═══════════════════════════════════════════════════════════════════════
// Pipeline status animation
// ═══════════════════════════════════════════════════════════════════════

const STEPS = ['screening', 'context', 'parsing', 'validating', 'simulating'];

function showPipeline() {
    DOM.pipeline.classList.add('visible');
    STEPS.forEach(s => {
        const el = document.querySelector(`[data-step="${s}"]`);
        el.className = 'pipeline__step';
    });
}

function setStep(stepName, status) {
    const el = document.querySelector(`[data-step="${stepName}"]`);
    if (!el) return;
    el.className = 'pipeline__step';
    if (status) el.classList.add(status);
}

async function animatePipeline(upToStep, finalStatus = 'done') {
    for (const step of STEPS) {
        if (step === upToStep) {
            setStep(step, 'active');
            await sleep(300);
            setStep(step, finalStatus);
            return;
        }
        setStep(step, 'done');
        await sleep(200);
    }
}

async function animateFullPipeline() {
    for (let i = 0; i < STEPS.length; i++) {
        setStep(STEPS[i], 'active');
        await sleep(300);
        setStep(STEPS[i], 'done');
    }
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

// ═══════════════════════════════════════════════════════════════════════
// Reset UI state
// ═══════════════════════════════════════════════════════════════════════

function resetResults() {
    DOM.results.classList.remove('visible');
    DOM.pipeline.classList.remove('visible');
    DOM.errorBanner.classList.remove('visible');
    DOM.injectionWarn.classList.remove('visible', 'blocked', 'flagged');
    DOM.capabilityGaps.classList.remove('visible');
    DOM.actionBar.classList.remove('visible');
    DOM.metaBar.classList.remove('visible');
    if (DOM.actionSelectorPanel) DOM.actionSelectorPanel.style.display = 'none';
    currentResult = null;
    currentRuleText = '';
    originalDraft = null;
    currentDraft = null;
    draftValidated = false;
    editMode = null;
}

// ═══════════════════════════════════════════════════════════════════════
// Main submit flow
// ═══════════════════════════════════════════════════════════════════════

DOM.submitBtn.addEventListener('click', handleSubmit);
DOM.ruleInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !DOM.submitBtn.disabled) {
        e.preventDefault();
        handleSubmit();
    }
});

async function handleSubmit() {
    const ruleText = DOM.ruleInput.value.trim();
    if (!ruleText) return;

    currentRuleText = ruleText;

    // Reset UI
    resetResults();

    // Show loading state
    DOM.submitBtn.disabled = true;
    DOM.submitText.textContent = 'Parsing...';
    DOM.submitSpinner.style.display = 'block';
    DOM.ruleInput.disabled = true;

    showPipeline();

    try {
        // Animate pipeline: screening
        setStep('screening', 'active');
        await sleep(200);

        // Make API call
        const response = await fetch('/api/parse-rule', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_text: ruleText }),
        });

        const data = await response.json();

        // Handle injection BLOCK
        if (response.status === 400 && data.blocked) {
            setStep('screening', 'error');
            showInjectionWarning(data.flags, true);
            showError('Input Blocked', data.message);
            return;
        }

        // Handle rate limit
        if (response.status === 429) {
            await animatePipeline('parsing', 'error');
            showError(
                'Rate Limited',
                `Too many requests. Please wait ${data.retry_after || 60} seconds.`
            );
            return;
        }

        // Handle server error
        if (response.status === 503) {
            await animatePipeline('parsing', 'error');
            showError(
                'Service Unavailable',
                `${data.error}. Retry after ${data.retry_after || 60}s.`
            );
            return;
        }

        if (response.status >= 400) {
            await animatePipeline('parsing', 'error');
            showError('Error', data.detail || data.error || 'Unknown error');
            return;
        }

        // Success path — animate full pipeline
        await animateFullPipeline();

        currentResult = data;

        // Show injection flags (if any low-confidence)
        if (data.injection_flags && data.injection_flags.length > 0) {
            showInjectionWarning(data.injection_flags, false);
        }

        // Show capability gaps — show even if capable=true (UWP warnings may still be present)
        if (data.capability && data.capability.gaps && data.capability.gaps.length > 0) {
            showCapabilityGaps(data.capability.gaps, data.capability.capable);
        }

        // Show results
        showResults(data);

    } catch (err) {
        await animatePipeline('parsing', 'error');
        showError('Network Error', err.message || 'Could not connect to server');
    } finally {
        DOM.submitBtn.disabled = false;
        DOM.submitText.textContent = 'Parse Rule';
        DOM.submitSpinner.style.display = 'none';
        DOM.ruleInput.disabled = false;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Display functions
// ═══════════════════════════════════════════════════════════════════════

function showError(title, detail) {
    DOM.errorBanner.querySelector('.error-banner__title').textContent = `⚠️ ${title}`;
    DOM.errorDetail.textContent = detail;
    DOM.errorBanner.classList.add('visible');
}

function showInjectionWarning(flags, isBlocked) {
    DOM.injectionWarn.classList.add('visible');
    DOM.injectionWarn.classList.add(isBlocked ? 'blocked' : 'flagged');
    DOM.injectionTitle.textContent = isBlocked
        ? '🛑 Input BLOCKED — Injection Detected'
        : '⚠️ Potential Injection Patterns (Low Confidence)';

    DOM.injectionFlags.innerHTML = flags
        .map(f => `<div class="flag-item">${escapeHtml(f)}</div>`)
        .join('');
}

function showCapabilityGaps(gaps, capable = false) {
    DOM.capabilityGaps.classList.add('visible');
    // Use red for blocking gaps, amber for warnings (capable=true but has UWP/advisory gaps)
    DOM.capabilityGaps.classList.toggle('gaps--warning', capable);
    DOM.capabilityList.innerHTML = gaps
        .map(g => `<div class="gap-item">${escapeHtml(g)}</div>`)
        .join('');
}

function showResults(data) {
    DOM.results.classList.add('visible');
    initializeDraftEditor(data);

    // IR Viewer
    if (data.ir) {
        // Show just the IR part (without _validation_errors)
        const irDisplay = { ...data.ir };
        delete irDisplay._validation_errors;
        DOM.irViewer.innerHTML = `<pre>${highlightJSON(irDisplay)}</pre>`;
    } else {
        DOM.irViewer.innerHTML = '<pre style="color: var(--text-dim)">No IR generated</pre>';
    }

    // Explanation
    if (data.ir && data.ir.explanation) {
        const expl = data.ir.explanation;
        DOM.explEvent.textContent = expl.matched_event || '—';
        DOM.explThreshold.textContent = expl.inferred_threshold || '—';
        DOM.explAssumptions.innerHTML = (expl.assumptions_made || [])
            .map(a => `<li>${escapeHtml(a)}</li>`)
            .join('') || '<li>—</li>';
    } else {
        DOM.explEvent.textContent = '—';
        DOM.explThreshold.textContent = '—';
        DOM.explAssumptions.innerHTML = '<li>—</li>';
    }

    // Simulation
    if (data.simulation && data.simulation.events) {
        DOM.simSummary.textContent = data.simulation.summary;
        DOM.simTbody.innerHTML = data.simulation.events
            .map(evt => {
                const match = evt.should_trigger === evt.did_trigger;
                const dataStr = Object.entries(evt.data)
                    .map(([k, v]) => `${k}: ${v}`)
                    .join(', ');
                return `<tr>
                    <td class="event-data" title="${escapeHtml(JSON.stringify(evt.data, null, 2))}">${escapeHtml(dataStr)}</td>
                    <td>${evt.should_trigger
                        ? '<span class="badge badge--info">Trigger</span>'
                        : '<span class="badge badge--warning">No Trigger</span>'
                    }</td>
                    <td>${evt.did_trigger
                        ? '<span class="badge badge--success">Triggered</span>'
                        : '<span class="badge badge--danger">Not Triggered</span>'
                    }</td>
                    <td>${match
                        ? '<span class="badge badge--success">✓ Correct</span>'
                        : '<span class="badge badge--danger">✗ Mismatch</span>'
                    }</td>
                    <td style="font-size:0.8rem;color:var(--text-muted)">${escapeHtml(evt.explanation)}</td>
                </tr>`;
            })
            .join('');
    }

    // Meta bar
    if (data.meta) {
        DOM.metaBar.classList.add('visible');
        DOM.metaModel.textContent = data.meta.model_used || '—';
        DOM.metaBudget.textContent = `${data.meta.budget_used}/3`;
        DOM.metaTime.textContent = `${data.meta.response_time_ms}ms`;
    }

    // — Action Selector panel —
    showActionSelector(data);

    // Action bar
    DOM.actionBar.classList.add('visible');
}

// ═══════════════════════════════════════════════════════════════════════
// Editable IR review
function cloneJSON(value) { return JSON.parse(JSON.stringify(value)); }

async function initializeDraftEditor(data) {
    const inner = data?.ir?.ir;
    if (!inner) return;
    originalDraft = cloneJSON(inner);
    currentDraft = cloneJSON(inner);
    draftValidated = Boolean(data.simulation && data.capability?.capable !== false);
    editMode = null;
    DOM.expertJson.value = JSON.stringify(currentDraft, null, 2);
    setDraftStatus(draftValidated, draftValidated ? 'Freshly validated' : 'Needs validation');
    DOM.recheckDraft.style.display = 'none';
    DOM.draftErrors.hidden = true;
    DOM.draftDiff.hidden = true;
    try {
        const response = await fetch('/api/ir-schema-options');
        if (response.ok) schemaOptions = await response.json();
    } catch (_) { schemaOptions = null; }
    renderIntermediateEditor();
}

function setDraftStatus(valid, label) {
    draftValidated = valid;
    DOM.approveBtn.disabled = !valid;
    DOM.draftStatus.textContent = label;
    DOM.draftStatus.className = `badge ${valid ? 'badge--success' : 'badge--warning'}`;
}

function markDraftDirty(mode) {
    editMode = mode;
    setDraftStatus(false, 'Changed — re-validation required');
    DOM.recheckDraft.style.display = '';
    DOM.draftErrors.hidden = true;
    showDraftDiff();
}

function showDraftDiff() {
    if (!originalDraft || !currentDraft || JSON.stringify(originalDraft) === JSON.stringify(currentDraft)) {
        DOM.draftDiff.hidden = true;
        editMode = null;
        return;
    }
    const changes = [];
    const keys = new Set([...Object.keys(originalDraft), ...Object.keys(currentDraft)]);
    keys.forEach(key => {
        if (JSON.stringify(originalDraft[key]) !== JSON.stringify(currentDraft[key])) changes.push(`• ${key} changed`);
    });
    DOM.draftDiff.textContent = `Edited draft (original LLM reasoning is shown separately):\n${changes.join('\n')}`;
    DOM.draftDiff.hidden = false;
}

function renderIntermediateEditor() {
    if (!currentDraft || !schemaOptions) {
        DOM.intermediateEditor.innerHTML = '<p class="editor-help">Schema options are unavailable. Expert mode remains available.</p>';
        return;
    }
    const event = currentDraft.trigger_event;
    const fields = schemaOptions.fields_by_event[event] || [];
    const eventOptions = schemaOptions.events.map(v => `<option ${v === event ? 'selected' : ''}>${escapeHtml(v)}</option>`).join('');
    const conditions = (currentDraft.conditions || []).map((cond, index) => {
        const field = fields.find(f => f.name === cond.field) || fields[0] || { type:'string' };
        const fieldOptions = fields.map(f => `<option value="${escapeHtml(f.name)}" ${f.name === cond.field ? 'selected' : ''}>${escapeHtml(f.name)}</option>`).join('');
        const operators = schemaOptions.operators_by_field_type[field.type] || [];
        const opOptions = operators.map(op => `<option ${op === cond.operator ? 'selected' : ''}>${escapeHtml(op)}</option>`).join('');
        return `<div class="condition-row" data-condition="${index}">
            <select class="editor-control condition-field">${fieldOptions}</select>
            <select class="editor-control condition-operator">${opOptions}</select>
            <input class="editor-control condition-value" value="${escapeHtml(String(cond.value))}" aria-label="Condition value">
            <button class="btn btn--danger remove-condition" type="button" aria-label="Remove condition">×</button>
        </div>`;
    }).join('');
    DOM.intermediateEditor.innerHTML = `<div class="editor-grid">
        <label class="editor-label">Event<select id="draft-event" class="editor-control">${eventOptions}</select></label>
        <label class="editor-label">Severity<select id="draft-severity" class="editor-control">${schemaOptions.severities.map(v => `<option ${v === currentDraft.severity ? 'selected' : ''}>${v}</option>`).join('')}</select></label>
        <label class="editor-label">Priority<input id="draft-priority" class="editor-control" type="number" min="1" max="10" value="${currentDraft.priority}"></label>
        ${currentDraft.aggregation ? `<label class="editor-label">Window<input id="draft-window" class="editor-control" value="${escapeHtml(currentDraft.aggregation.window)}"></label><label class="editor-label">Threshold<input id="draft-threshold" class="editor-control" value="${escapeHtml(currentDraft.aggregation.threshold)}"></label>` : ''}
    </div><div class="editor-label">Conditions</div><div id="condition-list">${conditions}</div>
    <button id="add-condition" class="btn btn--ghost" type="button">+ Add Condition</button>`;
}

document.querySelectorAll('.mode-tab').forEach(tab => tab.addEventListener('click', () => {
    const mode = tab.dataset.mode;
    if (mode === 'intermediate' && currentDraft) {
        const supported = new Set(['trigger_event','aggregation','conditions','investigation_steps','response_actions','severity','priority','tags','suggested_action','suggested_action_reason']);
        const extra = Object.keys(currentDraft).filter(k => !supported.has(k));
        if (extra.length) {
            DOM.modeWarning.textContent = `Intermediate mode cannot display: ${extra.join(', ')}. Continue in Expert mode or remove those features.`;
            DOM.modeWarning.hidden = false;
            return;
        }
        renderIntermediateEditor();
    }
    DOM.modeWarning.hidden = true;
    document.querySelectorAll('.mode-tab').forEach(t => t.classList.toggle('active', t === tab));
    document.querySelectorAll('.mode-panel').forEach(p => p.classList.toggle('active', p.id === `mode-${mode}`));
    if (mode === 'expert' && currentDraft) DOM.expertJson.value = JSON.stringify(currentDraft, null, 2);
}));

DOM.intermediateEditor.addEventListener('change', event => {
    if (!currentDraft) return;
    if (event.target.id === 'draft-event') {
        currentDraft.trigger_event = event.target.value;
        currentDraft.conditions = [];
        renderIntermediateEditor();
        markDraftDirty('intermediate');
        recheckCurrentDraft();
        return;
    }
    if (event.target.id === 'draft-severity') currentDraft.severity = event.target.value;
    else if (event.target.id === 'draft-priority') currentDraft.priority = Number(event.target.value);
    else if (event.target.id === 'draft-window') currentDraft.aggregation.window = event.target.value;
    else if (event.target.id === 'draft-threshold') currentDraft.aggregation.threshold = event.target.value;
    else {
        const row = event.target.closest('[data-condition]');
        if (row) {
            const index = Number(row.dataset.condition);
            const field = row.querySelector('.condition-field').value;
            currentDraft.conditions[index] = { field, operator: row.querySelector('.condition-operator').value, value: row.querySelector('.condition-value').value };
            if (event.target.classList.contains('condition-field')) renderIntermediateEditor();
        }
    }
    markDraftDirty('intermediate');
    if (!event.target.classList.contains('condition-value') && event.target.id !== 'draft-window' && event.target.id !== 'draft-threshold') recheckCurrentDraft();
});

DOM.intermediateEditor.addEventListener('click', event => {
    if (!currentDraft || !schemaOptions) return;
    if (event.target.id === 'add-condition') {
        const field = schemaOptions.fields_by_event[currentDraft.trigger_event]?.[0];
        if (!field) return;
        currentDraft.conditions.push({field: field.name, operator: schemaOptions.operators_by_field_type[field.type][0], value: ''});
    } else if (event.target.classList.contains('remove-condition')) {
        currentDraft.conditions.splice(Number(event.target.closest('[data-condition]').dataset.condition), 1);
    } else return;
    renderIntermediateEditor(); markDraftDirty('intermediate'); recheckCurrentDraft();
});

DOM.expertJson.addEventListener('input', () => markDraftDirty('expert'));
DOM.recheckDraft.addEventListener('click', () => {
    if (document.getElementById('mode-expert').classList.contains('active')) {
        try { currentDraft = JSON.parse(DOM.expertJson.value); }
        catch (error) { setDraftStatus(false, 'Invalid JSON'); DOM.draftErrors.textContent = error.message; DOM.draftErrors.hidden = false; return; }
    }
    recheckCurrentDraft();
});

async function recheckCurrentDraft() {
    if (!currentDraft) return;
    setDraftStatus(false, 'Checking…');
    try {
        const response = await fetch('/api/rules/draft-check', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({draft:currentDraft})});
        const result = await response.json();
        if (result.valid) {
            currentDraft = result.normalized_draft || currentDraft;
            currentResult.simulation = result.simulation;
            renderDraftSimulation(result.simulation);
            DOM.draftErrors.hidden = true;
            DOM.recheckDraft.style.display = 'none';
            setDraftStatus(true, 'Freshly validated');
            showDraftDiff();
        } else {
            setDraftStatus(false, 'Validation failed');
            DOM.draftErrors.textContent = (result.errors || ['Draft check failed']).join('\n');
            DOM.draftErrors.hidden = false;
        }
    } catch (error) { setDraftStatus(false, 'Check unavailable'); DOM.draftErrors.textContent = error.message; DOM.draftErrors.hidden = false; }
}

function renderDraftSimulation(simulation) {
    if (!simulation) return;
    DOM.simSummary.textContent = simulation.summary;
    DOM.simTbody.innerHTML = (simulation.events || []).map(evt => `<tr><td class="event-data">${escapeHtml(Object.entries(evt.data).map(([k,v]) => `${k}: ${v}`).join(', '))}</td><td>${evt.should_trigger ? 'Trigger' : 'No Trigger'}</td><td>${evt.did_trigger ? 'Triggered' : 'Not Triggered'}</td><td>${evt.should_trigger === evt.did_trigger ? '✓ Correct' : '✕ Mismatch'}</td><td>${escapeHtml(evt.explanation)}</td></tr>`).join('');
}

// Action edits are structural changes to the shared draft.
DOM.actionCheckboxes?.addEventListener('change', () => {
    if (!currentDraft) return;
    currentDraft.response_actions = getSelectedActions().map(type => ({type, duration:null}));
    markDraftDirty(editMode || 'intermediate');
    recheckCurrentDraft();
});

// Approve / Reject / Reset
// ═══════════════════════════════════════════════════════════════════════

DOM.approveBtn.addEventListener('click', async () => {
    if (!currentResult || !currentResult.ir) return;
    if (!draftValidated || !currentDraft) {
        showToast('Re-validate the current draft before approval.', 'error');
        return;
    }

    DOM.approveBtn.disabled = true;

    // Collect human-selected response actions from the checkboxes
    const selectedActions = getSelectedActions();

    try {
        const response = await fetch('/api/rules/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rule_text: currentRuleText,
                ir: { ...currentResult.ir, ir: currentDraft },
                original_ir: { ...currentResult.ir, ir: originalDraft },
                edit_mode: editMode,
                injection_flags: currentResult.injection_flags || [],
                capability_gaps: currentResult.capability?.gaps || [],
                response_actions: selectedActions,
            }),
        });

        const data = await response.json();

        if (response.ok) {
            showToast(`Rule approved: ${data.rule_id.slice(0, 8)}… Actions: ${selectedActions.join(', ') || 'alert'}`, 'success');
            loadHistory();
        } else {
            const errMsg = data.detail?.messages?.join('; ') || data.detail || 'Unknown error';
            showToast('Approval failed: ' + errMsg, 'error');
        }
    } catch (err) {
        showToast('Network error: ' + err.message, 'error');
    } finally {
        DOM.approveBtn.disabled = false;
    }
});

DOM.rejectBtn.addEventListener('click', async () => {
    const reason = DOM.rejectReason.value.trim();
    if (!reason) {
        DOM.rejectReason.focus();
        DOM.rejectReason.style.borderColor = 'var(--danger)';
        setTimeout(() => DOM.rejectReason.style.borderColor = '', 2000);
        return;
    }

    DOM.rejectBtn.disabled = true;

    try {
        const response = await fetch('/api/rules/reject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rule_text: currentRuleText,
                ir: currentResult?.ir || null,
                reason: reason,
                injection_flags: currentResult?.injection_flags || [],
            }),
        });

        const data = await response.json();

        if (response.ok) {
            showToast('Rule rejected', 'success');
            DOM.rejectReason.value = '';
        } else {
            showToast('Rejection failed: ' + (data.detail || 'Unknown error'), 'error');
        }
    } catch (err) {
        showToast('Network error: ' + err.message, 'error');
    } finally {
        DOM.rejectBtn.disabled = false;
    }
});

DOM.resetBtn.addEventListener('click', () => {
    resetResults();
    DOM.ruleInput.value = '';
    DOM.ruleInput.dispatchEvent(new Event('input'));
    DOM.ruleInput.focus();
});

// ═══════════════════════════════════════════════════════════════════════
// Rule history (from server, not localStorage)
// ═══════════════════════════════════════════════════════════════════════

async function loadHistory() {
    try {
        const response = await fetch('/api/rules?page=0&limit=20');
        const data = await response.json();

        DOM.historyCount.textContent = data.total || 0;

        if (!data.rules || data.rules.length === 0) {
            DOM.historyContainer.innerHTML = '<div class="history-empty">No approved rules yet</div>';
            return;
        }

        DOM.historyContainer.innerHTML = '<div class="history-list">' +
            data.rules.map(rule => {
                const time = new Date(rule.created_at).toLocaleString();
                const severity = rule.ir?.ir?.severity || rule.ir?.severity || '—';
                const badgeClass = {
                    'low': 'badge--info',
                    'medium': 'badge--warning',
                    'high': 'badge--danger',
                    'critical': 'badge--danger',
                }[severity] || 'badge--info';

                return `<div class="history-item" onclick="this.querySelector('.history-detail')?.classList.toggle('visible')">
                    <div class="history-item__header">
                        <span class="badge ${badgeClass}">${escapeHtml(severity)}</span>
                        <span class="history-item__time">${escapeHtml(time)}</span>
                    </div>
                    <div class="history-item__text">${escapeHtml(rule.rule_text)}</div>
                </div>`;
            }).join('') +
        '</div>';
    } catch (err) {
        DOM.historyContainer.innerHTML =
            '<div class="history-empty">Could not load history</div>';
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Toast
// ═══════════════════════════════════════════════════════════════════════

function showToast(message, type = 'success') {
    DOM.toast.textContent = message;
    DOM.toast.className = `toast toast--${type}`;
    requestAnimationFrame(() => {
        DOM.toast.classList.add('show');
    });
    setTimeout(() => {
        DOM.toast.classList.remove('show');
    }, 3500);
}

// ═══════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════

function escapeHtml(str) {
    if (typeof str !== 'string') str = String(str);
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

// ═══════════════════════════════════════════════════════════════════════
// Agent Status Panel
// ═══════════════════════════════════════════════════════════════════════

async function loadAgentStatus() {
    if (!DOM.agentStatusPanel) return;
    try {
        const response = await fetch('/api/agent-status');
        const data = await response.json();

        const isRunning = data.active_collectors && data.active_collectors.length > 0;
        const agentNotRunning = data.status === 'agent_not_running';

        // Update badge
        DOM.agentStatusBadge.textContent = agentNotRunning
            ? 'Agent Offline'
            : `${data.active_collectors.length} Active`;
        DOM.agentStatusBadge.className = `badge ${
            agentNotRunning ? 'badge--danger' : 'badge--success'
        }`;

        let html = '';

        if (agentNotRunning) {
            html = '<div class="agent-offline">⚪ Watcher Agent is not running. Start it with: <code>python -m watcher.main</code></div>';
        } else {
            // Active collectors
            html += '<div class="agent-section"><div class="agent-section__label">Active Collectors</div><div class="agent-chips">';
            (data.active_collectors || []).forEach(c => {
                html += `<span class="agent-chip agent-chip--active">✅ ${escapeHtml(c)}</span>`;
            });
            html += '</div></div>';

            // Failed collectors
            const failed = data.failed_collectors || {};
            if (Object.keys(failed).length > 0) {
                html += '<div class="agent-section"><div class="agent-section__label">Failed Collectors</div><div class="agent-chips">';
                Object.entries(failed).forEach(([name, probs]) => {
                    const problems = Array.isArray(probs) ? probs.join('; ') : String(probs);
                    html += `<span class="agent-chip agent-chip--failed" title="${escapeHtml(problems)}">❌ ${escapeHtml(name)}</span>`;
                });
                html += '</div></div>';
            }

            // Supported events
            html += '<div class="agent-section"><div class="agent-section__label">Monitored Event Types</div><div class="agent-chips">';
            (data.supported_events || []).forEach(e => {
                html += `<span class="agent-chip agent-chip--event">${escapeHtml(e)}</span>`;
            });
            html += '</div></div>';

            // Unsupported events (collapsed)
            if ((data.unsupported_events || []).length > 0) {
                html += '<div class="agent-section"><div class="agent-section__label" style="color:var(--text-muted)">Unmonitored Event Types</div><div class="agent-chips">';
                data.unsupported_events.forEach(e => {
                    html += `<span class="agent-chip agent-chip--unsupported">${escapeHtml(e)}</span>`;
                });
                html += '</div></div>';
            }
        }

        DOM.agentStatusBody.innerHTML = html;
        DOM.agentStatusPanel.classList.add('visible');
    } catch (err) {
        if (DOM.agentStatusPanel) {
            DOM.agentStatusBadge.textContent = 'Error';
            DOM.agentStatusBadge.className = 'badge badge--danger';
            DOM.agentStatusBody.innerHTML = '<div class="agent-offline">Could not reach server</div>';
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Action Selector Panel (Backend_Action_Evidence_Upgrade_Plan §A.4)
// ═══════════════════════════════════════════════════════════════════════

/** Cached action options from /api/action-options — fetched once on first use */
let _cachedActionOptions = null;

async function fetchActionOptions() {
    if (_cachedActionOptions) return _cachedActionOptions;
    try {
        const resp = await fetch('/api/action-options');
        if (resp.ok) {
            _cachedActionOptions = await resp.json();
        }
    } catch (e) {
        console.warn('Failed to fetch action options:', e);
    }
    return _cachedActionOptions || [
        { value: 'alert', label: 'Send an alert', description: 'Always recommended — low risk', destructive: false },
        { value: 'kill_process', label: 'Kill the process', description: 'Immediate and irreversible', destructive: true },
        { value: 'isolate_host', label: 'Isolate the host', description: 'Blocks outbound network', destructive: true },
    ];
}

async function showActionSelector(data) {
    if (!DOM.actionSelectorPanel || !data.ir) return;

    const options = await fetchActionOptions();
    const ir = data.ir.ir || data.ir;
    const severity = ir.severity || '—';
    const suggestedActions = ir.suggested_action || [];
    const suggestedReason = ir.suggested_action_reason || '';

    // Update severity badge
    const severityClasses = {
        low: 'badge--info',
        medium: 'badge--warning',
        high: 'badge--danger',
        critical: 'badge--danger',
    };
    DOM.actionSeverityBadge.textContent = `Severity: ${severity.toUpperCase()}`;
    DOM.actionSeverityBadge.className = `badge ${severityClasses[severity] || 'badge--info'}`;

    // Show LLM suggestion hint
    if (suggestedReason) {
        DOM.actionSuggestionHint.innerHTML =
            `<em>💡 LLM suggests: <strong>${suggestedActions.join(', ') || 'alert'}</strong></em><br>` +
            `<small style="color:var(--text-muted)">${escapeHtml(suggestedReason)}</small>`;
    } else {
        DOM.actionSuggestionHint.innerHTML = '';
    }

    // Render checkboxes — pre-check the LLM-suggested actions
    DOM.actionCheckboxes.innerHTML = options.map(opt => {
        const isChecked = suggestedActions.includes(opt.value) || (suggestedActions.length === 0 && opt.value === 'alert');
        const destructiveClass = opt.destructive ? 'action-checkbox--destructive' : '';
        return `
            <label class="action-checkbox ${destructiveClass}" id="action-cb-${opt.value}">
                <input type="checkbox" name="action" value="${opt.value}" ${isChecked ? 'checked' : ''}>
                <span class="action-checkbox__label">${escapeHtml(opt.label)}</span>
                <span class="action-checkbox__desc">${escapeHtml(opt.description)}</span>
            </label>`;
    }).join('');

    DOM.actionSelectorPanel.style.display = 'block';
}

function getSelectedActions() {
    if (!DOM.actionCheckboxes) return ['alert'];
    const checked = DOM.actionCheckboxes.querySelectorAll('input[name="action"]:checked');
    const actions = Array.from(checked).map(cb => cb.value);
    return actions.length > 0 ? actions : ['alert'];
}

// ═══════════════════════════════════════════════════════════════════════
// Alerts Feed (Frontend_Tauri_Desktop_Plan — AlertsFeed component)
// ═══════════════════════════════════════════════════════════════════════

let _alertsLastSince = '';
let _alertsFeedCount = 0;

async function pollAlerts() {
    if (!DOM.alertsFeedBody) return;
    try {
        const url = _alertsLastSince
            ? `/api/alerts?limit=50&since=${encodeURIComponent(_alertsLastSince)}`
            : '/api/alerts?limit=50';

        const resp = await fetch(url);
        if (!resp.ok) {
            DOM.alertsFeedStatus.textContent = 'Error';
            DOM.alertsFeedStatus.className = 'badge badge--danger';
            return;
        }
        const data = await resp.json();

        DOM.alertsFeedStatus.textContent = 'Live';
        DOM.alertsFeedStatus.className = 'badge badge--success';

        if (data.alerts && data.alerts.length > 0) {
            // Track newest timestamp for incremental polling
            const newestAlert = data.alerts[0];
            if (newestAlert.fired_at) {
                _alertsLastSince = newestAlert.fired_at;
            }

            _alertsFeedCount += data.alerts.length;
            if (_alertsFeedCount > 0 && DOM.alertsCountBadge) {
                DOM.alertsCountBadge.textContent = `${_alertsFeedCount} total`;
                DOM.alertsCountBadge.style.display = 'inline-block';
            }

            // Prepend new alerts (newest first, then existing)
            const existingHTML = DOM.alertsFeedBody.innerHTML;
            const isFirstLoad = existingHTML.includes('alerts-feed-empty');
            const newHTML = data.alerts.map(a => renderAlert(a)).join('');

            if (isFirstLoad) {
                DOM.alertsFeedBody.innerHTML = newHTML;
            } else {
                DOM.alertsFeedBody.innerHTML = newHTML + existingHTML;
            }
        } else if (_alertsFeedCount === 0) {
            // No alerts yet — keep the placeholder
        }
    } catch (err) {
        DOM.alertsFeedStatus.textContent = 'Offline';
        DOM.alertsFeedStatus.className = 'badge badge--danger';
    }
}

function renderAlert(alert) {
    const time = alert.fired_at ? new Date(alert.fired_at).toLocaleTimeString() : '—';
    const severityClass = {
        low: 'badge--info',
        medium: 'badge--warning',
        high: 'badge--danger',
        critical: 'badge--danger',
    }[alert.severity] || 'badge--info';

    const dryRunBadge = alert.dry_run ? '<span class="badge badge--warning" style="font-size:0.65rem">DRY-RUN</span>' : '';
    const actions = (alert.action_results || []).map(r => r.action).join(', ') || '—';
    const evidenceBtn = alert.instance_id
        ? `<button class="btn btn--ghost btn--xs" onclick="showEvidence('${escapeHtml(alert.instance_id)}')" title="View evidence">🔍</button>`
        : '';

    return `
        <div class="alert-item alert-item--${alert.severity || 'medium'}">
            <div class="alert-item__header">
                <span class="badge ${severityClass}">${escapeHtml((alert.severity || 'unknown').toUpperCase())}</span>
                ${dryRunBadge}
                <span class="alert-item__time">${escapeHtml(time)}</span>
                ${evidenceBtn}
            </div>
            <div class="alert-item__summary">${escapeHtml(alert.summary || alert.rule_text || '—')}</div>
            <div class="alert-item__meta">
                <span>Host: ${escapeHtml(alert.host || '—')}</span>
                <span>Event: ${escapeHtml(alert.event_type || '—')}</span>
                <span>Actions: ${escapeHtml(actions)}</span>
            </div>
        </div>`;
}

// ═══════════════════════════════════════════════════════════════════════
// Evidence Viewer Modal (Frontend_Tauri_Desktop_Plan — EvidenceViewer)
// ═══════════════════════════════════════════════════════════════════════

async function showEvidence(instanceId) {
    if (!DOM.evidenceModal) return;

    DOM.evidenceModal.style.display = 'flex';
    DOM.evidenceModalMeta.innerHTML = `<p style="color:var(--text-muted)">Loading evidence for instance ${escapeHtml(instanceId.slice(0, 8))}…</p>`;
    DOM.evidenceModalContent.innerHTML = '';

    try {
        const resp = await fetch(`/api/evidence/${encodeURIComponent(instanceId)}`);
        if (!resp.ok) {
            const errData = await resp.json().catch(() => ({}));
            DOM.evidenceModalMeta.innerHTML = `<p style="color:var(--danger)">⚠ ${escapeHtml(errData.detail || 'Evidence not found')}</p>`;
            return;
        }

        const evidence = await resp.json();

        // Meta summary at top
        DOM.evidenceModalMeta.innerHTML = `
            <div class="evidence-meta-grid">
                <div><strong>Rule:</strong> ${escapeHtml(evidence.rule_name || '—')}</div>
                <div><strong>Severity:</strong> <span class="badge badge--${evidence.severity === 'critical' || evidence.severity === 'high' ? 'danger' : evidence.severity === 'medium' ? 'warning' : 'info'}">${escapeHtml((evidence.severity || '—').toUpperCase())}</span></div>
                <div><strong>Matched At:</strong> ${evidence.matched_at ? new Date(evidence.matched_at).toLocaleString() : '—'}</div>
                <div><strong>Event Type:</strong> ${escapeHtml(evidence.event_type || '—')}</div>
                <div><strong>Collector:</strong> ${escapeHtml(evidence.source_collector || '—')}</div>
                <div><strong>Instance ID:</strong> ${escapeHtml(evidence.instance_id?.slice(0, 12) || '—')}…</div>
            </div>`;

        // Full JSON
        DOM.evidenceModalContent.innerHTML = `<pre>${highlightJSON(evidence)}</pre>`;
    } catch (err) {
        DOM.evidenceModalMeta.innerHTML = `<p style="color:var(--danger)">⚠ Network error: ${escapeHtml(err.message)}</p>`;
    }
}

// Evidence modal close handlers
if (DOM.evidenceModalClose) {
    DOM.evidenceModalClose.addEventListener('click', () => {
        DOM.evidenceModal.style.display = 'none';
    });
}
if (DOM.evidenceModalBackdrop) {
    DOM.evidenceModalBackdrop.addEventListener('click', () => {
        DOM.evidenceModal.style.display = 'none';
    });
}
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && DOM.evidenceModal && DOM.evidenceModal.style.display !== 'none') {
        DOM.evidenceModal.style.display = 'none';
    }
});

// ═══════════════════════════════════════════════════════════════════════
// Init
// ═══════════════════════════════════════════════════════════════════════

loadHistory();
loadAgentStatus();
// Refresh agent status every 30s
setInterval(loadAgentStatus, 30000);
// Poll alerts every 10s (Frontend_Tauri_Desktop_Plan v1 polling approach)
pollAlerts();
setInterval(pollAlerts, 10000);
