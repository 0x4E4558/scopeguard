/**
 * Nex — form.js
 * Single source of truth for all save logic.
 * Works for both flat sections (identity, period, etc.)
 * and list sections (contacts, assets, etc.).
 */

const SG = (() => {
  let _engId     = null;
  let _sectionId = null;
  let _saveTimer = null;
  let _saveInProgress = false;
  let _panelCollapsed = true;

  const _IDENTITY_SIGN_FIELDS = {
    human: [
      'client_signatory_name',
      'client_signatory_date',
      'tester_lead_signatory_name',
      'tester_lead_signatory_date',
      'tester_principal_signatory_name',
      'tester_principal_signatory_date',
    ],
    cryptoSignatures: [
      'client_signatory_signature',
      'tester_lead_signatory_signature',
      'tester_principal_signatory_signature',
      'document_creator_signature',
    ],
    cryptoKeys: [
      'client_signatory_public_key',
      'tester_lead_signatory_public_key',
      'tester_principal_signatory_public_key',
      'document_creator_public_key',
    ],
  };

  // ── Init ────────────────────────────────────────────────────────────────────

  function init(engId, sectionId) {
    _engId     = engId;
    _sectionId = sectionId;

    _initConditionals();
    _initTagsInputs();
    _initMultiselects();
    _initMultiselectOther();
    _initFindingsPanel();
    _initIdentitySignatureGuardrails();

    // Autosave on any input change — use document-level delegation so
    // dynamically added inputs (new list items) are covered automatically.
    document.addEventListener('change', _onAnyChange);
    document.addEventListener('input',  _onAnyChange);

    // Ctrl/Cmd+S → immediate save
    document.addEventListener('keydown', e => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        clearTimeout(_saveTimer);
        doSave();
      }
    });
  }

  function _onAnyChange(e) {
    const el = e.target;
    // Only trigger for actual form inputs
    if (!el.matches('input, select, textarea')) return;
    // Skip the bare tags-input text field (save triggered on tag add/remove)
    if (el.classList.contains('tags-input')) return;
    // Skip the multiselect Other input (save triggered on Enter / item creation)
    if (el.classList.contains('multiselect-other-input')) return;
    _validateIdentitySignatureInputs(false);
    scheduleAutosave();
  }

  // ── Public: schedule and force save ────────────────────────────────────────

  function scheduleAutosave() {
    clearTimeout(_saveTimer);
    _setStatus('saving');
    _saveTimer = setTimeout(doSave, 600);
  }

  async function doSave() {
    if (_saveInProgress) return;
    _saveInProgress = true;
    // Use SG._collectData if overridden (e.g. technique matrix), else private _collectData
    const data = (typeof SG !== 'undefined' && SG._collectData) ? SG._collectData() : _collectData();
    try {
      const resp = await fetch(
        `/engagement/${_engId}/section/${_sectionId}/save`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ data }),
        }
      );
      if (!resp.ok) throw new Error('Save failed');
      const result = await resp.json();
      _setStatus('saved');
      _updateFindingsPanel(result.findings || []);
      if (result.required_roles) {
        _updateRequiredRolesPanel(result.required_roles);
      }
    } catch (err) {
      _setStatus('error');
      console.error('Save error:', err);
    } finally {
      _saveInProgress = false;
    }
  }

  async function saveAndContinue(nextUrl) {
    if (!_validateIdentitySignatureInputs(true)) {
      _setStatus('error');
      return;
    }
    clearTimeout(_saveTimer);
    await doSave();
    if (nextUrl) window.location.href = nextUrl;
  }

  function _initIdentitySignatureGuardrails() {
    if (_sectionId !== 'identity') return;
    _validateIdentitySignatureInputs(false);
  }

  function _validateIdentitySignatureInputs(showBubble) {
    if (_sectionId !== 'identity') return true;

    const statusEl = document.querySelector('[name="document_status"]');
    const status = String(statusEl?.value || '').toLowerCase();
    const allFields = [
      ..._IDENTITY_SIGN_FIELDS.human,
      ..._IDENTITY_SIGN_FIELDS.cryptoSignatures,
      ..._IDENTITY_SIGN_FIELDS.cryptoKeys,
    ];

    if (status !== 'executed') {
      allFields.forEach(name => _setFieldValidation(name, ''));
      return true;
    }

    let firstInvalid = null;
    const requiredMsg = 'Required when document status is Executed.';

    const validateRequired = (name) => {
      const el = document.querySelector(`[name="${name}"]`);
      if (!el) return;
      const value = String(el.value || '').trim();
      const msg = value ? '' : requiredMsg;
      _setFieldValidation(name, msg);
      if (msg && !firstInvalid) firstInvalid = el;
    };

    _IDENTITY_SIGN_FIELDS.human.forEach(validateRequired);
    _IDENTITY_SIGN_FIELDS.cryptoSignatures.forEach(name => {
      validateRequired(name);
      const el = document.querySelector(`[name="${name}"]`);
      const value = String(el?.value || '').trim();
      if (value && !_looksLikeDetachedSignature(value)) {
        const msg = 'Signature must be hex or base64.';
        _setFieldValidation(name, msg);
        if (!firstInvalid) firstInvalid = el;
      }
    });
    _IDENTITY_SIGN_FIELDS.cryptoKeys.forEach(name => {
      validateRequired(name);
      const el = document.querySelector(`[name="${name}"]`);
      const value = String(el?.value || '').trim();
      if (value && !_looksLikePemPublicKey(value)) {
        const msg = 'Public key must be PEM formatted.';
        _setFieldValidation(name, msg);
        if (!firstInvalid) firstInvalid = el;
      }
    });

    if (showBubble && firstInvalid) firstInvalid.reportValidity();
    return !firstInvalid;
  }

  function _looksLikePemPublicKey(value) {
    return value.includes('-----BEGIN PUBLIC KEY-----')
      && value.includes('-----END PUBLIC KEY-----');
  }

  function _looksLikeDetachedSignature(value) {
    const hexOk = value.length >= 64 && value.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(value);
    const b64Ok = value.length >= 32 && /^[A-Za-z0-9+/=]+$/.test(value);
    return hexOk || b64Ok;
  }

  function _setFieldValidation(name, message) {
    const el = document.querySelector(`[name="${name}"]`);
    if (!el || typeof el.setCustomValidity !== 'function') return;
    el.setCustomValidity(message || '');
    if (message) {
      el.setAttribute('aria-invalid', 'true');
    } else {
      el.removeAttribute('aria-invalid');
    }
  }

  // ── Data collection ─────────────────────────────────────────────────────────
  // Detects list vs flat by presence of #list-container.

  function _collectData() {
    if (document.getElementById('list-container')) {
      return _collectList();
    }
    return _collectFlat();
  }

  function _collectFlat() {
    const data = {};
    const form = document.getElementById('section-form');
    if (!form) return data;

    form.querySelectorAll('[name]:not(:disabled)').forEach(el => {
      if (el.classList.contains('tags-input')) return; // handled below
      if (el.type === 'checkbox') {
        data[el.name] = el.checked;
      } else if (el.value !== '') {
        data[el.name] = el.value;
      } else {
        data[el.name] = null;
      }
    });

    // Tag fields
    form.querySelectorAll('[data-tag-field]').forEach(c => {
      data[c.dataset.tagField] = _getTagValues(c);
    });

    // Multiselects
    form.querySelectorAll('.multiselect-group').forEach(g => {
      data[g.dataset.fieldName] = Array.from(
        g.querySelectorAll('.multiselect-item.selected')
      ).map(el => el.dataset.value);
    });

    return data;
  }

  function _collectList() {
    const items = [];
    document.querySelectorAll('#list-container .list-item').forEach(item => {
      const obj = {};

      // Regular inputs and selects
      item.querySelectorAll('[name]').forEach(el => {
        if (el.classList.contains('tags-input')) return;
        if (el.type === 'checkbox') {
          obj[el.name] = el.checked;
        } else if (el.value !== '') {
          obj[el.name] = el.value;
        }
      });

      // Multiselects
      item.querySelectorAll('.multiselect-group').forEach(g => {
        obj[g.dataset.fieldName] = Array.from(
          g.querySelectorAll('.multiselect-item.selected')
        ).map(el => el.dataset.value);
      });

      // Tag fields
      item.querySelectorAll('[data-tag-field]').forEach(c => {
        obj[c.dataset.tagField] = _getTagValues(c);
      });

      // Only save items that have at least one real text/select value filled in.
      // This prevents blank stubs (only checkboxes = false) from overwriting existing data.
      const hasMeaningfulValue = Object.entries(obj).some(([k, v]) => {
        if (typeof v === 'boolean') return false;          // skip checkbox-only
        if (Array.isArray(v)) return v.length > 0;        // non-empty tag/multiselect
        return v !== null && v !== '' && v !== undefined;  // non-empty string/select
      });
      if (hasMeaningfulValue) items.push(obj);
    });
    return items;
  }

  // ── Status indicator ────────────────────────────────────────────────────────

  function _setStatus(state) {
    const el = document.getElementById('save-status');
    if (!el) return;
    el.className = `save-status ${state}`;
    el.textContent = { saving: 'Saving…', saved: 'Saved', error: 'Save failed' }[state] || '';
    // Clear the indicator once the CSS animation finishes so it doesn't linger
    if (state === 'saved') {
      setTimeout(() => {
        if (el.classList.contains('saved')) {
          el.className = 'save-status';
          el.textContent = '';
        }
      }, 1900); // slightly longer than the 1.8s sg-saved animation
    }
  }

  // ── Conditional visibility ──────────────────────────────────────────────────

  function _initConditionals() {
    _evalAllConditionals();
    // Re-evaluate when any select or checkbox changes
    document.addEventListener('change', e => {
      if (e.target.matches('select, input[type="checkbox"]')) {
        _evalAllConditionals();
      }
    });
  }

  function _evalAllConditionals() {
    document.querySelectorAll('[data-conditional-field]').forEach(group => {
      const condField = group.dataset.conditionalField;
      const condValue = group.dataset.conditionalValue;
      const condValues = (() => {
        try { return JSON.parse(group.dataset.conditionalValues || 'null'); } catch (e) { return null; }
      })();
      const condCond  = group.dataset.conditionalCondition;

      const controller = document.querySelector(
        `[name="${condField}"]:not([data-conditional-field])`
      );
      if (!controller) return;

      let show = false;
      if (condCond === 'present') {
        show = !!controller.value;
      } else if (condValues && Array.isArray(condValues) && condValues.length) {
        const actual = controller.type === 'checkbox'
          ? String(controller.checked)
          : controller.value;
        show = condValues.includes(actual);
      } else {
        const actual = controller.type === 'checkbox'
          ? String(controller.checked)
          : controller.value;
        show = (actual === condValue);
      }

      group.classList.toggle('hidden', !show);
      group.querySelectorAll('input, select, textarea').forEach(el => {
        el.disabled = !show;
      });
    });
  }

  // ── Tags inputs ─────────────────────────────────────────────────────────────

  function _initTagsInputs() {
    document.querySelectorAll('[data-tag-field]').forEach(_setupTagsContainer);
  }

  function _setupTagsContainer(container) {
    const input = container.querySelector('.tags-input');
    if (!input || input._sgWired) return;
    input._sgWired = true;

    input.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ',') {
        e.preventDefault();
        const val = input.value.trim().replace(/,$/, '');
        if (val) _addTag(container, val);
        input.value = '';
      } else if (e.key === 'Backspace' && !input.value) {
        const tags = container.querySelectorAll('.tag');
        if (tags.length) { tags[tags.length - 1].remove(); scheduleAutosave(); }
      }
    });

    container.addEventListener('click', () => input.focus());

    // Wire existing tag remove buttons
    container.querySelectorAll('.tag-remove').forEach(rm => {
      if (!rm._sgWired) {
        rm._sgWired = true;
        rm.addEventListener('click', e => {
          e.stopPropagation();
          rm.closest('.tag').remove();
          scheduleAutosave();
        });
      }
    });
  }

  function _addTag(container, value) {
    const input = container.querySelector('.tags-input');
    const tag   = document.createElement('div');
    tag.className = 'tag';
    const span = document.createElement('span'); span.textContent = value;
    const rm   = document.createElement('span');
    rm.className = 'tag-remove'; rm.textContent = '×'; rm._sgWired = true;
    rm.addEventListener('click', e => {
      e.stopPropagation(); tag.remove(); scheduleAutosave();
    });
    tag.appendChild(span); tag.appendChild(rm);
    container.insertBefore(tag, input);
    scheduleAutosave();
  }

  function _getTagValues(container) {
    return Array.from(
      container.querySelectorAll('.tag span:first-child')
    ).map(s => s.textContent);
  }

  // ── Multiselects ────────────────────────────────────────────────────────────

  function _initMultiselects() {
    document.querySelectorAll('.multiselect-item').forEach(item => {
      if (!item._sgWired) {
        item._sgWired = true;
        // Custom items are removed via their × button, not toggled by click
        if (item.classList.contains('multiselect-custom')) {
          const rm = item.querySelector('.multiselect-remove');
          if (rm && !rm._sgWired) {
            rm._sgWired = true;
            rm.addEventListener('click', e => {
              e.stopPropagation();
              item.remove();
              scheduleAutosave();
            });
          }
        } else {
          item.addEventListener('click', () => {
            item.classList.toggle('selected');
            scheduleAutosave();
          });
        }
      }
    });
  }

  // ── Multiselect "Other" free-text input ─────────────────────────────────────

  function _setupMultiselectOther(input) {
    if (input._sgWired) return;
    input._sgWired = true;
    input.addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      e.preventDefault();
      const val = input.value.trim();
      if (!val) return;
      // Find the associated multiselect group via data-for-group
      const groupName = input.dataset.forGroup;
      const scope = input.closest('.field-group') || input.closest('.list-item-body') || document;
      const group = scope.querySelector(`.multiselect-group[data-field-name="${groupName}"]`);
      if (!group) return;
      // Avoid duplicate entries
      const already = Array.from(group.querySelectorAll('.multiselect-item'))
        .some(el => el.dataset.value.toLowerCase() === val.toLowerCase());
      if (already) { input.value = ''; return; }
      // Build the custom item
      const item = document.createElement('div');
      item.className = 'multiselect-item selected multiselect-custom';
      item.dataset.value = val;
      item.textContent = val;
      const rm = document.createElement('span');
      rm.className = 'multiselect-remove';
      rm.title = 'Remove';
      rm.textContent = '×';
      rm._sgWired = true;
      rm.addEventListener('click', ev => { ev.stopPropagation(); item.remove(); scheduleAutosave(); });
      item.appendChild(rm);
      item._sgWired = true; // handled above; no click-toggle for custom items
      group.appendChild(item);
      input.value = '';
      scheduleAutosave();
    });
  }

  function _initMultiselectOther() {
    document.querySelectorAll('.multiselect-other-input').forEach(_setupMultiselectOther);
  }

  // ── Findings panel ──────────────────────────────────────────────────────────

  function _initFindingsPanel() {
    const header = document.querySelector('.findings-panel-header');
    if (!header) return;
    header.addEventListener('click', () => {
      _panelCollapsed = !_panelCollapsed;
      document.querySelector('.findings-panel')
        .classList.toggle('collapsed', _panelCollapsed);
    });
    document.querySelector('.findings-panel')?.classList.add('collapsed');
    _loadInitialFindings();
  }

  async function _loadInitialFindings() {
    try {
      const resp = await fetch(`/engagement/${_engId}/validate`);
      const data = await resp.json();
      _updateFindingsPanel(data.findings || []);
    } catch (e) { /* silent */ }
  }

  function _updateBlockIndicator(findings) {
    const el = document.getElementById('block-count-indicator');
    if (!el) return;
    const blocks  = findings.filter(f => f.severity === 'BLOCK').length;
    const total   = findings.length;
    if (blocks > 0) {
      el.textContent = '✗ ' + blocks + ' BLOCK' + (blocks !== 1 ? 'S' : '');
      el.style.color      = 'var(--sev-block)';
      el.style.fontWeight = '600';
      el.title = 'Document generation is blocked — visit Pre-flight Report to resolve';
    } else if (total > 0) {
      el.textContent = total + ' finding' + (total !== 1 ? 's' : '');
      el.style.color      = 'var(--sev-clarify)';
      el.style.fontWeight = '500';
      el.title = 'Visit Pre-flight Report to review';
    } else {
      el.textContent      = '✓ clean';
      el.style.color      = 'var(--sev-note)';
      el.style.fontWeight = '400';
      el.title            = '';
    }
  }

  function _updateFindingsPanel(findings) {
    _updateBlockIndicator(findings);

    const body  = document.querySelector('.findings-panel-body');
    const title = document.querySelector('.findings-panel-title');
    if (!body) return;

    const counts = { BLOCK: 0, CLARIFY: 0, MISSING: 0, NOTE: 0 };
    findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

    if (title) {
      const parts = [];
      if (counts.BLOCK)   parts.push(`<span style="color:var(--sev-block)">${counts.BLOCK} BLOCK</span>`);
      if (counts.CLARIFY) parts.push(`<span style="color:var(--sev-clarify)">${counts.CLARIFY} CLARIFY</span>`);
      if (counts.MISSING) parts.push(`<span style="color:var(--sev-missing)">${counts.MISSING} MISSING</span>`);
      if (counts.NOTE)    parts.push(`<span style="color:var(--sev-note)">${counts.NOTE} NOTE</span>`);
      title.innerHTML = `<span>findings</span> ${parts.join(' · ') || '<span style="color:var(--text3)">none</span>'}`;
    }

    body.innerHTML = findings.slice(0, 15).map(f => `
      <div class="mini-finding sev-${f.severity}">
        <span class="rule">${f.rule_id}</span>
        <span class="desc">${_esc(f.description)}</span>
      </div>
    `).join('') + (findings.length > 15
      ? `<div style="color:var(--text3);font-size:0.72rem;padding:6px 8px">+${findings.length - 15} more — see pre-flight report</div>`
      : '');
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  function _esc(str) {
    return String(str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Expose for list-section template use
  function wireNewItem(item) {
    // Wire tag containers
    item.querySelectorAll('[data-tag-field]').forEach(_setupTagsContainer);
    // Wire multiselects (standard items toggle; custom items use remove button)
    item.querySelectorAll('.multiselect-item').forEach(el => {
      if (!el._sgWired) {
        el._sgWired = true;
        if (el.classList.contains('multiselect-custom')) {
          const rm = el.querySelector('.multiselect-remove');
          if (rm && !rm._sgWired) {
            rm._sgWired = true;
            rm.addEventListener('click', e => { e.stopPropagation(); el.remove(); scheduleAutosave(); });
          }
        } else {
          el.addEventListener('click', () => { el.classList.toggle('selected'); scheduleAutosave(); });
        }
      }
    });
    // Wire multiselect Other inputs
    item.querySelectorAll('.multiselect-other-input').forEach(_setupMultiselectOther);
    // Re-evaluate conditionals
    _evalAllConditionals();
    // Do NOT autosave here — save only fires when the user actually fills in a field.
    // Saving an empty item immediately would overwrite existing data with a blank stub.
  }

  // ── Required roles panel live update ──────────────────────────────────────────

  function _updateRequiredRolesPanel(roles) {
    roles.forEach(r => {
      const row  = document.querySelector(`[data-role-row="${r.role}"]`);
      if (!row) return;
      const icon   = row.querySelector('[data-role-icon]');
      const addBtn = row.querySelector('button');

      // Update icon
      if (icon) {
        icon.textContent = r.filled ? '✓' : '!';
        icon.style.color  = r.filled ? 'var(--note)' : 'var(--block)';
      }

      // Update row background
      if (r.filled) {
        row.style.transition  = 'background 0.5s';
        row.style.background  = 'rgba(102,187,106,0.15)';
        row.style.borderColor = 'rgba(102,187,106,0.3)';
        setTimeout(() => {
          row.style.background  = 'rgba(102,187,106,0.04)';
          row.style.borderColor = '';
        }, 900);
        if (addBtn) addBtn.style.display = 'none';
      } else {
        row.style.background  = 'var(--bg2)';
        row.style.borderColor = '';
        if (addBtn) { addBtn.style.display = ''; addBtn.disabled = false; }
      }
    });

    // Update header count
    const filled = roles.filter(r => r.filled).length;
    const countEl = document.querySelector('.required-roles-count');
    if (countEl) countEl.textContent = `${filled} of ${roles.length} defined`;
  }

  return {
    init,
    scheduleAutosave,
    doSave,
    _collectData,        // exposed so technique matrix can override it
    updateFindings: _updateFindingsPanel,
    saveAndContinue,
    wireNewItem,
  };
})();
