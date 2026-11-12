/**
 * Romanian UI for local key derivation and file upload.
 * The panel never receives raw key material — only masks and public addresses.
 */
import { planCheck } from './plan.js';
import { registerSecrets, redact, containsSecret } from './privacy.js';
import {
  FileReadError,
  extractKeysFromFile,
  MAX_DOCUMENT_BYTES,
  MAX_FILE_BYTES,
  fileReadLimitMessage,
  formatUploadLimit,
} from './read-files.js';

const valueSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
let programmatic = 0;
let currentAbort = null;
let summaryMode = 'idle';
let runId = 0;

function setReactValue(textarea, value) {
  programmatic += 1;
  try {
    valueSetter.call(textarea, value);
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
  } finally {
    programmatic -= 1;
  }
}

function waitForValue(textarea, value) {
  if (textarea.value === value) return Promise.resolve();
  return new Promise((resolve) => {
    let frames = 0;
    const tick = () => {
      frames += 1;
      if (!textarea.isConnected || textarea.value === value || frames > 40) resolve();
      else requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
}

function formatBytes(bytes) {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function progressCopy(fileName, index, total, event) {
  const name = redact(fileName);
  const prefix = total > 1 ? `Fișier ${index} din ${total}. ` : '';
  if (event.phase === 'pdf') {
    return `${prefix}Se extrage textul din „${name}”… pagina ${event.page} din ${event.pages}`;
  }
  if (event.phase === 'docx') return `${prefix}Se citește documentul „${name}”…`;
  const pct = event.total ? Math.round((event.loaded / event.total) * 100) : 0;
  return `${prefix}Se citește „${name}”… ${pct}% (${formatBytes(event.loaded)} / ${formatBytes(event.total)})`;
}

function errorCopy(error) {
  const name = redact(error.fileName || 'fișier');
  if (error.code === 'too-big' || error.code === 'too-big-document') {
    return fileReadLimitMessage(error.code, name);
  }
  if (error.code === 'unsupported') {
    return `„${name}” nu este un format acceptat. Folosește PDF, TXT, CSV, JSON, LOG, MD, HTML sau DOCX.`;
  }
  if (error.code === 'pdf') {
    return `Nu am putut citi „${name}”. PDF-urile scanate sau protejate nu au text de extras.`;
  }
  if (error.code === 'docx') return `Nu am putut citi documentul „${name}”.`;
  return 'Citirea a eșuat. Conținutul nu a fost trimis.';
}

function panelElements(panel) {
  return {
    progress: panel.querySelector('[data-testid="key-progress"]'),
    bar: panel.querySelector('[data-testid="key-progress-bar"]'),
    label: panel.querySelector('[data-testid="key-progress-label"]'),
    summary: panel.querySelector('[data-testid="key-summary"]'),
    file: panel.querySelector('[data-testid="key-file-input"]'),
  };
}

function setBusy(panel, busy) {
  const { progress, file } = panelElements(panel);
  progress.hidden = !busy;
  file.disabled = busy;
  panel.classList.toggle('is-busy', busy);
}

function showProgress(panel, text, ratio) {
  const { progress, bar, label } = panelElements(panel);
  progress.hidden = false;
  label.textContent = text;
  bar.style.width = `${Math.max(0, Math.min(100, Math.round((ratio || 0) * 100)))}%`;
}

function showNote(panel, text, kind) {
  summaryMode = kind || 'note';
  const { summary } = panelElements(panel);
  summary.replaceChildren();
  const paragraph = document.createElement('p');
  paragraph.className = kind === 'error' ? 'key-error' : 'key-lead';
  paragraph.textContent = text;
  summary.appendChild(paragraph);
}

function renderSummary(panel, plan, intro, { pending = false } = {}) {
  summaryMode = pending ? 'preview' : 'result';
  const { summary } = panelElements(panel);
  summary.replaceChildren();

  const lead = document.createElement('p');
  lead.className = 'key-lead';
  lead.textContent = intro;
  summary.appendChild(lead);

  const count = document.createElement('p');
  count.className = 'key-count';
  const omitted = plan.derivedOmitted > 0
    ? ` ${plan.derivedOmitted} ${plan.derivedOmitted === 1 ? 'adresă nu încape' : 'adrese nu încap'} în limita de ${20} de identificatori.`
    : '';
  const verb = pending ? 'vor fi verificate' : 'sunt trimise la verificare';
  count.textContent = `Chei găsite: ${plan.foundCount}. Adrese derivate care ${verb}: ${plan.checkedCount} din ${plan.derivedCount}.${omitted}`;
  summary.appendChild(count);

  const list = document.createElement('ul');
  list.className = 'key-list';
  const visible = plan.entries.slice(0, 24);
  for (const entry of visible) {
    const item = document.createElement('li');
    item.className = 'key-row';
    const mask = document.createElement('span');
    mask.className = 'key-mask mono';
    mask.dataset.testid = 'key-mask';
    const format = entry.format === 'wif' ? 'Bitcoin WIF' : entry.format === 'solana' ? 'Solana' : 'EVM';
    mask.textContent = `${format} · ${entry.mask}`;
    item.appendChild(mask);
    const addresses = document.createElement('ul');
    addresses.className = 'key-addresses';
    for (const address of entry.addresses) {
      const row = document.createElement('li');
      const value = document.createElement('span');
      value.className = 'key-address mono';
      value.dataset.testid = 'key-derived-address';
      value.dataset.chain = address.chain;
      value.textContent = address.address;
      row.append(`${address.label}: `);
      row.appendChild(value);
      if (!address.included) {
        const skip = document.createElement('span');
        skip.className = 'key-skip';
        skip.textContent = ' — peste limita de verificare';
        row.appendChild(skip);
      }
      addresses.appendChild(row);
    }
    item.appendChild(addresses);
    list.appendChild(item);
  }
  summary.appendChild(list);
  if (plan.entries.length > visible.length) {
    const more = document.createElement('p');
    more.className = 'key-note';
    more.textContent = `Și încă ${plan.entries.length - visible.length} chei, neafișate aici. Cheile complete nu sunt reafișate.`;
    summary.appendChild(more);
  }
  if (plan.hashEchoCount > 0) {
    const note = document.createElement('p');
    note.className = 'key-note';
    note.textContent = 'Șirul de 64 hex rămâne clasificat local ca hash de tranzacție, fără interogare de sold pentru hash. Linkurile către explorere sunt oprite, ca să nu părăsească browserul. Adresa de mai sus este verificată doar dacă șirul este o cheie privată validă.';
    summary.appendChild(note);
  }
  const local = document.createElement('p');
  local.className = 'key-note';
  local.textContent = 'Derivarea s-a făcut în acest browser. Cheia nu este trimisă, salvată sau pusă în adresa paginii. Frazele mnemonic nu sunt derivate.';
  summary.appendChild(local);
}

async function runChecker(plan) {
  const textarea = document.getElementById('address-input');
  if (!textarea) return false;
  registerSecrets(plan.secrets);
  if (!plan.submissionText.trim()) return false;
  setReactValue(textarea, plan.submissionText);
  await waitForValue(textarea, plan.submissionText);
  const liveArea = document.getElementById('address-input');
  const liveButton = document.querySelector('[data-testid="button-scan"]');
  if (!liveArea || !liveButton || liveButton.disabled) return false;
  if (liveArea.value !== plan.submissionText) {
    setReactValue(liveArea, plan.submissionText);
    await waitForValue(liveArea, plan.submissionText);
  }
  liveButton.dataset.clarKeyBypass = '1';
  liveButton.click();
  const after = document.getElementById('address-input');
  if (after && after.value !== plan.maskedText) setReactValue(after, plan.maskedText);
  return true;
}

async function submitPlan(panel, plan, intro) {
  registerSecrets(plan.secrets);
  if (containsSecret(intro)) intro = redact(intro);
  renderSummary(panel, plan, intro);
  if (document.querySelector('[data-testid="button-stop"]')) {
    showNote(panel, 'O verificare este deja în curs. Cheile găsite nu au fost trimise.', 'error');
    return;
  }
  try {
    const started = await runChecker(plan);
    if (!started) {
      showNote(panel, 'Nu am putut porni verificarea adreselor derivate. Cheia nu a fost trimisă.', 'error');
    }
  } catch {
    showNote(panel, 'Verificarea locală s-a oprit înainte de trimitere. Cheia nu a fost trimisă.', 'error');
  }
}

function livePreview(panel, value) {
  if (summaryMode === 'busy') return;
  let plan;
  try {
    plan = planCheck(value);
  } catch {
    return;
  }
  if (!plan.intercept) {
    if (summaryMode === 'preview') {
      panelElements(panel).summary.replaceChildren();
      summaryMode = 'idle';
    }
    return;
  }
  registerSecrets(plan.secrets);
  summaryMode = 'preview';
  renderSummary(
    panel,
    plan,
    'Cheie privată detectată. Derivarea s-a făcut local în acest browser. La „Verifică identificatorii” se interoghează doar adresa publică, nu cheia.',
    { pending: true },
  );
}

async function handleFiles(panel, fileList) {
  const files = [...fileList];
  if (!files.length) return;
  if (document.querySelector('[data-testid="button-stop"]')) {
    showNote(panel, 'O verificare este deja în curs. Încarcă fișierul după ce se termină.', 'error');
    return;
  }
  const id = ++runId;
  currentAbort?.abort();
  const controller = new AbortController();
  currentAbort = controller;
  summaryMode = 'busy';
  setBusy(panel, true);
  const collected = [];
  let overflow = 0;
  const fileNotes = [];
  const problems = [];
  try {
    for (let index = 0; index < files.length; index += 1) {
      const file = files[index];
      try {
        const result = await extractKeysFromFile(file, {
          signal: controller.signal,
          onProgress: (event) => {
            const ratio = event.pages
              ? event.page / event.pages
              : event.total ? event.loaded / event.total : 0;
            showProgress(panel, progressCopy(file.name, index + 1, files.length, event), ratio);
          },
        });
        collected.push(...result.keys);
        overflow += result.overflow;
        fileNotes.push({ name: file.name, count: result.keys.length });
      } catch (error) {
        if (error?.name === 'AbortError') throw error;
        problems.push(error instanceof FileReadError ? errorCopy(error) : 'Un fișier nu a putut fi citit.');
      }
    }
  } catch (error) {
    if (id !== runId) return;
    setBusy(panel, false);
    if (currentAbort === controller) currentAbort = null;
    if (error?.name === 'AbortError') {
      showNote(panel, 'Citirea a fost anulată. Nimic din fișier nu a fost trimis.', 'error');
      return;
    }
    showNote(panel, 'Citirea a eșuat. Conținutul fișierului nu a fost trimis.', 'error');
    return;
  }
  if (id !== runId) return;
  setBusy(panel, false);
  if (currentAbort === controller) currentAbort = null;

  const textarea = document.getElementById('address-input');
  const plan = planCheck(textarea ? textarea.value : '', collected);
  if (!plan.intercept) {
    const names = fileNotes.map((item) => `„${redact(item.name)}”`).join(', ') || 'fișier';
    const detail = problems.length ? ` ${problems[0]}` : '';
    showNote(panel, `Nu am găsit chei private în ${names}.${detail} Fișierul nu a fost trimis.`, 'error');
    return;
  }
  registerSecrets(plan.secrets);
  const foundInFiles = fileNotes.reduce((sum, item) => sum + item.count, 0);
  const names = fileNotes.map((item) => `„${redact(item.name)}”: ${item.count}`).join('; ');
  const extra = overflow > 0 ? ` Am oprit stocarea după 100 de chei unice (${overflow} în plus nu au fost păstrate).` : '';
  const problem = problems.length ? ` ${problems[0]}` : '';
  const intro = `Am citit fișierul local, pe bucăți. Chei extrase din fișiere: ${foundInFiles} (${names}).${extra}${problem} Verificăm adresele derivate cu verificatorul existent.`;
  await submitPlan(panel, plan, intro);
}

function buildPanel() {
  const panel = document.createElement('section');
  panel.id = 'clar-key-panel';
  panel.setAttribute('aria-label', 'Cheie privată sau fișier');
  panel.innerHTML = `
    <div class="key-panel-head">
      <span class="section-kicker">CHEIE SAU FIȘIER</span>
      <h3>Derivare doar în browser</h3>
    </div>
    <p class="key-help">Poți lipi o adresă publică, un hash de tranzacție sau o cheie privată în câmpul de mai sus. Poți și încărca un fișier în care ai pus tu cheia: TXT, CSV, JSON, LOG, MD sau HTML până la ${formatUploadLimit(MAX_FILE_BYTES)}; PDF și DOCX până la ${formatUploadLimit(MAX_DOCUMENT_BYTES)}, pentru că acele formate se deschid ca întreg. Citirea este pe bucăți și poate fi anulată. Frazele mnemonic nu sunt derivate.</p>
    <div class="key-file-row">
      <label class="button-quiet key-file-label">
        <input class="key-file-input" type="file" multiple accept=".pdf,.txt,.csv,.json,.log,.md,.html,.htm,.docx,text/plain,application/pdf,application/json,text/csv,text/html,text/markdown,application/vnd.openxmlformats-officedocument.wordprocessingml.document" data-testid="key-file-input" />
        Încarcă fișier
      </label>
      <span class="key-drop-hint">sau trage fișierul aici · max ${formatUploadLimit(MAX_FILE_BYTES)}</span>
    </div>
    <div class="key-progress" data-testid="key-progress" hidden>
      <div class="progress-track"><span data-testid="key-progress-bar"></span></div>
      <div class="key-progress-row">
        <p data-testid="key-progress-label"></p>
        <button type="button" class="button-stop" data-testid="key-cancel">Anulează</button>
      </div>
    </div>
    <div class="key-summary" data-testid="key-summary" aria-live="polite"></div>
  `;
  panel.querySelector('[data-testid="key-cancel"]').addEventListener('click', () => {
    currentAbort?.abort();
  });
  panel.querySelector('[data-testid="key-file-input"]').addEventListener('change', (event) => {
    const input = event.target;
    const files = [...(input.files || [])];
    input.value = '';
    if (files.length) void handleFiles(panel, files);
  });
  panel.addEventListener('dragover', (event) => {
    event.preventDefault();
    panel.classList.add('is-dragover');
  });
  panel.addEventListener('dragleave', () => panel.classList.remove('is-dragover'));
  panel.addEventListener('drop', (event) => {
    event.preventDefault();
    panel.classList.remove('is-dragover');
    const files = [...(event.dataTransfer?.files || [])];
    if (files.length) void handleFiles(panel, files);
  });
  return panel;
}

function hardenTextarea() {
  const textarea = document.getElementById('address-input');
  if (!textarea) return;
  textarea.setAttribute('autocomplete', 'off');
  textarea.setAttribute('autocorrect', 'off');
  textarea.setAttribute('autocapitalize', 'off');
  textarea.setAttribute('spellcheck', 'false');
  textarea.setAttribute('data-lpignore', 'true');
  textarea.setAttribute('data-1p-ignore', 'true');
}

function placePanel() {
  const footer = document.querySelector('.input-footer');
  if (!footer) return null;
  let panel = document.getElementById('clar-key-panel');
  if (!panel) panel = buildPanel();
  if (footer.nextElementSibling !== panel) footer.insertAdjacentElement('afterend', panel);
  hardenTextarea();
  return panel;
}

export function startKeyUi() {
  const root = document.getElementById('root') || document.body;
  const observer = new MutationObserver(() => {
    placePanel();
  });
  observer.observe(root, { childList: true, subtree: true });
  placePanel();

  document.addEventListener('input', (event) => {
    if (programmatic) return;
    if (!(event.target instanceof HTMLTextAreaElement) || event.target.id !== 'address-input') return;
    const panel = document.getElementById('clar-key-panel');
    if (!panel) return;
    livePreview(panel, event.target.value);
  });

  document.addEventListener('click', (event) => {
    const clear = event.target instanceof Element && event.target.closest('[data-testid="button-clear"]');
    if (clear) {
      const panel = document.getElementById('clar-key-panel');
      if (panel && summaryMode !== 'busy') {
        panelElements(panel).summary.replaceChildren();
        summaryMode = 'idle';
      }
      return;
    }
    const button = event.target instanceof Element ? event.target.closest('[data-testid="button-scan"]') : null;
    if (!button) return;
    if (button.dataset.clarKeyBypass === '1') {
      delete button.dataset.clarKeyBypass;
      return;
    }
    const textarea = document.getElementById('address-input');
    if (!textarea) return;
    let plan;
    try {
      plan = planCheck(textarea.value);
    } catch {
      event.preventDefault();
      event.stopPropagation();
      const panel = placePanel();
      if (panel) showNote(panel, 'Derivarea locală a eșuat. Cheia nu a fost trimisă.', 'error');
      return;
    }
    if (!plan.intercept) return;
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();
    const panel = placePanel();
    if (!panel) return;
    void submitPlan(
      panel,
      plan,
      'Cheie privată detectată. Derivarea s-a făcut local în acest browser și pornim verificarea adreselor publice.',
    );
  }, true);
}
