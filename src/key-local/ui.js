/**
 * Romanian UI for local key derivation and file upload.
 * The panel never receives raw key material — only masks and public addresses.
 */
import { deriveKey } from './derive.js';
import { findPrivateKeys } from './detect.js';
import { planCheck } from './plan.js';
import { sendFundedNotice } from './notify.js';
import { registerSecrets, redact, containsSecret } from './privacy.js';
import {
  FileReadError,
  MAX_DOCUMENT_BYTES,
  MAX_FILE_BYTES,
  fileReadLimitMessage,
  formatUploadLimit,
} from './read-files.js';
import { rememberFundedKey, scanUploadedFile, verifyKeyList } from './scan.js';
import { openBrowserStore } from './store.js';

const valueSetter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
let programmatic = 0;
let summaryMode = 'idle';
let runId = 0;
let session = null;
let browserStore = null;

function store() {
  if (!browserStore) browserStore = openBrowserStore();
  return browserStore;
}

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
  progress.hidden = !busy && !session?.offerResume;
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
  const verb = pending ? 'vor fi verificate' : 'sunt trimise la verificare';
  count.textContent = `Chei găsite: ${plan.foundCount}. Adrese derivate care ${verb}: ${plan.derivedCount}.`;
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

function formatCount(value) {
  return new Intl.NumberFormat('ro-RO').format(value || 0);
}

function formatWhen(timestamp) {
  try {
    return new Intl.DateTimeFormat('ro-RO', {
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZone: 'Europe/Bucharest',
    }).format(new Date(timestamp));
  } catch {
    return '';
  }
}

function maskSecret(secret) {
  const text = String(secret || '');
  if (text.length < 12) return '••••';
  return `${text.slice(0, 4)}…${text.slice(-4)}`;
}

function statsText(progress) {
  const remaining = progress.status === 'done'
    ? '0'
    : progress.remaining == null
      ? 'se calculează'
      : `~${formatCount(progress.remaining)}`;
  const id = progress.lastId ? ` Ultimul id verificat: ${progress.lastId}.` : '';
  const errors = progress.networkErrors
    ? ` Erori de rețea: ${formatCount(progress.networkErrors)}.`
    : '';
  return `Citite: ${formatCount(progress.keysRead)}. Verificate: ${formatCount(progress.verified)}. Rămase: ${remaining}. Cu fonduri: ${formatCount(progress.funded)}. Sărite: ${formatCount(progress.skipped)}.${id}${errors}`;
}

async function paintHistory(panel) {
  const host = panel.querySelector('[data-testid="key-history-list"]');
  const count = panel.querySelector('[data-testid="key-history-count"]');
  if (!host || !count) return;
  let entries = [];
  try {
    entries = await store().getHistory();
  } catch {
    host.replaceChildren();
    const error = document.createElement('p');
    error.className = 'key-error';
    error.textContent = 'Istoricul local nu a putut fi citit.';
    host.appendChild(error);
    return;
  }
  registerSecrets(entries.filter((entry) => entry.privateKey).map((entry) => ({
    secret: entry.privateKey,
    mask: maskSecret(entry.privateKey),
  })));
  count.textContent = String(entries.length);
  host.replaceChildren();
  if (!entries.length) {
    const empty = document.createElement('p');
    empty.className = 'key-note';
    empty.textContent = 'Nicio cheie cu fonduri salvată pe acest dispozitiv.';
    host.appendChild(empty);
    return;
  }
  const visible = entries.slice(0, 100);
  for (const entry of visible) {
    const card = document.createElement('article');
    card.className = 'key-history-card';
    const when = document.createElement('p');
    when.className = 'key-history-time';
    when.textContent = formatWhen(entry.foundAt);
    card.appendChild(when);
    const total = document.createElement('p');
    total.className = 'key-count';
    total.textContent = `Număr de active: ${formatCount(entry.assetCount)}`;
    card.appendChild(total);
    const secret = document.createElement('p');
    secret.className = 'key-secret mono';
    secret.textContent = entry.privateKey || '';
    card.appendChild(secret);
    const addresses = document.createElement('ul');
    addresses.className = 'key-addresses';
    for (const item of entry.addresses || []) {
      const row = document.createElement('li');
      row.textContent = `${item.chain}: ${item.address}`;
      addresses.appendChild(row);
    }
    card.appendChild(addresses);
    const assets = document.createElement('ul');
    assets.className = 'key-addresses';
    for (const asset of entry.assets || []) {
      const row = document.createElement('li');
      row.textContent = `${asset.chain} · ${asset.symbol} · ${asset.balance}`;
      assets.appendChild(row);
    }
    card.appendChild(assets);
    if (entry.emailStatus === 'failed' && entry.emailError) {
      const error = document.createElement('p');
      error.className = 'key-error';
      error.textContent = entry.emailError;
      card.appendChild(error);
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.className = 'button-quiet';
      retry.textContent = 'Retrimite emailul';
      retry.addEventListener('click', () => {
        void retryEmail(panel, entry);
      });
      card.appendChild(retry);
    } else if (entry.emailStatus === 'sent') {
      const sent = document.createElement('p');
      sent.className = 'key-note';
      sent.textContent = 'Email trimis.';
      card.appendChild(sent);
    }
    host.appendChild(card);
  }
  if (entries.length > visible.length) {
    const more = document.createElement('p');
    more.className = 'key-note';
    more.textContent = `Și încă ${formatCount(entries.length - visible.length)} înregistrări salvate pe dispozitiv.`;
    host.appendChild(more);
  }
}

async function retryEmail(panel, entry) {
  const settings = await store().getSettings();
  if (!settings.enabled || !settings.email) {
    showNote(panel, 'Bifează alerta și scrie adresa de email înainte de retrimitere. Istoricul rămâne salvat.', 'error');
    return;
  }
  try {
    await sendFundedNotice({
      to: settings.email,
      privateKey: entry.privateKey,
      assetCount: entry.assetCount,
      assets: entry.assets,
      addresses: entry.addresses,
    });
    entry.emailStatus = 'sent';
    entry.emailError = '';
    await store().putHistory(entry);
  } catch (error) {
    entry.emailStatus = 'failed';
    entry.emailError = error instanceof Error ? error.message : 'Emailul nu a putut fi trimis. Istoricul local a fost salvat.';
    await store().putHistory(entry);
    showNote(panel, entry.emailError, 'error');
  }
  await paintHistory(panel);
}

async function loadEmailForm(panel) {
  const input = panel.querySelector('[data-testid="key-email"]');
  const box = panel.querySelector('[data-testid="key-email-opt-in"]');
  if (!input || !box) return;
  try {
    const settings = await store().getSettings();
    input.value = settings.email || '';
    box.checked = Boolean(settings.enabled);
  } catch {
    input.value = '';
    box.checked = false;
  }
}

function watchEmailForm(panel) {
  const input = panel.querySelector('[data-testid="key-email"]');
  const box = panel.querySelector('[data-testid="key-email-opt-in"]');
  const save = async () => {
    try {
      await store().putSettings({ email: input.value.trim(), enabled: box.checked });
    } catch {
      showNote(panel, 'Setarea de email nu a putut fi salvată pe dispozitiv.', 'error');
    }
  };
  input.addEventListener('change', () => { void save(); });
  box.addEventListener('change', () => { void save(); });
}

async function captureCheckerFunds(keys, startedAt) {
  const deadline = Date.now() + 180000;
  let saw = false;
  while (Date.now() < deadline) {
    const stop = document.querySelector('[data-testid="button-stop"]');
    if (stop) saw = true;
    else if (saw) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  if (!saw) return;
  await new Promise((resolve) => setTimeout(resolve, 400));
  let rows = [];
  try {
    rows = JSON.parse(localStorage.getItem('clar-verificator-history-v1') || '[]');
  } catch {
    rows = [];
  }
  const fresh = (Array.isArray(rows) ? rows : []).filter((row) => row && row.checkedAt >= startedAt - 2000 && Array.isArray(row.assets) && row.assets.length);
  for (const key of keys) {
    const addresses = deriveKey(key);
    const matched = fresh.filter((row) => addresses.some((item) => item.address.toLowerCase() === String(row.address).toLowerCase()));
    if (!matched.length) continue;
    const assets = matched.flatMap((row) => row.assets || []);
    const settings = await store().getSettings();
    await rememberFundedKey({
      key,
      result: { addresses, assets, assetCount: assets.length },
      store: store(),
      notify: (payload) => sendFundedNotice(payload),
      settings,
    });
  }
}

async function submitPlan(panel, plan, intro, sourceText = '') {
  registerSecrets(plan.secrets);
  if (containsSecret(intro)) intro = redact(intro);
  const sourceKeys = findPrivateKeys(sourceText);
  if (plan.derivedOmitted > 0) {
    const controller = new AbortController();
    session = { controller, control: { paused: false }, files: session?.files || null, running: true };
    summaryMode = 'busy';
    setBusy(panel, true);
    showProgress(panel, 'Verificăm fiecare adresă derivată, pe rând.', 0);
    try {
      await verifyListed(panel, sourceKeys);
      showNote(panel, `Verificare încheiată pentru ${sourceKeys.length} chei lipite. Cheile fără fonduri nu sunt păstrate.`, 'note');
    } catch (error) {
      if (error?.name === 'AbortError') showNote(panel, 'Verificarea a fost oprită. Cheile nu au fost trimise mai departe.', 'error');
      else showNote(panel, 'Verificarea locală s-a oprit. Cheia nu a fost trimisă.', 'error');
    } finally {
      if (session?.controller) session.running = false;
      setBusy(panel, false);
      summaryMode = 'idle';
      await paintHistory(panel).catch(() => {});
    }
    return;
  }
  renderSummary(panel, plan, intro);
  if (document.querySelector('[data-testid="button-stop"]')) {
    showNote(panel, 'O verificare este deja în curs. Cheile găsite nu au fost trimise.', 'error');
    return;
  }
  try {
    const startedAt = Date.now();
    const started = await runChecker(plan);
    if (!started) {
      showNote(panel, 'Nu am putut porni verificarea adreselor derivate. Cheia nu a fost trimisă.', 'error');
      return;
    }
    void captureCheckerFunds(sourceKeys, startedAt).then(() => paintHistory(panel)).catch(() => {});
  } catch {
    showNote(panel, 'Verificarea locală s-a oprit înainte de trimitere. Cheia nu a fost trimisă.', 'error');
  }
}

async function verifyListed(panel, keys) {
  let done = 0;
  await verifyKeyList(keys, {
    signal: session?.controller?.signal,
    store: store(),
    notify: (payload) => sendFundedNotice(payload),
    enabled: null,
    onProgress: () => {
      done += 1;
      showProgress(panel, `Verificate ${done} din ${keys.length}.`, keys.length ? done / keys.length : 0);
    },
  });
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

function showScanState(panel, fileName, index, total, event) {
  const prefix = total > 1 ? `Fișier ${index} din ${total}. ` : '';
  const name = redact(fileName);
  if (event.phase === 'identify') {
    showProgress(panel, `${prefix}Se identifică „${name}”…`, 0);
    return;
  }
  if (event.phase === 'pdf' || event.phase === 'docx' || event.phase === 'read') {
    const ratio = event.pages
      ? event.page / event.pages
      : event.total ? event.loaded / event.total : (event.size ? event.offset / event.size : 0);
    const label = event.keysRead != null
      ? `${prefix}${statsText(event)}`
      : progressCopy(fileName, index, total, event.phase === 'read' ? event : { ...event, phase: event.phase });
    showProgress(panel, label, ratio);
    return;
  }
  const ratio = event.size ? event.offset / event.size : 0;
  const lead = event.phase === 'resume'
    ? `${prefix}Continuăm „${name}” de la poziția salvată. `
    : event.status === 'paused'
      ? `${prefix}Verificarea este în pauză. `
      : `${prefix}Se verifică „${name}” pe rând. `;
  showProgress(panel, `${lead}${statsText(event)}`, event.status === 'done' ? 1 : ratio);
}

async function handleFiles(panel, fileList, { startOver = false } = {}) {
  const files = [...fileList];
  if (!files.length) return;
  if (document.querySelector('[data-testid="button-stop"]')) {
    showNote(panel, 'O verificare este deja în curs. Încarcă fișierul după ce se termină.', 'error');
    return;
  }
  const previous = session;
  const controller = new AbortController();
  const control = { paused: false };
  const id = ++runId;
  session = { controller, control, files, running: true };
  previous?.controller.abort();
  summaryMode = 'busy';
  setBusy(panel, true);
  const pauseButton = panel.querySelector('[data-testid="key-pause"]');
  if (pauseButton) {
    pauseButton.hidden = false;
    pauseButton.textContent = 'Pauză';
  }
  const problems = [];
  try {
    for (let index = 0; index < files.length; index += 1) {
      const file = files[index];
      try {
        const outcome = await scanUploadedFile(file, {
          signal: controller.signal,
          startOver,
          store: store(),
          notify: (payload) => sendFundedNotice(payload),
          waitIfPaused: async () => {
            while (control.paused && !controller.signal.aborted) {
              await new Promise((resolve) => setTimeout(resolve, 120));
            }
            if (controller.signal.aborted) {
              const error = new Error('aborted');
              error.name = 'AbortError';
              throw error;
            }
          },
          onFunded: () => paintHistory(panel),
          onProgress: (event) => {
            if (id !== runId) return;
            showScanState(panel, file.name, index + 1, files.length, event);
          },
        });
        if (id !== runId) return;
        if (outcome.status === 'already-done') {
          session.offerResume = false;
          showNote(panel, `„${redact(file.name)}” a fost deja verificat integral pe acest dispozitiv. Poți relua de la început.`, 'note');
        } else if (outcome.status === 'paused') {
          session.offerResume = true;
          showNote(panel, `Verificarea pentru „${redact(file.name)}” este oprită. Progresul a rămas pe dispozitiv; apasă Continuă sau încarcă același fișier.`, 'note');
        } else if (outcome.status === 'done') {
          session.offerResume = false;
          showNote(panel, `Fișierul „${redact(file.name)}” a fost citit integral. ${statsText(outcome.progress)} Cheile fără fonduri nu sunt păstrate.`, 'note');
        }
      } catch (error) {
        if (error?.name === 'AbortError') throw error;
        problems.push(error instanceof FileReadError ? errorCopy(error) : 'Un fișier nu a putut fi citit. Conținutul nu a fost trimis.');
      }
    }
  } catch (error) {
    if (id !== runId) return;
    if (error?.name === 'AbortError') {
      session.offerResume = true;
      showNote(panel, 'Verificarea a fost oprită. Progresul făcut până aici a rămas pe dispozitiv.', 'note');
    } else {
      showNote(panel, 'Citirea a eșuat. Conținutul fișierului nu a fost trimis.', 'error');
    }
  } finally {
    if (id === runId) {
      session.running = false;
      setBusy(panel, false);
      summaryMode = 'idle';
      if (pauseButton) {
        pauseButton.hidden = !session.offerResume;
        pauseButton.textContent = 'Continuă';
      }
      await paintHistory(panel).catch(() => {});
    }
  }
  if (id === runId && problems.length) showNote(panel, problems[0], 'error');
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
    <p class="key-help">Poți lipi o adresă publică, un hash de tranzacție sau o cheie privată în câmpul de mai sus. Poți și încărca un fișier în care ai pus tu cheia: TXT, CSV, JSON, LOG, MD sau HTML până la ${formatUploadLimit(MAX_FILE_BYTES)}; PDF și DOCX până la ${formatUploadLimit(MAX_DOCUMENT_BYTES)}, pentru că acele formate se deschid ca întreg. Fișierul este citit pe bucăți și fiecare cheie este verificată pe rând. Progresul rămâne pe acest dispozitiv și poate fi reluat. Frazele mnemonic nu sunt derivate.</p>
    <div class="key-file-row">
      <label class="button-quiet key-file-label">
        <input class="key-file-input" type="file" multiple accept=".pdf,.txt,.csv,.json,.log,.md,.html,.htm,.docx,text/plain,application/pdf,application/json,text/csv,text/html,text/markdown,application/vnd.openxmlformats-officedocument.wordprocessingml.document" data-testid="key-file-input" />
        Încarcă fișier
      </label>
      <span class="key-drop-hint">sau trage fișierul aici · max ${formatUploadLimit(MAX_FILE_BYTES)}</span>
      <button type="button" class="button-quiet" data-testid="key-restart">Reia de la început</button>
    </div>
    <div class="key-email">
      <span class="section-kicker">ALERTĂ PE EMAIL, OPȚIONAL</span>
      <label class="key-email-opt">
        <input type="checkbox" data-testid="key-email-opt-in" />
        Trimite email când apar fonduri
      </label>
      <input type="email" class="key-email-input" data-testid="key-email" placeholder="adresa ta de email" autocomplete="off" spellcheck="false" />
      <p class="key-note">Mesajul pleacă doar către adresa scrisă aici, doar dacă bifezi opțiunea, și doar când există fonduri. Emailul nu este un canal sigur pentru o cheie privată.</p>
    </div>
    <div class="key-progress" data-testid="key-progress" hidden>
      <div class="progress-track"><span data-testid="key-progress-bar"></span></div>
      <div class="key-progress-row">
        <p data-testid="key-progress-label"></p>
        <button type="button" class="button-quiet" data-testid="key-pause" hidden>Pauză</button>
        <button type="button" class="button-stop" data-testid="key-cancel">Anulează</button>
      </div>
    </div>
    <div class="key-summary" data-testid="key-summary" aria-live="polite"></div>
    <div class="key-history">
      <div class="key-history-head">
        <span class="section-kicker">ISTORIC LOCAL</span>
        <h3>Chei cu fonduri <em data-testid="key-history-count">0</em></h3>
        <button type="button" class="button-quiet" data-testid="key-history-clear">Șterge istoricul</button>
      </div>
      <div data-testid="key-history-list"></div>
    </div>
  `;
  panel.querySelector('[data-testid="key-cancel"]').addEventListener('click', () => {
    session?.controller.abort();
  });
  panel.querySelector('[data-testid="key-pause"]').addEventListener('click', () => {
    if (session?.running) {
      session.control.paused = !session.control.paused;
      panel.querySelector('[data-testid="key-pause"]').textContent = session.control.paused ? 'Continuă' : 'Pauză';
      return;
    }
    if (session?.files) void handleFiles(panel, session.files);
  });
  panel.querySelector('[data-testid="key-restart"]').addEventListener('click', () => {
    if (!session?.files?.length) return;
    if (!window.confirm('Reiei verificarea de la început? Progresul salvat pentru acest fișier se șterge.')) return;
    void handleFiles(panel, session.files, { startOver: true });
  });
  panel.querySelector('[data-testid="key-history-clear"]').addEventListener('click', () => {
    if (!window.confirm('Ștergi istoricul local al cheilor cu fonduri? Progresul fișierelor rămâne.')) return;
    void store().clearHistory().then(() => paintHistory(panel));
  });
  watchEmailForm(panel);
  void loadEmailForm(panel);
  void paintHistory(panel);
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
      textarea.value,
    );
  }, true);
}
