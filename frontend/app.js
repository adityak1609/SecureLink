'use strict';
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has('token')) { sessionStorage.setItem('securelinkToken', fragment.get('token')); history.replaceState(null, '', location.pathname); }
const token = sessionStorage.getItem('securelinkToken') || '';
let state = null, selectedFile = null, composer = 'files', pending = false, seenJobs = new Set(), initialized = false, previewUrl = null, selectedUrl = null, toastTimer;
const escaped = (value) => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const timestampDate = new Intl.DateTimeFormat('en-GB', {timeZone:'Asia/Kolkata',day:'2-digit',month:'short',year:'numeric'});
const timestampClock = new Intl.DateTimeFormat('en-GB', {timeZone:'Asia/Kolkata',hourCycle:'h23',hour:'2-digit',minute:'2-digit',second:'2-digit',fractionalSecondDigits:3});
function timestampMarkup(value) {
  if (value === undefined || value === null || value === '') return '<span class="muted timestamp-empty">Not recorded</span>';
  const valid = typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value);
  const date = valid ? new Date(value) : null;
  if (!date || !Number.isFinite(date.getTime())) return `<span class="muted timestamp-empty" title="${escaped(value)}">Unavailable</span>`;
  return `<time class="timestamp" datetime="${escaped(value)}" title="Displayed in IST (UTC+05:30). Original recorded timestamp: ${escaped(value)}"><span class="timestamp-date">${escaped(timestampDate.format(date))}</span><span class="timestamp-clock">${escaped(timestampClock.format(date))} <span class="timestamp-zone">IST</span></span></time>`;
}
function bytes(value) { if (!value) return '0 B'; const units = ['B','KiB','MiB','GiB']; const index = Math.min(3, Math.floor(Math.log(value)/Math.log(1024))); return `${(value/1024**index).toFixed(index ? 1 : 0)} ${units[index]}`; }
function toast(message, error = false) { clearTimeout(toastTimer); $('#toast').textContent = message; $('#toast').classList.toggle('error', error); $('#toast').hidden = false; toastTimer = setTimeout(() => $('#toast').hidden = true, error ? 9000 : 5500); }
async function api(path, options = {}) { const response = await fetch(path, {...options, headers: {...options.headers, 'X-SecureLink-Token': token}}); if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.error || `Request failed (${response.status})`); } return response; }
async function action(path, body = {}) { if (pending) return; pending = true; updateButtons(); try { await api(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}); await refresh(); } catch (error) { toast(error.message, true); } finally { pending = false; updateButtons(); } }
function busy() { return pending || !!state?.jobs.some(job => ['queued','running'].includes(job.status)); }
function updateButtons() { const locked = busy(), connected = !!state?.connected; $('#start-demo').disabled = locked; $('#start-demo').innerHTML = state?.mode === 'local' && connected ? 'Restart local demo <span>↻</span>' : 'Start local demo <span>→</span>'; $('#remote-button').disabled = locked; $('#disconnect').disabled = locked || state?.mode === 'offline'; $('#send-button').disabled = locked || !connected || (composer === 'files' ? !selectedFile : !$('#message').value.trim()); $$('[data-sample]').forEach(button => button.disabled = locked || !connected); $('#verify-audit').disabled = locked || !connected || state?.mode !== 'local'; $('#analyze').disabled = locked || !connected || state?.mode !== 'local'; $$('[data-export]').forEach(button => button.disabled = !state?.exports.includes(button.dataset.export)); $$('[data-receive], [data-retry]').forEach(button => button.disabled = locked || !connected); $('#shutdown').disabled = locked; $('#run-tests').disabled = locked; $$('[data-test-export]').forEach(button => button.disabled = !state?.tests); const openButton=$('#open-wireshark'); if(openButton) openButton.disabled=locked || !state?.wireshark_available; }
function switchView(view) { const titles = {workspace:'Transfers',security:'Security & audit',traffic:'Traffic analysis',guide:'Project guide',performance:'Crypto performance',evidence:'Transfer evidence',testing:'Testing & results'}; if (!(view in titles)) return; $$('.view').forEach(section => section.hidden = section.id !== `${view}-view`); $$('.nav-item').forEach(button => button.classList.toggle('active', button.dataset.view === view)); $('#breadcrumb').textContent = titles[view]; if(view === 'evidence') renderEvidenceSelector(); }
$$('[data-view]').forEach(button => button.addEventListener('click', event => { event.preventDefault(); switchView(button.dataset.view); }));
$$('[data-composer]').forEach(button => button.addEventListener('click', () => { composer = button.dataset.composer; $$('[data-composer]').forEach(tab => { tab.classList.toggle('active', tab === button); tab.setAttribute('aria-selected', String(tab === button)); }); $('#files-composer').hidden = composer !== 'files'; $('#text-composer').hidden = composer !== 'text'; updateButtons(); }));
$('#message').addEventListener('input', updateButtons);
function chooseFile(file) { if (!file) return; const valid = /\.(txt|png|jpe?g|wav|mp3|mp4)$/i.test(file.name); if (!valid || !file.size || file.size > 32*1024*1024) { toast('Choose a supported, non-empty file no larger than 32 MiB.', true); return; } selectedFile = file; $('#file-title').textContent = file.name; $('#file-caption').textContent = `${bytes(file.size)} · Ready to send`; if (selectedUrl) URL.revokeObjectURL(selectedUrl); $('#selected-preview').replaceChildren(); $('#selected-preview').hidden = true; if (/\.(png|jpe?g)$/i.test(file.name)) { selectedUrl = URL.createObjectURL(file); const image = document.createElement('img'); image.src = selectedUrl; image.alt = 'Selected image preview'; $('#selected-preview').append(image); $('#selected-preview').hidden = false; } updateButtons(); }
$('#file-input').addEventListener('change', event => chooseFile(event.target.files[0]));
$('#dropzone').addEventListener('keydown', event => { if (['Enter',' '].includes(event.key)) { event.preventDefault(); $('#file-input').click(); } });
['dragenter','dragover'].forEach(name => $('#dropzone').addEventListener(name, event => { event.preventDefault(); $('#dropzone').classList.add('dragging'); }));
['dragleave','drop'].forEach(name => $('#dropzone').addEventListener(name, event => { event.preventDefault(); $('#dropzone').classList.remove('dragging'); if (name === 'drop') chooseFile(event.dataTransfer.files[0]); }));
$('#send-button').addEventListener('click', async () => { if (composer === 'text') { await action('/api/text', {text:$('#message').value}); return; } if (!selectedFile || busy()) return; pending = true; updateButtons(); try { await api(`/api/upload?name=${encodeURIComponent(selectedFile.name)}`, {method:'POST', body:selectedFile}); await refresh(); } catch (error) { toast(error.message, true); } finally { pending = false; updateButtons(); } });
$('#start-demo').addEventListener('click', () => action('/api/demo/start'));
$('#disconnect').addEventListener('click', () => action('/api/disconnect'));
$('#verify-audit').addEventListener('click', () => action('/api/audit/verify'));
$('#analyze').addEventListener('click', () => action('/api/analysis'));
$$('[data-sample]').forEach(button => button.addEventListener('click', () => action('/api/sample', {name:button.dataset.sample})));
$('#remote-button').addEventListener('click', () => $('#remote-dialog').showModal());
$$('[data-close]').forEach(button => button.addEventListener('click', () => $(`#${button.dataset.close}`).close()));
$('#remote-form').addEventListener('submit', event => { event.preventDefault(); $('#remote-dialog').close(); action('/api/connect', {host:$('#host').value.trim(),port:Number($('#port').value)}); });
$('#shutdown').addEventListener('click', async () => { if (!confirm('Close SecureLink and stop its local device processes?')) return; try { await api('/api/shutdown', {method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}); clearInterval(pollTimer); toast('Application closed. You can close this tab.'); $$('button').forEach(button => button.disabled = true); } catch (error) { toast(error.message, true); } });
async function saveResponse(path, name) { const response = await api(path); const blob = await response.blob(), url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = name; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 60000); }
$$('[data-export]').forEach(button => button.addEventListener('click', () => saveResponse(`/api/export/${button.dataset.export}`, {pcap:'session_stream.pcap',sqlite:'packets.sqlite',xml:'packets.xml',json:'summary.json'}[button.dataset.export]).catch(error => toast(error.message, true))));
$$('[data-report]').forEach(button => button.addEventListener('click', () => saveResponse(`/api/report/${button.dataset.report}`, button.dataset.report).catch(error => toast(error.message, true))));
async function preview(request) { const row = state.transfers.find(row => row.request === request); try { const response = await api(`/api/file/${request}`); const blob = await response.blob(); if (previewUrl) URL.revokeObjectURL(previewUrl); previewUrl = URL.createObjectURL(blob); const element = document.createElement({image:'img',audio:'audio',video:'video',text:'pre'}[row.media]); if (row.media === 'text') element.textContent = await blob.text(); else { element.src = previewUrl; if (row.media === 'image') element.alt = row.name; else element.controls = true; } $('#preview-content').replaceChildren(element); $('#preview-title').textContent = row.name; $('#preview-hash').textContent = `SHA-256 verified after receiving: ${row.sha256}`; $('#preview-dialog').showModal(); } catch (error) { toast(error.message, true); } }
$('#preview-dialog').addEventListener('close', () => { $('#preview-content').replaceChildren(); if (previewUrl) URL.revokeObjectURL(previewUrl); previewUrl = null; });
function renderTransfers(rows) { const symbol = {text:'T',image:'▧',audio:'♫',video:'▷'}; $('#history-count').textContent = `${rows.length} file${rows.length === 1 ? '' : 's'}`; $('#empty-transfers').hidden = !!rows.length; $('#transfer-rows').innerHTML = rows.map(row => `<tr><td><div class="file-info"><span class="file-icon ${escaped(row.media)}">${symbol[row.media] || '↑'}</span><div><strong title="${escaped(row.name)}">${escaped(row.name)}</strong><small>${escaped(row.media.toUpperCase())} · ${escaped(row.request.slice(0,8))} · ${row.retries || 0} retries</small>${row.error ? `<div class="failed-detail">${escaped(row.error)}</div>` : ''}</div></div></td><td>${bytes(row.size)}</td><td class="timestamp-cell"><span class="muted">${row.upload_completed ? 'Uploaded' : 'Created'}</span>${timestampMarkup(row.upload_completed || row.created)}</td><td><span class="status ${escaped(row.status)}">${row.downloaded ? 'Hash verified' : row.status === 'complete' ? 'Delivered' : row.status === 'failed' ? 'Failed' : 'Sending'}</span></td><td><div class="row-actions">${row.status === 'failed' || row.status === 'sending' || !row.signature ? `<button data-retry="${row.request}">${row.status === 'complete' ? 'Sign & resend' : 'Resume'}</button>` : `<button data-receive="${row.request}">${row.downloaded ? 'Receive again' : 'Receive'}</button>`}${row.downloaded ? `<button data-preview="${row.request}">Preview</button><button data-save="${row.request}">Save ↓</button>` : ''}</div></td></tr>`).join(''); $$('[data-receive]').forEach(button => button.addEventListener('click', () => action('/api/download', {request:button.dataset.receive}))); $$('[data-retry]').forEach(button => button.addEventListener('click', () => action('/api/retry', {request:button.dataset.retry}))); $$('[data-preview]').forEach(button => button.addEventListener('click', () => preview(button.dataset.preview))); $$('[data-save]').forEach(button => button.addEventListener('click', () => { const row = rows.find(row => row.request === button.dataset.save); saveResponse(`/api/file/${row.request}`, row.name).catch(error => toast(error.message, true)); })); }
function renderSecurity() { const complete = state.transfers.filter(row => row.status === 'complete'); const controls = [
  ['01','Confidentiality','AES-256-GCM encrypts text and media with fresh derived session keys.',state.connected ? 'Authenticated encrypted channel available' : 'Connect a device to use encryption'],
  ['02','Integrity','Authenticated frames, checked chunk offsets and a final SHA-256 file digest.',`${complete.filter(row => row.downloaded).length} received copies verified with SHA-256`],
  ['03','Authentication','Mutual device authentication using provisioned keys, nonces and a timestamp.',state.connected ? `Last handshake: ${state.handshake_ms} ms` : 'No authenticated connection'],
  ['04','Accountability','Hash-chained server events anchored to a separate audit-witness process.',state.audit?.verified ? `${state.audit.count} records verified against witness` : 'Independent checkpoint verification pending'],
  ['05','Availability','Bounded connections, deadlines, storage limits and resumable chunk transfers.',`${complete.reduce((sum,row) => sum+(row.retries || 0),0)} reconnect retries across delivered files`],
  ['06','Replay resistance','Session sequence checks and durable owner/request identifiers.',`${complete.length} unique completed request IDs in this workspace`]
]; $('#security-cards').innerHTML = controls.map(([index,name,description,status]) => `<article class="security-card"><div class="eyebrow">CONTROL ${index} /</div><h3>${name}</h3><p>${description}</p><div class="control-state">${escaped(status)}</div></article>`).join(''); const audit = state.audit; $('#audit-summary').innerHTML = state.mode !== 'local' ? 'Local witness verification is available in the local simulation. Verify a remote server’s audit on its host.' : audit?.verified ? `<strong>✓ Audit chain and independent checkpoint match.</strong><br>${audit.count} records<div class="audit-verified-time"><span>Verified</span>${timestampMarkup(audit.verified_at)}</div><code>${escaped(audit.head)}</code>` : audit ? `<strong>Verification failed.</strong> Inspect the failed job message and the server log. The chain is not shown as verified.<div class="audit-verified-time"><span>Checked</span>${timestampMarkup(audit.verified_at)}</div>` : 'Audit events are available below. Choose Verify audit chain to check them against the authenticated witness.'; $('#audit-rows').innerHTML = state.events.slice().reverse().map(event => `<tr><td>${event.index}</td><td>${escaped(event.event)}</td><td>${escaped(event.device || '—')}</td><td><span class="status ${event.outcome === 'ok' ? '' : 'failed'}">${escaped(event.outcome)}</span></td><td class="timestamp-cell">${timestampMarkup(event.timestamp)}</td></tr>`).join('') || '<tr><td colspan="5">No local audit events yet.</td></tr>'; }
function renderAnalysis() { const result = state.analysis; if (!result) { $('#analysis-content').className = 'panel analysis-empty'; $('#analysis-content').innerHTML = '<span class="upload-mark">≋</span><h2>Your traffic evidence will appear here.</h2><p>Send a demo file, then choose Analyze capture.</p>'; return; } $('#analysis-content').className = 'panel'; $('#analysis-content').innerHTML = `<div class="panel-heading"><h2>Captured stream snapshot</h2><span class="outline-tag">${escaped(result.engine || 'Engine not recorded')}</span><span class="outline-tag">USER0 PCAP → SQLITE / XML</span></div><button id="open-wireshark" class="button secondary">Open in Wireshark ↗</button><div class="analysis-stats"><div><span>OBSERVATIONS</span><strong>${result.records}</strong><small class="muted">Matching export counts</small></div><div><span>OBSERVED PAYLOAD</span><strong>${bytes(result.payload_bytes)}</strong><small class="muted">Both directions</small></div><div><span>CAPTURE WINDOW</span><strong>${result.duration_seconds.toFixed(2)} s</strong><small class="muted">First to last observation</small></div><div><span>WEIGHTED ENTROPY</span><strong>${result.weighted_record_entropy.toFixed(2)}</strong><small class="muted">Bits per byte, descriptive</small></div></div><div class="analysis-note">Known transaction marker <code>"amount_paise"</code>: <strong>${result.marker_found ? 'found in observed stream' : 'not found in this snapshot'}</strong>.<br>Marker absence alone does not prove confidentiality. This capture contains encrypted transfers, handshake data and public protocol metadata.</div>`; $('#open-wireshark').addEventListener('click',()=>action('/api/wireshark/open')); }
function render() { const online = state.connected; $('#identity').textContent = state.identity; $('#connection-pill').classList.toggle('online', online); $('#connection-pill').innerHTML = `<i></i> ${online ? 'Device authenticated' : 'Devices offline'}`; $('#live-dot').classList.toggle('online', online); $('#client-node').textContent = `${state.identity} · PID ${state.topology.client}`; $('#server-node').textContent = state.mode === 'local' ? `Separate process · PID ${state.topology.server}` : state.target ? `${state.target[0]}:${state.target[1]}` : 'Not connected'; $('#witness-node').textContent = state.mode === 'local' ? `Separate process · PID ${state.topology.witness}` : state.mode === 'remote' ? 'Managed on the remote lab host' : 'Starts with your local demo'; $('#channel-label').textContent = online ? 'AES-256-GCM · protocol v3' : 'Waiting for connection'; $('#topology-note').textContent = state.mode === 'remote' ? 'Connected to a remote server. Keys stay in the local Python client; audit verification runs on the server host.' : 'The local demo runs the client, server and witness as three separate processes on this computer.'; const rows = state.transfers, complete = rows.filter(row => row.status === 'complete'); $('#metric-files').textContent = complete.length; const total = bytes(complete.reduce((sum,row) => sum + row.size,0)).split(' '); $('#metric-bytes').innerHTML = `${total[0]} <span>${total[1]}</span>`; const last = complete[0]; $('#metric-time').innerHTML = last ? `${(last.elapsed_ms/1000).toFixed(2)} <span>s</span>` : '—'; $('#metric-audit').textContent = state.audit?.verified ? state.audit.count : '—'; $('#metric-audit-note').textContent = state.audit?.verified ? 'Witness matched' : state.audit ? 'Verification failed' : 'Verification pending'; renderTransfers(rows); renderSecurity(); renderAnalysis(); renderPerformance(); renderTesting(); const job = state.jobs.find(job => ['running','queued'].includes(job.status)); $('#job-progress').hidden = !job; if (job) { const percentage = job.total ? Math.min(100, Math.floor(job.done/job.total*100)) : 0; $('#job-progress').innerHTML = `<div class="progress-caption"><span>${escaped(job.label)}</span><span>${job.total ? `${bytes(job.done)} / ${bytes(job.total)} · ${percentage}%` : 'Working…'}</span></div><div class="progress-track"><span style="width:${job.total ? percentage : 15}%"></span></div>`; } for (const job of state.jobs) { if (['complete','failed'].includes(job.status) && !seenJobs.has(job.id)) { seenJobs.add(job.id); if (initialized) toast(job.status === 'failed' ? job.error : job.result?.message || `${job.label} complete`, job.status === 'failed'); } } initialized = true; updateButtons(); }
let refreshing = false;
async function refresh() { if (refreshing) return; refreshing = true; try { state = await (await api('/api/state')).json(); render(); } catch (error) { if (!initialized) toast(error.message, true); $('#connection-pill').innerHTML = '<i></i> Application unavailable'; $('#connection-pill').classList.remove('online'); if (state) state.connected = false; updateButtons(); } finally { refreshing = false; } }
const pollTimer = setInterval(refresh, 1000);

let metricsSelection = '';
const operationLabels = {encryption:'AES-256-GCM encryption',decryption:'AES-256-GCM decryption',hashing:'SHA-256 file hashing',signing:'Ed25519 signing',signature_verification:'Ed25519 verification'};
function renderPerformance() {
  const rows = state.transfers;
  const selected = $('#metrics-file').value || metricsSelection;
  $('#metrics-file').innerHTML = rows.map(row => `<option value="${row.request}">${escaped(row.name)} · ${row.request.slice(0,8)}</option>`).join('');
  if (rows.some(row => row.request === selected)) $('#metrics-file').value = selected;
  metricsSelection = $('#metrics-file').value;
  const row = rows.find(row => row.request === metricsSelection);
  if (!row) { $('#metrics-content').textContent = 'Send a file, then select it to inspect measured crypto operations.'; return; }
  const proof = row.signature;
  let content = `<div class="signature-summary"><strong>${proof ? 'Ed25519 signed file manifest' : 'Legacy transfer: no signature measurements'}</strong><p>File SHA-256: <code>${escaped(row.sha256)}</code></p>${proof ? `<p>Public key: <code>${escaped(proof.public_key)}</code></p><p>Digital signature: <code>${escaped(proof.signature)}</code></p>` : '<p>Send a new file or use Sign & resend to collect signed-transfer measurements.</p>'}</div>`;
  for (const direction of ['upload','download']) {
    const metric = row.crypto?.[direction];
    content += `<div class="panel-heading"><h2>${direction === 'upload' ? 'Upload: client → server' : 'Receive: server → client'}</h2><span class="status ${metric?.signature_verified ? '' : 'sending'}">${metric?.signature_verified ? 'Signature verified' : 'Awaiting signed operation'}</span></div>`;
    if (!metric) { content += '<p class="muted">This direction has no measured operations yet.</p>'; continue; }
    content += '<div class="table-scroll"><table class="crypto-table"><thead><tr><th>OPERATION</th><th>CLIENT TIME / CALLS</th><th>SERVER TIME / CALLS</th></tr></thead><tbody>';
    for (const [operation,label] of Object.entries(operationLabels)) {
      const cell = endpoint => { const value = metric[endpoint]?.[operation]; return value ? `${value.milliseconds.toFixed(6)} ms <small>${value.calls} calls · ${bytes(value.bytes)} · ${value.failures} failed</small>` : '<span class="muted">Not performed in this scope</span>'; };
      content += `<tr><td>${label}</td><td>${cell('client')}</td><td>${cell('server')}</td></tr>`;
    }
    content += `</tbody></table></div><p class="muted">Handshake including communication: ${metric.handshake_ms.toFixed(3)} ms. File payload: ${bytes(row.size)}.</p>`;
  }
  $('#metrics-content').innerHTML = content;
}
function renderTesting() {
  const report = state.tests;
  const requirements = report?.requirements || state.test_requirements;
  const running = state.jobs.some(job => ['running','queued'].includes(job.status) && job.label.includes('regression tests'));
  $('#test-summary').innerHTML = running ? '<p>Running real isolated tests… Results will appear when the suite finishes.</p>' : !report ? '<p class="muted">No tests have been run from this application yet. Choose Run tests.</p>' : `<div class="analysis-stats"><div><span>PASSED</span><strong>${report.passed}</strong></div><div><span>FAILED</span><strong>${report.failed}</strong></div><div><span>SKIPPED</span><strong>${report.skipped}</strong></div><div><span>CASE TIME TOTAL</span><strong>${report.duration_seconds.toFixed(2)} s</strong></div></div><p>${report.success ? 'The executed tests passed.' : 'The suite did not pass.'} ${report.requirements_complete ? 'All mapped requirements passed.' : 'Some requirements are incomplete or failed; inspect the table below.'}</p><div class="test-run-time"><span class="muted">Test run completed</span>${timestampMarkup(report.finished_at)}</div>`;
  $('#requirement-rows').innerHTML = requirements.map(row => `<tr><td>${escaped(row.goal)}</td><td>${escaped(row.expected)}</td><td><span class="status ${row.status === 'failed' ? 'failed' : row.status !== 'passed' ? 'sending' : ''}">${escaped(row.status || 'Not run')}</span></td></tr>`).join('');
  $('#test-case-rows').innerHTML = report ? report.cases.map(test => `<tr><td>${escaped(test.name)}</td><td>${test.seconds.toFixed(3)} s</td><td><span class="status ${test.status === 'failed' ? 'failed' : test.status === 'skipped' ? 'sending' : ''}">${test.status}</span></td></tr>`).join('') : '<tr><td colspan="3">No executed test cases yet.</td></tr>';
}
$('#metrics-file').addEventListener('change', () => { metricsSelection = $('#metrics-file').value; renderPerformance(); });
$('#run-tests').addEventListener('click', () => action('/api/tests/run'));
$$('[data-metrics-export]').forEach(button => button.addEventListener('click', () => saveResponse(`/api/metrics/${button.dataset.metricsExport}`,`crypto_metrics.${button.dataset.metricsExport}`).catch(error => toast(error.message,true))));
$$('[data-test-export]').forEach(button => button.addEventListener('click', () => saveResponse(`/api/tests/export/${button.dataset.testExport}`,`test_results.${button.dataset.testExport}`).catch(error => toast(error.message,true))));
let evidenceVersion = '', evidenceSelection = '', evidenceRecord = null, evidenceLoading = '';
function renderEvidenceSelector() {
  const selected = $('#evidence-file').value || evidenceSelection;
  const rows = state?.transfers || [];
  $('#evidence-file').innerHTML = rows.map(row => `<option value="${row.request}">${escaped(row.name)} · ${row.request.slice(0,8)}</option>`).join('');
  if (rows.some(row => row.request === selected)) $('#evidence-file').value = selected;
  evidenceSelection = $('#evidence-file').value;
  $('#export-evidence').disabled = !evidenceSelection;
  $('#export-audit').disabled = state?.mode !== 'local';
  $('#refresh-evidence').disabled = !evidenceSelection;
  if (!evidenceSelection) { evidenceRecord = null; evidenceVersion = ''; $('#evidence-content').textContent = 'Send a file, then select it to inspect its evidence.'; return; }
  const row = rows.find(row => row.request === evidenceSelection);
  const version = `${evidenceSelection}:${row.updated_at || row.download_verified || row.status}`;
  if (!$('#evidence-view').hidden && evidenceVersion !== version && evidenceLoading !== version) loadEvidence(version);
}
async function loadEvidence(version) {
  const request = evidenceSelection;
  evidenceLoading = version;
  try {
    const data = await (await api(`/api/evidence/${request}`)).json();
    if (request !== evidenceSelection) return;
    evidenceRecord = data; evidenceVersion = version; renderEvidence(data);
  } catch (error) { toast(error.message,true); }
  finally { if(evidenceLoading === version) evidenceLoading = ''; }
}
function renderEvidence(data) {
  const row = data.transfer;
  const value = (label, content) => `<div class="evidence-value"><span>${escaped(label)}</span><code>${escaped(content ?? 'Not recorded')}</code></div>`;
  const timeValue = (label, content) => `<div class="evidence-value timestamp-value"><span>${escaped(label)}</span>${timestampMarkup(content)}</div>`;
  let html = `<div class="panel-heading"><h2>${escaped(row.name)}</h2><span class="outline-tag">${escaped(row.media)} · ${bytes(row.size)}</span></div>`;
  html += '<h3>Timestamps · IST</h3><div class="evidence-grid">';
  for (const [field,label] of Object.entries({created:'Transfer created',upload_started:'Upload started',upload_completed:'Upload acknowledged',download_started:'Receive started',download_verified:'Receive verified'})) html += timeValue(label,row[field]);
  html += `</div><p class="muted">Displayed in IST (UTC+05:30). Hover over a time for its original recorded value. ${escaped(data.timestamp_scope)}</p><h3>SHA-256 hash values</h3>${value('Original file',row.sha256)}${value('Received file',row.received_sha256)}`;
  html += `<p class="evidence-hash-state">${row.received_sha256 ? row.received_sha256 === row.sha256 ? 'Original and received SHA-256 values match.' : 'Original and received hashes differ.' : 'Receive the file to display its independently computed hash.'}</p>`;
  const proof = row.signature;
  html += '<h3>Digital signature</h3>' + (proof ? value('Algorithm',proof.algorithm) + value('Public signing key',proof.public_key) + value('Signature (hex)',proof.signature) : '<p>No signature recorded. Send a new file or Sign & resend.</p>');
  html += '<h3>Measured security operations</h3>';
  for (const direction of ['upload','download']) {
    const metric = row.crypto?.[direction];
    html += `<h4>${direction === 'upload' ? 'Upload' : 'Receive'} · ${metric?.signature_verified ? 'Signature verified' : 'No verified signature recorded in this scope'}</h4>`;
    if (!metric) { html += '<p class="muted">No operation measurements for this direction yet.</p>'; continue; }
    html += '<div class="table-scroll"><table class="crypto-table"><thead><tr><th>OPERATION</th><th>CLIENT</th><th>SERVER</th></tr></thead><tbody>';
    for (const [operation,label] of Object.entries(operationLabels)) {
      const cell = endpoint => { const measured = metric[endpoint]?.[operation]; return measured ? `${measured.milliseconds.toFixed(6)} ms <small>${measured.calls} calls · ${bytes(measured.bytes)} · ${measured.failures} failed</small>` : 'Not performed in this scope'; };
      html += `<tr><td>${label}</td><td>${cell('client')}</td><td>${cell('server')}</td></tr>`;
    }
    html += `</tbody></table></div><p class="muted">${escaped(metric.scope)}</p>`;
  }
  html += '<h3>Actual ciphertext</h3><p class="muted">One media-chunk sample per operation. Hexadecimal encoding; no plaintext or secret keys. AES-GCM authenticates public headers without encrypting them.</p>';
  let samples = 0;
  for (const direction of ['upload','download']) for (const sample of row.crypto?.[direction]?.ciphertext_samples || []) {
    samples++;
    html += `<div class="ciphertext-sample"><h4>${direction === 'upload' ? 'Upload' : 'Receive'} · ${escaped(sample.direction)} · ${sample.ciphertext_bytes} ciphertext bytes</h4>`;
    html += timeValue('Observed at · IST',sample.observed_at) + value(`Actual ciphertext prefix (${sample.prefix_bytes} bytes)`,sample.ciphertext_prefix_hex) + value('AES-GCM tag (16 bytes)',sample.gcm_tag_hex) + value('Nonce (12 bytes)',sample.nonce_hex) + value('Authenticated public header',sample.authenticated_header) + '</div>';
  }
  if (!samples) html += '<p>No media-record sample exists for this operation. New uploads/receives collect actual samples; a fully resumed operation may send no media chunks.</p>';
  html += '<h3>Image metrics</h3>';
  const image = row.image_metrics;
  if (row.media !== 'image') html += '<p class="muted">Not applicable: this transfer is not an image.</p>';
  else if (!image) html += '<p>Send or receive this image again to collect image measurements.</p>';
  else {
    for (const side of ['source','received']) if(image[side]) {
      const info = image[side];
      html += `<div class="evidence-grid">${value(`${side} dimensions`,`${info.width} × ${info.height} pixels`)}${value(`${side} format / mode / channels`,`${info.format} / ${info.mode} / ${info.channels}`)}${value(`${side} encoded size`,`${info.encoded_bytes} bytes`)}</div>`;
    }
    if (image.mse !== undefined) html += `<div class="evidence-grid">${value('Mean squared error (RGBA)',image.mse)}${value('Peak signal-to-noise ratio',image.psnr_db === null ? image.psnr : `${image.psnr_db.toFixed(6)} dB`)}${value('Decoded pixels identical',image.pixels_equal ? 'Yes' : 'No')}</div>`;
    html += `<p class="muted">${escaped(image.comparison)} ${escaped(image.scope || '')}</p>`;
  }
  html += '<h3>Transfer logs</h3><p class="muted">Client activity and matching server audit events. Verify server audit integrity in Security & audit.</p>';
  const logs = [...data.client_events.map(event => ({...event,origin:'Client'})),...data.server_events.map(event => ({...event,origin:'Server'}))].sort((a,b) => a.timestamp.localeCompare(b.timestamp));
  html += '<div class="table-scroll evidence-logs"><table><thead><tr><th>DATE & TIME · IST</th><th>ORIGIN / EVENT</th><th>OUTCOME</th><th>DETAILS</th></tr></thead><tbody>';
  html += logs.map(event => `<tr><td>${timestampMarkup(event.timestamp)}</td><td>${escaped(event.origin)}<br>${escaped(event.event)}</td><td>${escaped(event.outcome)}</td><td>${escaped(typeof event.details === 'string' ? event.details : JSON.stringify(event.details))}${event.hash ? `<br>Audit hash: <code>${escaped(event.hash)}</code>` : ''}</td></tr>`).join('') || '<tr><td colspan="4">No recorded events for this transfer.</td></tr>';
  html += `</tbody></table></div><p class="muted">${escaped(data.server_log_scope)} Export Evidence JSON for the complete selected record, including request/session IDs.</p>`;
  $('#evidence-content').innerHTML = html;
}
$('#evidence-file').addEventListener('change', () => { evidenceVersion = ''; renderEvidenceSelector(); });
$('#refresh-evidence').addEventListener('click', () => { evidenceVersion = ''; renderEvidenceSelector(); });
$('#export-evidence').addEventListener('click', () => saveResponse(`/api/evidence/${evidenceSelection}`,`evidence_${evidenceSelection}.json`).catch(error => toast(error.message,true)));
$('#export-audit').addEventListener('click', () => saveResponse('/api/logs/audit.jsonl','server_audit.jsonl').catch(error => toast(error.message,true)));
setInterval(() => { if(state) renderEvidenceSelector(); }, 1000);
refresh();
