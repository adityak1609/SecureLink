'use strict';
const labUI = {selected:'', version:'', report:null, loading:'', urls:[], offset:0, next:null, autoSelect:false};
const labEl = id => document.getElementById(id);
const labPercent = value => `${Number(value).toFixed(3)}%`;
const labTime = value => value ? `${value.milliseconds.toFixed(6)} ms` : 'Not performed yet';
const labValue = (label,value) => `<div class="lab-key-value"><span>${escaped(label)}</span><code>${escaped(value ?? 'Not recorded')}</code></div>`;

function updateLabState() {
  if (!state) return;
  const runs=state.crypto_lab || [], previous=labUI.selected;
  const listKey=runs.map(row=>`${row.id}:${row.decrypted}:${row.decrypted_at || ''}`).join(',');
  if (labEl('lab-history').dataset.version !== listKey) {
    labEl('lab-history').dataset.version=listKey;
    labEl('lab-history').innerHTML=runs.map(row=>`<option value="${row.id}">${escaped(row.name)} · ${row.id.slice(0,8)} · ${row.decrypted ? 'Verified' : 'Encrypted'}</option>`).join('') || '<option value="">No demonstrations yet</option>';
    if (labUI.autoSelect && runs.length) { labUI.selected=runs[0].id; labUI.autoSelect=false; }
    else labUI.selected=runs.some(row=>row.id===previous) ? previous : runs[0]?.id || '';
    labEl('lab-history').value=labUI.selected;
  }
  const row=runs.find(row=>row.id===labUI.selected);
  const version=row ? `${row.id}:${row.decrypted}:${row.decrypted_at || ''}` : '';
  if (!labEl('cryptolab-view').hidden && version && version!==labUI.version && version!==labUI.loading) loadLab(version);
  const locked=busy();
  labEl('lab-encrypt-text').disabled=locked || !labEl('lab-text').value.trim();
  labEl('lab-file').disabled=locked;
  labEl('lab-decrypt').disabled=locked || !row;
  labEl('lab-export').disabled=!row;
  labEl('lab-signature').disabled=!row;
  labEl('lab-save-recovered').disabled=!row?.decrypted;
}

async function encryptLab(blob,name) {
  if (busy()) return;
  if (!/\.(txt|png|jpe?g)$/i.test(name) || !blob.size || blob.size>32*1024*1024) {
    toast('Choose nonempty UTF-8 text, PNG or JPEG up to 32 MiB.',true); return;
  }
  pending=true; updateButtons(); updateLabState();
  labEl('lab-input-status').textContent=`Encrypting ${name} and measuring security…`;
  try {
    await api(`/api/lab/encrypt?name=${encodeURIComponent(name)}`,{method:'POST',body:blob});
    labUI.autoSelect=true;
    await refresh();
  } catch(error) { toast(error.message,true); }
  finally { pending=false; updateButtons(); updateLabState(); labEl('lab-input-status').textContent='Files up to 32 MiB. No device connection needed.'; }
}

async function labPreview(id,side,element) {
  const response=await api(`/api/lab/${id}/${side}`), blob=await response.blob();
  if (id!==labUI.selected) return;
  element.replaceChildren();
  if (labUI.report.metadata.media==='text') {
    const text=await blob.slice(0,65536).text();
    if (id!==labUI.selected) return;
    const pre=document.createElement('pre'); pre.textContent=text; element.append(pre);
    if (blob.size>65536) { const note=document.createElement('small'); note.textContent='First 64 KiB preview. Save the complete file to inspect all text.'; element.append(note); }
  } else {
    const url=URL.createObjectURL(blob); labUI.urls.push(url);
    const image=document.createElement('img'); image.src=url; image.alt=`${side==='source' ? 'Original' : 'Decrypted'} ${labUI.report.metadata.name}`; element.append(image);
  }
}

async function loadLab(version) {
  const id=labUI.selected; labUI.loading=version;
  try {
    const report=await (await api(`/api/lab/${id}`)).json();
    if (id!==labUI.selected) return;
    labUI.urls.forEach(url=>URL.revokeObjectURL(url)); labUI.urls=[];
    labUI.report=report; labUI.version=version;
    labEl('lab-content').hidden=false;
    labEl('lab-status').textContent=report.decrypted ? `${report.metadata.name}: decrypted bytes match SHA-256; pinned Ed25519 signature verified.` : `${report.metadata.name}: encrypted and signed. Choose Decrypt & verify to recover the plaintext.`;
    labEl('lab-recovered').textContent='Choose Decrypt & verify.';
    renderLabResults(report);
    await Promise.all([labPreview(id,'source',labEl('lab-original')),
      report.decrypted ? labPreview(id,'recovered',labEl('lab-recovered')) : Promise.resolve(), loadCipherPage(0)]);
  } catch(error) { toast(error.message,true); }
  finally { if(labUI.loading===version) labUI.loading=''; updateLabState(); }
}

async function loadCipherPage(offset) {
  const id=labUI.selected;
  try {
    const page=await (await api(`/api/lab/${id}/hex?offset=${offset}`)).json();
    if (id!==labUI.selected) return;
    labUI.offset=page.offset; labUI.next=page.next_offset;
    const rows=[];
    for(let index=0;index<page.hex.length;index+=32) rows.push(`${(page.offset+index/2).toString(16).padStart(8,'0')}  ${page.hex.slice(index,index+32).match(/.{1,2}/g).join(' ')}`);
    labEl('lab-ciphertext').textContent=rows.join('\n');
    labEl('lab-cipher-scope').textContent=`Showing ciphertext bytes ${page.offset+1}–${page.offset+page.length} of ${page.total}. Navigate to any byte or download the full ciphertext with its 16-byte tag. The tag and nonce appear below.`;
    labEl('lab-cipher-offset').value=page.offset; labEl('lab-cipher-offset').max=page.total-1;
    labEl('lab-cipher-prev').disabled=page.offset===0; labEl('lab-cipher-next').disabled=page.next_offset===null;
  } catch(error) { toast(error.message,true); }
}

function sensitivityChart(series) {
  const width=620,height=225,left=40,right=10,top=15,bottom=30;
  const x=index=>left+index/(series.trials.length-1)*(width-left-right);
  const y=value=>top+(100-value)/100*(height-top-bottom);
  const path=field=>series.trials.map((trial,index)=>`${index ? 'L':'M'}${x(index).toFixed(2)},${y(trial[field]).toFixed(2)}`).join(' ');
  return `<svg class="lab-sensitivity-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escaped(series.kind)} bit and byte-character avalanche for each flipped bit">
    ${[0,50,100].map(value=>`<line x1="${left}" y1="${y(value)}" x2="${width-right}" y2="${y(value)}" stroke="#9caec3" stroke-dasharray="4 3"/><text x="${left-5}" y="${y(value)+4}" text-anchor="end">${value}%</text>`).join('')}
    <path d="${path('character_percent')}" fill="none" stroke="#315c82" stroke-width="1.4"/><path d="${path('bit_percent')}" fill="none" stroke="#9b4329" stroke-width="1.4"/>
    <text x="${left}" y="${height-5}">Bit 0</text><text x="${width-right}" y="${height-5}" text-anchor="end">Bit ${series.trial_count-1}</text></svg><div class="lab-legend">Orange: changed bits · Blue: changed byte characters. Dashed references: 50% bits and 100% characters.</div>`;
}

function renderLabResults(report) {
  const enc=report.metrics, dec=report.decryption_metrics || {};
  let html='<h3>Measured encryption, hash and signature operations</h3><div class="table-scroll"><table class="crypto-table"><thead><tr><th>OPERATION</th><th>TIME</th><th>SPEED</th></tr></thead><tbody>';
  for(const [label,value] of [['AES-256-GCM encryption',enc.encryption],['AES-256-GCM decryption',dec.decryption],['SHA-256 generation',enc.hashing],['SHA-256 recovered file',dec.hashing],['Ed25519 signature generation',enc.signing],['Ed25519 signature verification',dec.signature_verification]]) {
    html+=`<tr><td>${label}</td><td>${labTime(value)}</td><td>${value?.throughput_mib_s != null ? `${value.throughput_mib_s.toFixed(3)} MiB/s` : '—'}</td></tr>`;
  }
  const timings=[['Encryption',enc.encryption],['Decryption',dec.decryption],['Hash generation',enc.hashing],['Signing',enc.signing],['Verification',dec.signature_verification]];
  const maximum=Math.max(0,...timings.map(([,value])=>value?.milliseconds || 0));
  html+='</tbody></table></div><div class="graph-card crypto-chart"><h4>Measured operation times</h4>'+timings.map(([label,value])=>`<div class="crypto-chart-row"><span class="crypto-operation">${label}</span><div class="crypto-bar-line"><div class="chart-track"><span style="width:${value && maximum ? value.milliseconds/maximum*100 : 0}%"></span></div><strong>${labTime(value)}</strong></div></div>`).join('')+'</div>';
  html+=`<p>${escaped(report.timing_scope)}</p><div class="lab-grid">${labValue('SHA-256 original digest',report.metadata.sha256)}${labValue('SHA-256 decrypted digest',report.received_sha256)}${labValue('AES-GCM nonce (12 bytes)',report.nonce_hex)}${labValue('AES-GCM authentication tag (16 bytes)',report.tag_hex)}</div>`;
  html+='<h3>Digital signature · Ed25519</h3>'+labValue('Stored signature (hex)',report.signature.signature)+labValue('Pinned public signing key',report.signature.public_key);
  html+=`<p>${report.signature_verified ? 'Signature verified against the local pinned public key.' : 'Signature stored. Decrypt to verify it against the local pinned public key.'} The signature binds the file digest, name, size, media, device and demonstration ID. Use Download signature to save its verification context.</p>`;
  html+='<h3>Integrity · modified ciphertext check</h3>';
  html+=`<p>Changed ${report.tampering.payload_difference.changed_bits} ciphertext bit: <strong>${report.tampering.rejected ? 'Rejected by AES-GCM authentication' : 'Unexpected acceptance'}</strong>. ${escaped(report.tampering.scope)}.</p>`;
  const security=report.text_security;
  html+='<h3>Text security · confusion, diffusion and avalanche</h3>';
  if (!security) html+='<p>Encrypt text to measure AES input-bit and key-bit sensitivity. Image encryption, hashing and signatures are measured above.</p>';
  else {
    html+=`<p>${escaped(security.scope)}</p><p>${escaped(security.character_definition)}</p><p>${escaped(security.target_scope)}</p><div class="lab-grid">`;
    for(const series of security.series) {
      html+=`<article class="lab-card"><h4>${series.kind==='diffusion' ? 'Diffusion · one plaintext bit changed' : 'Confusion · one key bit changed'}</h4><p>${series.trial_count} trials · mean bit avalanche <strong>${labPercent(series.mean_bit_percent)}</strong> (reference 50%).<br>Mean byte-character change <strong>${labPercent(series.mean_character_percent)}</strong> (requested reference 100%).<br>Mean hex-character change ${labPercent(series.mean_hex_character_percent)}.</p>${sensitivityChart(series)}<details class="lab-trials"><summary>Inspect all ${series.trial_count} trials</summary><div class="table-scroll"><table><thead><tr><th>INPUT BIT</th><th>BIT CHANGE</th><th>BYTE CHARACTER CHANGE</th><th>OUTPUT HEX</th></tr></thead><tbody>${series.trials.map(trial=>`<tr><td>${trial.input_bit}</td><td>${trial.changed_bits}/${trial.total_bits} · ${labPercent(trial.bit_percent)}</td><td>${trial.changed_characters}/${trial.total_characters} · ${labPercent(trial.character_percent)}</td><td><code>${trial.output_hex}</code></td></tr>`).join('')}</tbody></table></div></details></article>`;
    }
    html+='</div>'+labValue('AES input block (hex)',security.block_hex)+labValue('Baseline AES block output (hex)',security.baseline_ciphertext_hex);
    html+=`<p>${escaped(security.gcm_scope)} <a href="https://csrc.nist.gov/pubs/sp/800/38/d/final" target="_blank" rel="noreferrer">NIST GCM specification</a></p>`;
  }
  const hash=report.hash_resistance;
  html+=`<h3>Hash security · three SHA-256 criteria</h3><p>${escaped(hash.scope)}</p><div class="lab-grid">`;
  const labels={preimage:'Pre-image resistance',second_preimage:'Second pre-image resistance',collision:'Collision resistance'};
  for(const criterion of hash.criteria) html+=`<article class="lab-card"><h4>${labels[criterion.criterion]}</h4><p>${escaped(criterion.definition)}</p><p><strong>${escaped(criterion.outcome)}</strong><br>${criterion.attempts} candidates · ${criterion.milliseconds.toFixed(3)} ms</p><p>${escaped(criterion.candidate_scope)}</p>${criterion.match ? labValue('Observed match',JSON.stringify(criterion.match)) : ''}</article>`;
  html+=`</div><p>SHA-256 digest avalanche after changing one input bit: <strong>${labPercent(hash.digest_avalanche.bit_percent)}</strong> bits and ${labPercent(hash.digest_avalanche.character_percent)} byte characters changed.</p>`+labValue('Digest after one input bit change',hash.one_bit_changed_digest_hex);
  html+='<p><a href="https://csrc.nist.gov/projects/hash-functions" target="_blank" rel="noreferrer">NIST definitions of hash resistance</a></p>';
  if(report.image_metrics) html+=`<h3>Image recovery</h3><p>Decoded pixels identical: <strong>${report.image_metrics.pixels_equal ? 'Yes' : 'See image comparison'}</strong>. MSE: ${escaped(report.image_metrics.mse ?? 'Not available')}. PSNR: ${escaped(report.image_metrics.psnr || report.image_metrics.psnr_db || 'Not available')}.</p>`;
  html+=`<p>${escaped(report.scope)}</p>`;
  labEl('lab-results').innerHTML=html;
}

labEl('lab-encrypt-text').addEventListener('click',()=>encryptLab(new Blob([labEl('lab-text').value],{type:'text/plain;charset=utf-8'}),'message.txt'));
labEl('lab-text').addEventListener('input',updateLabState);
labEl('lab-file').addEventListener('change',event=>{const file=event.target.files[0];if(file)encryptLab(file,file.name);event.target.value='';});
labEl('lab-history').addEventListener('change',()=>{labUI.selected=labEl('lab-history').value;labUI.version='';updateLabState();});
labEl('lab-decrypt').addEventListener('click',()=>action('/api/lab/decrypt',{id:labUI.selected}));
labEl('lab-cipher-next').addEventListener('click',()=>{if(labUI.next!==null)loadCipherPage(labUI.next);});
labEl('lab-cipher-prev').addEventListener('click',()=>loadCipherPage(Math.max(0,labUI.offset-4096)));
labEl('lab-cipher-go').addEventListener('click',()=>{const value=Number(labEl('lab-cipher-offset').value);if(Number.isSafeInteger(value) && value>=0)loadCipherPage(value);else toast('Enter a valid byte offset.',true);});
for(const [id,resource,filename] of [['lab-save-source','source',null],['lab-save-recovered','recovered',null],['lab-save-ciphertext','ciphertext','ciphertext.bin'],['lab-export','report','crypto_report.json'],['lab-signature','signature','signature.json']]) labEl(id).addEventListener('click',()=>saveResponse(`/api/lab/${labUI.selected}/${resource}`,filename || labUI.report.metadata.name).catch(error=>toast(error.message,true)));
setInterval(updateLabState,700);
