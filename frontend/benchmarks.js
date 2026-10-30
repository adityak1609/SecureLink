'use strict';
// Benchmark UI only reads the authenticated local API. No keys or input bytes reach JavaScript.
const benchmarkAlgorithms = {
  aead:['AES-256-GCM'],
  hash:['SHA-256'],
  signature:['Ed25519']
};
const benchmarkMetrics = {
  aead:['milliseconds','throughput_mib_s'],
  hash:['milliseconds'],
  signature:['milliseconds']
};
const benchmarkMetricLabels = {
  milliseconds:'Time (ms)',throughput_mib_s:'Encryption / decryption speed (MiB/s)'
};
const bench = {runs:new Map(),observations:new Map(),selected:'',report:null,distributionSize:null,
               runListKey:'',jobKey:'',loading:'',autoSelect:false};
const benchEl = id => document.getElementById(id);
function sizeLabel(size) { return bytes(size); }
function metricNumber(value,field) {
  if (value === undefined || value === null || value === '') return 'Not measured';
  return `${Number(value).toFixed(Number(value) < 1 ? 4 : 2)}${field === 'milliseconds' ? ' ms' : ' MiB/s'}`;
}
function benchmarkConfig() {
  return {category:benchEl('benchmark-category').value,
          algorithms:benchmarkAlgorithms[benchEl('benchmark-category').value],
          dataset:'sizes',
          sizes:$$('[name="benchmark-size"]:checked').map(input=>Number(input.value)),
          iterations:Number(benchEl('benchmark-iterations').value)};
}
function estimate() {
  const config=benchmarkConfig();
  const cases=config.iterations * config.sizes.length;
  const invalid=!config.sizes.length;
  benchEl('benchmark-estimate').textContent=invalid ? 'Select at least one text size.' : `${cases} measured trials plus warmups`;
  benchEl('benchmark-run').disabled=invalid || busy();
}
function updateBenchmarkState(snapshot) {
  const job=snapshot.jobs.slice().reverse().find(row=>row.label==='Run performance benchmark');
  const running=job && ['running','queued'].includes(job.status);
  const key=job ? `${job.id}:${job.status}:${job.benchmark_done||0}:${job.benchmark_step||''}` : '';
  if (key!==bench.jobKey) {
    bench.jobKey=key;
    benchEl('benchmark-progress').innerHTML=running ? `<div class="progress-caption"><strong>${escaped(job.benchmark_step||'Preparing experiment')}</strong><span>${job.benchmark_done||0} / ${job.benchmark_total||'…'} cases</span></div><div class="progress-track"><span style="width:${job.benchmark_total ? Math.round((job.benchmark_done||0)/job.benchmark_total*100) : 2}%"></span></div>` : job?.status==='failed' ? `<span class="benchmark-error">${escaped(job.error)}</span>` : job?.result?.cancelled ? 'Experiment stopped; incomplete results were discarded.' : '';
  }
  benchEl('benchmark-cancel').disabled=!running;
  estimate();
  const runs=snapshot.benchmarks||[];
  const listKey=runs.map(row=>row.id).join(',');
  if (listKey!==bench.runListKey) {
    bench.runListKey=listKey;
    bench.runs=new Map(runs.map(row=>[row.id,row]));
    const options=runs.map(row=>`<option value="${row.id}">${escaped(row.config.algorithms[0])} · ${row.config.iterations} reps · ${escaped(new Date(row.finished_at).toLocaleString('en-GB',{timeZone:'Asia/Kolkata'}))} · ${row.id.slice(0,6)}</option>`).join('');
    benchEl('benchmark-history').innerHTML=options||'<option value="">No saved benchmarks yet</option>';
    if (bench.autoSelect && runs.length) { bench.selected=runs[0].id; bench.autoSelect=false; }
    else if (!bench.runs.has(bench.selected)) bench.selected=runs[0]?.id||'';
    benchEl('benchmark-history').value=bench.selected;
    if (bench.selected) loadBenchmark(bench.selected);
  }
}
async function loadBenchmark(id) {
  if (!id || bench.loading===id) return;
  bench.loading=id;
  benchEl('benchmark-result').textContent='Loading saved measurements…';
  try {
    const report=await (await api(`/api/benchmarks/${id}`)).json();
    const raw=await (await api(`/api/benchmarks/${id}/observations`)).json();
    if (bench.selected!==id) return;
    bench.report=report;
    bench.distributionSize=null;
    bench.observations.set(id,raw);
    const current=benchEl('benchmark-metric').value;
    benchEl('benchmark-metric').innerHTML=benchmarkMetrics[report.config.category].map(name=>`<option value="${name}">${benchmarkMetricLabels[name]}</option>`).join('');
    if (benchmarkMetrics[report.config.category].includes(current)) benchEl('benchmark-metric').value=current;
    const operations=[...new Set(report.summary.map(row=>row.operation))];
    benchEl('benchmark-operation').innerHTML=operations.map(name=>`<option value="${escaped(name)}">${escaped(name)}</option>`).join('');
    benchEl('benchmark-operation').value=operations.includes('encrypt') ? 'encrypt' : operations.includes('hash') ? 'hash' : 'sign';
    renderBenchmark();
  } catch(error) { benchEl('benchmark-result').textContent=error.message; }
  finally { if (bench.loading===id) bench.loading=''; }
}
function chartRows() {
  const operation=benchEl('benchmark-operation').value;
  const metric=benchEl('benchmark-metric').value;
  return bench.report.summary.filter(row=>row.operation===operation && row.metrics[metric]);
}
function lineChart(rows,metric) {
  const sizes=[...new Set(rows.map(row=>row.size_bytes))].sort((a,b)=>a-b);
  const largest=Math.max(1e-9,...rows.map(row=>row.metrics[metric].p95));
  const colors=['#9b4329','#315c82','#26765f','#8262a0'];
  const width=700,height=270,left=56,right=20,top=18,bottom=46;
  const x=size=>left+(sizes.length===1 ? (width-left-right)/2 : sizes.indexOf(size)/(sizes.length-1)*(width-left-right));
  const y=value=>top+(height-top-bottom)*(1-value/largest);
  const grid=[0,.25,.5,.75,1].map(fraction=>`<g><line x1="${left}" y1="${y(largest*fraction)}" x2="${width-right}" y2="${y(largest*fraction)}" stroke="#d5deea"/><text x="${left-7}" y="${y(largest*fraction)+4}" text-anchor="end">${(largest*fraction).toFixed(largest<1?3:1)}</text></g>`).join('');
  const series=bench.report.config.algorithms.map((name,index)=>{
    const points=rows.filter(row=>row.algorithm===name).sort((a,b)=>a.size_bytes-b.size_bytes);
    if (!points.length) return '';
    const color=colors[index%colors.length];
    const path=points.map((row,i)=>`${i?'L':'M'}${x(row.size_bytes)},${y(row.metrics[metric].median)}`).join(' ');
    const marks=points.map(row=>`<g><line x1="${x(row.size_bytes)}" x2="${x(row.size_bytes)}" y1="${y(row.metrics[metric].median)}" y2="${y(row.metrics[metric].p95)}" stroke="${color}"/><circle cx="${x(row.size_bytes)}" cy="${y(row.metrics[metric].median)}" r="5" fill="${color}"><title>${escaped(name)} · ${sizeLabel(row.size_bytes)} · median ${metricNumber(row.metrics[metric].median,metric)} · p95 ${metricNumber(row.metrics[metric].p95,metric)}</title></circle></g>`).join('');
    return `<path d="${path}" fill="none" stroke="${color}" stroke-width="2.5"/>${marks}`;
  }).join('');
  const labels=sizes.map(size=>`<text x="${x(size)}" y="${height-12}" text-anchor="middle">${sizeLabel(size)}</text>`).join('');
  return `<div class="benchmark-svg-scroll"><svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Median ${escaped(benchmarkMetricLabels[metric])} by payload size, with p95 whiskers">${grid}${series}${labels}</svg></div><div class="benchmark-legend">${bench.report.config.algorithms.map((name,index)=>`<span><i style="background:${colors[index%colors.length]}"></i>${escaped(name)}</span>`).join('')}</div>`;
}
function distribution(rows,metric,operation) {
  const sizes=[...new Set(rows.map(row=>row.size_bytes))].sort((a,b)=>a-b);
  const selected=sizes.includes(bench.distributionSize) ? bench.distributionSize : sizes.at(-1);
  const raw=(bench.observations.get(bench.selected)||[]).filter(row=>row.operation===operation && Number(row.size_bytes)===selected && row[metric]!=='' && row[metric]!==null);
  const max=Math.max(1e-9,...raw.map(row=>Number(row[metric])));
  return `<label class="benchmark-inline-label">OBSERVATION SIZE<select id="benchmark-distribution-size">${sizes.map(size=>`<option value="${size}" ${size===selected?'selected':''}>${sizeLabel(size)}</option>`).join('')}</select></label><div class="benchmark-distributions">${bench.report.config.algorithms.map(name=>{
    const values=raw.filter(row=>row.algorithm===name);
    const dots=values.map((row,index)=>`<span class="benchmark-dot" style="left:${Math.min(98,Number(row[metric])/max*97)}%;top:${3+(index%3)*7}px" title="Trial ${Number(row.iteration)+1}: ${metricNumber(Number(row[metric]),metric)}"></span>`).join('');
    return `<div class="benchmark-distribution-row"><strong>${escaped(name)}</strong><div class="benchmark-dot-track">${dots}</div><span>${values.length} trials</span></div>`;
  }).join('')}</div><p class="muted">Each dot is one measured repetition at ${sizeLabel(selected)}. Its exact value is in the observation table and CSV.</p>`;
}
function renderBenchmark() {
  const report=bench.report;
  if (!report || !bench.selected) return;
  const metric=benchEl('benchmark-metric').value,operation=benchEl('benchmark-operation').value;
  const rows=chartRows();
  const selected=rows.length ? rows : [];
  const table=selected.map(row=>`<tr><td>${escaped(row.algorithm)}</td><td>${row.sample ? escaped(row.sample) : sizeLabel(row.size_bytes)}</td><td>${row.n}</td><td>${metricNumber(row.metrics[metric].median,metric)}</td><td>${metricNumber(row.metrics[metric].p95,metric)}</td><td>${metricNumber(row.metrics[metric].stdev,metric)}</td><td>${(row.success_rate*100).toFixed(0)}%</td></tr>`).join('');
  const checks=report.checks.map(item=>`<span class="benchmark-check">✓ ${escaped(item.name)} · ${item.passed}</span>`).join('');
  const raw=(bench.observations.get(bench.selected)||[]).filter(row=>row.operation===operation);
  benchEl('benchmark-result').innerHTML=`<div class="benchmark-run-heading"><div><h2>${escaped(report.config.algorithms[0])} · ${report.config.iterations} repetitions</h2><p>${report.observations} measured observations · Completed ${escaped(new Date(report.finished_at).toLocaleString('en-GB',{timeZone:'Asia/Kolkata'}))} IST</p></div><div class="export-buttons"><button class="button secondary" data-benchmark-export="json">↓ JSON report</button><button class="button secondary" data-benchmark-export="csv">↓ Raw CSV</button><button class="button secondary" data-benchmark-export="png">↓ Chart PNG</button></div></div>
    <div class="benchmark-checks">${checks}</div>
    <section class="benchmark-chart-card"><h3>${escaped(benchmarkMetricLabels[metric])} by payload size</h3><p>Line: median of measured repetitions. Whisker: p95. Values are descriptive for this machine and run.</p>${selected.length ? lineChart(selected,metric) : '<p>No measurement exists for this operation and metric. Select another metric.</p>'}</section>
    ${selected.length ? `<section class="benchmark-chart-card"><h3>Repeated observations</h3>${distribution(selected,metric,operation)}</section>` : ''}
    <h3>Exact summary · ${escaped(operation)}</h3><div class="table-scroll benchmark-table"><table><thead><tr><th>ALGORITHM</th><th>INPUT</th><th>N</th><th>MEDIAN</th><th>P95</th><th>STD DEV</th><th>SUCCESS</th></tr></thead><tbody>${table||'<tr><td colspan="7">No measurements for this selection.</td></tr>'}</tbody></table></div>
    <details class="benchmark-raw"><summary>Inspect every measured observation (${raw.length} rows for ${escaped(operation)})</summary><div class="table-scroll"><table><thead><tr><th>ALGORITHM</th><th>INPUT SIZE</th><th>TRIAL</th><th>TIME (ms)</th>${report.config.category === 'aead' ? '<th>SPEED (MiB/s)</th>' : ''}</tr></thead><tbody>${raw.map(row=>`<tr><td>${escaped(row.algorithm)}</td><td>${sizeLabel(Number(row.size_bytes))}</td><td>${Number(row.iteration)+1}</td><td>${metricNumber(Number(row.milliseconds),'milliseconds')}</td>${report.config.category === 'aead' ? `<td>${metricNumber(row.throughput_mib_s === '' ? null : Number(row.throughput_mib_s),'throughput_mib_s')}</td>` : ''}</tr>`).join('')}</tbody></table></div></details>`;
  benchEl('benchmark-method-panel').hidden=false;
  benchEl('benchmark-method').innerHTML=`<p>${escaped(report.method)}</p><p>Python ${escaped(report.environment.python)} · cryptography ${escaped(report.environment.cryptography)} · ${escaped(report.environment.platform)}</p><ul>${report.limits.map(item=>`<li>${escaped(item)}</li>`).join('')}</ul>`;
  $$('[data-benchmark-export]').forEach(button=>button.addEventListener('click',()=>saveResponse(`/api/benchmarks/${bench.selected}/export/${button.dataset.benchmarkExport}`,
    `securelink_${bench.selected}.${button.dataset.benchmarkExport}`).catch(error=>toast(error.message,true))));
  benchEl('benchmark-distribution-size')?.addEventListener('change',event=>{ bench.distributionSize=Number(event.target.value); renderBenchmark(); });
}
benchEl('benchmark-category').addEventListener('change',estimate);
benchEl('benchmark-iterations').addEventListener('change',estimate);
benchEl('benchmark-size-field').addEventListener('change',estimate);
benchEl('benchmark-run').addEventListener('click',()=>{bench.autoSelect=true;action('/api/benchmarks/run',benchmarkConfig());});
benchEl('benchmark-cancel').addEventListener('click',async()=>{try{await api('/api/benchmarks/cancel',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});toast('Stopping after the current trial.');}catch(error){toast(error.message,true);}});
benchEl('benchmark-history').addEventListener('change',()=>{bench.selected=benchEl('benchmark-history').value;bench.report=null;loadBenchmark(bench.selected);});
benchEl('benchmark-metric').addEventListener('change',renderBenchmark);
benchEl('benchmark-operation').addEventListener('change',renderBenchmark);
estimate();
setInterval(()=>{if(state)updateBenchmarkState(state);},1000);
