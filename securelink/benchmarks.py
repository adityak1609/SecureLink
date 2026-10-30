import csv
import json
import math
import platform
import os
from pathlib import Path
import statistics
import threading
import time
from contextlib import ExitStack

import psutil
from .client import Client
from .lab import local_lab

class MemorySampler:
    def __enter__(self):
        self.process=psutil.Process();self.baseline=self.process.memory_info().rss;self.peak=self.baseline
        self.stop=threading.Event()
        def sample():
            while not self.stop.wait(.002):self.peak=max(self.peak,self.process.memory_info().rss)
        self.thread=threading.Thread(target=sample,daemon=True);self.thread.start()
        return self
    def __exit__(self,*args):
        self.peak=max(self.peak,self.process.memory_info().rss)
        self.stop.set();self.thread.join()

def run(output,iterations=30):
    if iterations<2:raise ValueError('At least two iterations required')
    output=Path(output)
    if output.exists():raise FileExistsError('Choose a fresh benchmark directory')
    output.mkdir(parents=True)
    rows=[]
    fixtures=Path('sample_data/fixtures')
    with ExitStack() as stack:
        labs={mode:stack.enter_context(local_lab(output/mode,plaintext=mode=='plaintext')) for mode in ('secure','plaintext')}
        for name in ('transaction.txt','identity.png','audio.wav'):
            source=fixtures/name
            for iteration in range(-1,iterations):
                # Alternate execution order to reduce systematic ordering bias.
                for mode in (('secure','plaintext') if iteration%2 else ('plaintext','secure')):
                    server,key,_,_=labs[mode]
                    with MemorySampler() as memory:
                        start=time.perf_counter();cpu=time.process_time()
                        with Client(server.address,'terminal-1',key,plaintext_lab=mode=='plaintext') as client:
                            result=client.upload(source)
                            latency=time.perf_counter()-start
                            cpu_ms=(time.process_time()-cpu)*1000
                        wire_bytes=client.sent_bytes+client.received_bytes
                    if iteration>=0:
                        rows.append({'file':name,'mode':mode,'iteration':iteration,'bytes':source.stat().st_size,
                                     'latency_ms':latency*1000,'goodput_mib_s':source.stat().st_size/1048576/latency,
                                     'process_cpu_ms':cpu_ms,'sampled_peak_rss_mib':memory.peak/1048576,
                                     'rss_increase_mib':(memory.peak-memory.baseline)/1048576,
                                     'handshake_ms':client.handshake_ms,'client_protocol_bytes':wire_bytes,
                                     'retries':client.retries,'success':result['complete']})
            print(f'Benchmarked {name}: {iterations} repetitions per mode',flush=True)
        for server,key,audit,remote in labs.values():audit.verify()
    with (output/'measurements.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=rows[0]);writer.writeheader();writer.writerows(rows)
    summary=[]
    for name in sorted({row['file'] for row in rows}):
        for mode in ('plaintext','secure'):
            group=[row for row in rows if row['file']==name and row['mode']==mode]
            latencies=sorted(row['latency_ms'] for row in group)
            summary.append({'file':name,'mode':mode,'n':len(group),'median_latency_ms':statistics.median(latencies),
                'p95_latency_ms':latencies[math.ceil(.95*len(latencies))-1],
                'median_goodput_mib_s':statistics.median(row['goodput_mib_s'] for row in group),
                'median_cpu_ms':statistics.median(row['process_cpu_ms'] for row in group),
                'peak_rss_mib':max(row['sampled_peak_rss_mib'] for row in group),
                'median_handshake_ms':statistics.median(row['handshake_ms'] for row in group),
                'median_client_protocol_bytes':statistics.median(row['client_protocol_bytes'] for row in group),
                'success_rate':sum(row['success'] for row in group)/len(group)})
    report={'environment':{'python':platform.python_version(),'platform':platform.platform(),'cpu_count':psutil.cpu_count()},
        'method':'Cold connection per transfer; full upload through durable receiver ACK; one discarded warmup per mode/file; alternating order; identical chunking and audit policy.',
        'limits':['Client, server and witness share one process and machine: CPU/RSS are aggregate, not per-device.',
                  'Windows process CPU time may be quantized; a zero measurement is below timer resolution, not zero computational work.',
                  'RSS sampled every 2ms; very short peaks may be missed.',
                  'Protocol byte count includes client-server handshake and application frames, excludes TCP/IP and separate witness traffic.',
                  'Baseline disables client-server authentication/encryption only, and is restricted to loopback.',
                  'Timing includes local hashing, disk persistence and audit anchoring; no claim of cryptography-only latency.'],
        'summary':summary}
    (output/'summary.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    plot(summary,output/'comparison.png')
    return report

def plot(summary,path):
    os.environ.setdefault('MPLCONFIGDIR',str(Path('runtime/matplotlib').resolve()))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    names=sorted({row['file'] for row in summary})
    fig,axes=plt.subplots(1,2,figsize=(11,4.3),layout='constrained')
    for axis,metric,title in zip(axes,['median_latency_ms','median_goodput_mib_s'],['Median completion latency (ms)','Median useful throughput (MiB/s)']):
        for offset,mode,color in [(-.18,'plaintext','#8296aa'),(.18,'secure','#215b91')]:
            values=[next(row[metric] for row in summary if row['file']==name and row['mode']==mode) for name in names]
            axis.bar([i+offset for i in range(len(names))],values,width=.36,label=mode,color=color)
        axis.set_xticks(range(len(names)),names,rotation=15);axis.set_title(title);axis.legend();axis.grid(axis='y',alpha=.2)
    fig.suptitle('SecureLink measured transfers on simulated loopback endpoints')
    fig.savefig(path,dpi=160);plt.close(fig)
