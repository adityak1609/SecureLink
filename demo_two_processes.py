"""Start independently running server/witness processes and a client endpoint."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from securelink.audit import WitnessClient, AuditLog
from securelink.capture import StreamCapture
from securelink.client import Client
from securelink.credentials import provision,load
from securelink.storage import file_hash
from securelink.analysis import analyze

def wait_ready(path,process):
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        if process.poll() is not None:raise RuntimeError('Service exited; see service console log')
        if path.exists():
            try:return tuple(json.loads(path.read_text(encoding='utf-8')))
            except ValueError:pass
        time.sleep(.05)
    raise TimeoutError('Service startup deadline exceeded')

def run(directory):
    root=Path(directory).resolve()
    if root.exists():raise FileExistsError('Use a fresh demo output directory')
    root.mkdir(parents=True)
    # Keep secrets in excluded runtime storage, never in evidence deliverables.
    secret_root=Path('runtime')/('process_demo_'+str(time.time_ns()))
    provision(secret_root)
    processes=[];logs=[]
    try:
        def start(script,args,name):
            log=(root/(name+'.console.log')).open('w',encoding='utf-8');logs.append(log)
            proc=subprocess.Popen([sys.executable,'-u',script,*map(str,args)],stdout=log,stderr=subprocess.STDOUT,
                                  creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            processes.append(proc);return proc
        witness=start('witness_server.py',['--port',0,'--credentials',secret_root/'witness.json',
                      '--database',root/'witness.sqlite','--ready-file',root/'witness.ready.json'],'witness')
        witness_address=wait_ready(root/'witness.ready.json',witness)
        bank=start('bank_server.py',['--port',0,'--credentials',secret_root/'server.json',
                   '--state',root/'bank','--audit-log',root/'audit.jsonl','--witness-port',witness_address[1],
                   '--ready-file',root/'bank.ready.json'],'bank')
        bank_address=wait_ready(root/'bank.ready.json',bank)
        config=load(secret_root/'client.json')
        results={'topology':'Three separate processes on one Windows host over loopback; not separate physical devices',
                 'client_pid':os.getpid(),'bank_pid':bank.pid,'witness_pid':witness.pid,
                 'bank_address':bank_address,'witness_address':witness_address,'transfers':[]}
        with StreamCapture(bank_address,root/'session_stream.pcap') as capture:
            with Client(capture.address,config['device'],bytes.fromhex(config['secret'])) as client:
                for name in ('transaction.txt','identity.png','audio.wav'):
                    source=Path('sample_data/fixtures')/name
                    uploaded=client.upload(source)
                    downloaded=client.download(uploaded['request'],root/'downloads'/name)
                    assert file_hash(source)==file_hash(downloaded)
                    results['transfers'].append({'name':name,'request':uploaded['request'],
                        'sha256':file_hash(downloaded),'verified':True,'bytes':source.stat().st_size})
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                with capture.lock:
                    if not capture.connections:break
                time.sleep(.02)
        config=load(secret_root/'server.json')
        audit=AuditLog.__new__(AuditLog);audit.path=root/'audit.jsonl'
        audit.witness=WitnessClient(witness_address,config['audit_identity'],bytes.fromhex(config['audit_secret']))
        results['audit_records'],results['audit_head']=audit.verify()
        results['capture']=analyze(root/'session_stream.pcap',root/'analysis')
        (root/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
        print(json.dumps(results,indent=2))
    finally:
        for process in reversed(processes):
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        for log in logs:log.close()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',default='results/two_process_demo')
    run(p.parse_args().output)
