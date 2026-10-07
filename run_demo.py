"""Reproducible multimedia, capture and recovery demonstration."""
import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid
from PIL import Image
import imageio_ffmpeg

from securelink.analysis import analyze,tshark_path,open_pyshark
from securelink.capture import StreamCapture,stream_records
from securelink.client import Client
from securelink.lab import local_lab
from securelink.storage import file_hash

def run(output):
    output=Path(output)
    if output.exists():raise FileExistsError('Use a fresh output directory to preserve earlier evidence')
    output.mkdir(parents=True)
    results={'topology':'Separate TCP endpoints on IPv4 loopback in one process; shared CPU and memory',
             'capture_type':'Actual socket stream bytes in USER0 PCAP; no IP/TCP headers', 'modes':{}}
    fixtures=Path('sample_data/fixtures')
    for mode in ('secure','plaintext'):
        plain=mode=='plaintext';root=output/mode
        with local_lab(root,plaintext=plain) as (server,key,audit,remote):
            with StreamCapture(server.address,root/'session_stream.pcap',attempts_per_minute=100000) as observer:
                transfers=[]
                with Client(observer.address,'terminal-1',key,plaintext_lab=plain) as client:
                    for filename in ('transaction.txt','identity.png','audio.wav','video.mp4'):
                        source=fixtures/filename
                        result=client.upload(source)
                        received=client.download(result['request'],root/'downloads'/filename)
                        assert file_hash(source)==file_hash(received)
                        if received.suffix=='.png':
                            with Image.open(received) as image:image.verify()
                        elif received.suffix in ('.wav','.mp4'):
                            subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(),'-v','error','-xerror','-i',str(received),'-f','null','-'],check=True)
                        transfers.append({'file':filename,'request':result['request'],'bytes':result['metadata']['size'],
                                          'sha256':result['metadata']['sha256'],'roundtrip_verified':True,'decoded':True})
                # Ensure observer pumps finish before closing output.
                deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    with observer.lock:
                        if not observer.connections:break
                    time.sleep(.01)
            count,head=audit.verify()
            summary=analyze(root/'session_stream.pcap',root/'analysis')
            assert summary['marker_found']==plain
            evidence={'transfers':transfers,'audit_records':count,'audit_head':head,'capture':summary}
            executable=tshark_path()
            if executable:
                with open_pyshark(root/'session_stream.pcap') as cap:
                    packet_count=sum(1 for _ in cap)
                assert packet_count==summary['records']
                evidence['pyshark_verified_records']=packet_count
            results['modes'][mode]=evidence
    drops=[]
    def fault(kind,request,result):
        if kind=='finish' and not drops:
            drops.append(time.perf_counter());return True
        return False
    with local_lab(output/'recovery',fault=fault) as (server,key,audit,remote):
        request=uuid.uuid4().hex
        with Client(server.address,'terminal-1',key,retry_delay=.1) as client:
            result=client.upload(fixtures/'transaction.txt',request)
            recovery_ms=(time.perf_counter()-drops[0])*1000
            client.upload(fixtures/'transaction.txt',request)
            with server.store.connect() as db:transactions=db.execute('SELECT count(*) FROM transactions').fetchone()[0]
            assert transactions==1 and client.retries==1
            results['recovery']={'injected_failure':'Connection closed after durable commit before ACK',
                                 'retries':client.retries,'recovery_ms':recovery_ms,'ledger_entries':transactions,
                                 'completed':result['complete']}
        results['recovery']['audit_records']=audit.verify()[0]
    (output/'demo_results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    return results

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',default='results/demo')
    result=run(p.parse_args().output)
    print(json.dumps(result,indent=2))
