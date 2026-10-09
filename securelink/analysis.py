"""PCAP to SQLite/XML plus honest descriptive traffic statistics."""
from collections import Counter
import json
import math
from pathlib import Path
import shutil
import sqlite3
import xml.etree.ElementTree as ET
from importlib.metadata import version
from contextlib import contextmanager, closing
import asyncio

def entropy(data):
    return -sum((n/len(data))*math.log2(n/len(data)) for n in Counter(data).values()) if data else 0.0

def tshark_path():
    direct=shutil.which('tshark')
    if direct:return direct
    root=Path(__file__).resolve().parent.parent
    matches=list((root/'tools').glob('**/tshark.exe'))
    if matches:return str(matches[0])
    system=Path('C:/Program Files/Wireshark/tshark.exe')
    return str(system) if system.exists() else None

def wireshark_path():
    direct=shutil.which('wireshark')
    if direct:return direct
    executable=tshark_path()
    if executable:
        sibling=Path(executable).with_name('Wireshark.exe' if Path(executable).suffix.lower()=='.exe' else 'wireshark')
        if sibling.is_file():return str(sibling)
    return None

@contextmanager
def open_pyshark(path):
    try:
        import pyshark
    except ImportError as exc:
        raise RuntimeError('Install requirements.txt to enable PyShark analysis') from exc
    executable = tshark_path()
    if not executable:
        raise RuntimeError('Wireshark/TShark is required for capture analysis; install Wireshark first')
    loop=asyncio.new_event_loop()
    cap=None
    try:
        dissector=Path(__file__).resolve().parents[1]/'tools'/'securelink_user0.lua'
        cap=pyshark.FileCapture(str(path),keep_packets=False,tshark_path=executable,eventloop=loop,
                               custom_parameters=['-X','lua_script:'+str(dissector)])
        yield cap
    finally:
        if cap is not None:cap.close()
        loop.close()

def network_records(path):
    with open_pyshark(path) as cap:
        for index,packet in enumerate(cap,1):
            observer=getattr(packet,'securelink_stream',None)
            if observer is not None:
                direction=int(observer.direction)
                if direction not in (0,1):
                    raise ValueError('Invalid stream direction decoded by TShark')
                payload=bytes.fromhex(observer.get_field_value('bytes',raw=True) or '')
                yield {'number':index,'timestamp':float(packet.sniff_timestamp),'length':int(packet.length),
                       'connection':int(observer.connection),'direction':direction,'payload':payload,
                       'source':'client' if direction==0 else 'server',
                       'destination':'server' if direction==0 else 'client',
                       'retransmission':None,'kind':'application_stream'}
                continue
            tcp=getattr(packet,'tcp',None)
            network=getattr(packet,'ip',getattr(packet,'ipv6',None))
            payload=bytes.fromhex(str(tcp.payload).replace(':','')) if tcp and hasattr(tcp,'payload') else b''
            yield {'number':index,'timestamp':float(packet.sniff_timestamp),'length':int(packet.length),
                   'connection':int(tcp.stream) if tcp and hasattr(tcp,'stream') else -1,
                   'direction':0,'payload':payload,
                   'source':str(network.src) if network else '', 'destination':str(network.dst) if network else '',
                   'retransmission':bool(tcp and any('retransmission' in f for f in tcp.field_names)),
                   'kind':'network_packet'}

def analyze(path,output,backend='pyshark',marker=b'"amount_paise"'):
    if backend!='pyshark':
        raise ValueError('Capture decoding now requires --backend pyshark; no custom parser fallback')
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    records=network_records(path)
    db_path=output/'packets.sqlite'
    xml_root=ET.Element('Capture',source=str(path),backend=backend)
    summary={'source':str(path),'backend':backend,'engine':'PyShark + Wireshark/TShark',
             'pyshark_version':version('pyshark'),'records':0,'captured_bytes':0,'payload_bytes':0,
             'marker_found':False,'retransmissions':None,'capture_kind':None,
             'interpretation':'Entropy is descriptive, not proof of encryption. USER0 captures contain socket bytes, not TCP packets.'}
    tails={};first=None;last=None;weighted_entropy=0
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute('DROP TABLE IF EXISTS packets')
        db.execute('CREATE TABLE packets (number INTEGER PRIMARY KEY, timestamp REAL, length INTEGER, connection INTEGER, source TEXT, destination TEXT, payload_size INTEGER, entropy REAL, retransmission INTEGER, payload_hex TEXT)')
        for record in records:
            if summary['capture_kind'] is None:
                summary['capture_kind']=record['kind']
                summary['retransmissions']=0 if record['kind']=='network_packet' else None
            elif summary['capture_kind']!=record['kind']:
                raise ValueError('Mixed network and stream captures are not supported')
            data=record['payload'];value=entropy(data)
            key=(record['connection'],record['source'],record['destination'])
            # Stream backend preserves observed byte order; TCP reassembly is
            # deliberately not approximated by concatenating arbitrary packets.
            scan=(tails.get(key,b'')+data) if record['kind']=='application_stream' else data
            summary['marker_found'] |= bool(marker and marker in scan)
            if marker:tails[key]=scan[-(len(marker)-1):] if len(marker)>1 else b''
            fields=(record['number'],record['timestamp'],record['length'],record['connection'],record['source'],
                    record['destination'],len(data),value,record['retransmission'],data.hex())
            db.execute('INSERT INTO packets VALUES (?,?,?,?,?,?,?,?,?,?)',fields)
            element=ET.SubElement(xml_root,'Record',number=str(record['number']))
            for name,item in zip(('timestamp','length','connection','source','destination','payload_size','entropy','retransmission','payload_hex'),fields[1:]):
                ET.SubElement(element,name).text='' if item is None else str(item)
            summary['records']+=1;summary['captured_bytes']+=record['length'];summary['payload_bytes']+=len(data)
            weighted_entropy+=value*len(data)
            if summary['retransmissions'] is not None:summary['retransmissions']+=int(record['retransmission'])
            first=record['timestamp'] if first is None else min(first,record['timestamp'])
            last=record['timestamp'] if last is None else max(last,record['timestamp'])
        if summary['records']==0:raise ValueError('Empty capture')
        assert db.execute('SELECT count(*) FROM packets').fetchone()[0]==summary['records']
    summary['duration_seconds']=last-first
    summary['weighted_record_entropy']=weighted_entropy/max(summary['payload_bytes'],1)
    ET.indent(xml_root)
    ET.ElementTree(xml_root).write(output/'packets.xml',encoding='utf-8',xml_declaration=True)
    assert len(ET.parse(output/'packets.xml').getroot())==summary['records']
    (output/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    return summary
