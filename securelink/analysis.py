"""PCAP to SQLite/XML plus honest descriptive traffic statistics."""
from collections import Counter
import json
import math
from pathlib import Path
import shutil
import sqlite3
import xml.etree.ElementTree as ET
from .capture import stream_records
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

@contextmanager
def open_pyshark(path):
    import pyshark
    loop=asyncio.new_event_loop()
    cap=None
    try:
        cap=pyshark.FileCapture(str(path),keep_packets=False,tshark_path=tshark_path(),eventloop=loop)
        yield cap
    finally:
        if cap is not None:cap.close()
        loop.close()

def network_records(path):
    with open_pyshark(path) as cap:
        for index,packet in enumerate(cap,1):
            tcp=getattr(packet,'tcp',None)
            network=getattr(packet,'ip',getattr(packet,'ipv6',None))
            payload=bytes.fromhex(str(tcp.payload).replace(':','')) if tcp and hasattr(tcp,'payload') else b''
            yield {'number':index,'timestamp':float(packet.sniff_timestamp),'length':int(packet.length),
                   'connection':int(tcp.stream) if tcp and hasattr(tcp,'stream') else -1,
                   'direction':0,'payload':payload,
                   'source':str(network.src) if network else '', 'destination':str(network.dst) if network else '',
                   'retransmission':bool(tcp and any('retransmission' in f for f in tcp.field_names)),
                   'kind':'network_packet'}

def analyze(path,output,backend='stream',marker=b'"amount_paise"'):
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    records=stream_records(path) if backend=='stream' else network_records(path)
    db_path=output/'packets.sqlite'
    xml_root=ET.Element('Capture',source=str(path),backend=backend)
    summary={'source':str(path),'backend':backend,'records':0,'captured_bytes':0,'payload_bytes':0,
             'marker_found':False,'retransmissions':0 if backend=='pyshark' else None,
             'interpretation':'Entropy is descriptive, not proof of encryption. USER0 captures contain socket bytes, not TCP packets.'}
    tails={};first=None;last=None;weighted_entropy=0
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute('DROP TABLE IF EXISTS packets')
        db.execute('CREATE TABLE packets (number INTEGER PRIMARY KEY, timestamp REAL, length INTEGER, connection INTEGER, source TEXT, destination TEXT, payload_size INTEGER, entropy REAL, retransmission INTEGER, payload_hex TEXT)')
        for record in records:
            data=record['payload'];value=entropy(data)
            key=(record['connection'],record['source'],record['destination'])
            # Stream backend preserves observed byte order; TCP reassembly is
            # deliberately not approximated by concatenating arbitrary packets.
            scan=(tails.get(key,b'')+data) if backend=='stream' else data
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
