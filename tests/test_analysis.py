import sqlite3
import struct
import xml.etree.ElementTree as ET
import pytest
from securelink.analysis import analyze
from securelink.capture import stream_records

def test_pcap_conversion_counts_and_cross_record_marker(tmp_path):
    path=tmp_path/'sample.pcap'
    with path.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,131072,147))
        for i,payload in enumerate([b'abcSEC',b'RETxyz']):
            body=struct.pack('!BI',0,1)+payload
            stream.write(struct.pack('<IIII',100,i,len(body),len(body))+body)
    result=analyze(path,tmp_path/'out',marker=b'SECRET')
    assert result['records']==2 and result['marker_found']
    assert result['retransmissions'] is None
    assert result['backend']=='pyshark' and result['engine']=='PyShark + Wireshark/TShark'
    assert len(result['timeline'])==12
    assert sum(bin['records'] for bin in result['timeline'])==result['records']
    assert sum(bin['payload_bytes'] for bin in result['timeline'])==result['payload_bytes']
    assert result['direction_summary']==[{'source':'client','destination':'server','records':2,
                                           'payload_bytes':12}]
    with sqlite3.connect(tmp_path/'out/packets.sqlite') as db:
        assert db.execute('SELECT count(*) FROM packets').fetchone()[0]==2
    assert len(ET.parse(tmp_path/'out/packets.xml').getroot())==2


def test_pyshark_only_no_custom_fallback(tmp_path,monkeypatch):
    import securelink.analysis as analysis
    with pytest.raises(ValueError,match='no custom parser fallback'):
        analyze(tmp_path/'unused.pcap',tmp_path/'out',backend='stream')
    monkeypatch.setattr(analysis,'tshark_path',lambda:None)
    with pytest.raises(RuntimeError,match='Wireshark/TShark is required'):
        analyze(tmp_path/'unused.pcap',tmp_path/'out')

def test_truncated_capture_rejected(tmp_path):
    path=tmp_path/'bad.pcap';path.write_bytes(b'\xd4\xc3\xb2\xa1')
    with pytest.raises(ValueError):list(stream_records(path))

def test_pyshark_reads_actual_demo_capture():
    from pathlib import Path
    from securelink.analysis import open_pyshark,tshark_path
    path=Path('results/demo_v3/secure/session_stream.pcap')
    if not tshark_path() or not path.exists():pytest.skip('Requires TShark and generated demo capture')
    expected=sum(1 for _ in stream_records(path))
    with open_pyshark(path) as cap:
        assert sum(1 for _ in cap)==expected

@pytest.mark.parametrize('ipv6',[False,True])
def test_pyshark_network_parser_with_synthetic_unit_fixture(tmp_path,ipv6):
    """Parser fixture only: never presented as captured project traffic."""
    import socket
    from securelink.analysis import tshark_path
    if not tshark_path():pytest.skip('TShark not installed')
    payload=b'parser-test-marker'
    tcp=struct.pack('!HHIIBBHHH',12345,9999,1,1,0x50,0x18,8192,0,0)+payload
    if ipv6:
        ip=struct.pack('!IHBB',6<<28,len(tcp),6,64)+socket.inet_pton(socket.AF_INET6,'2001:db8::1')+socket.inet_pton(socket.AF_INET6,'2001:db8::2')
        ethertype=b'\x86\xdd'
    else:
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,0,64,6,0,
                       socket.inet_aton('192.0.2.1'),socket.inet_aton('192.0.2.2'))
        ethertype=b'\x08\x00'
    packet=b'\0'*12+ethertype+ip+tcp
    path=tmp_path/'parser_fixture.pcap'
    path.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+
                     struct.pack('<IIII',100,0,len(packet),len(packet))+packet)
    result=analyze(path,tmp_path/'out',backend='pyshark',marker=payload)
    assert result['records']==1 and result['payload_bytes']==len(payload)
    assert result['marker_found']
    with sqlite3.connect(tmp_path/'out/packets.sqlite') as db:
        assert db.execute('SELECT source FROM packets').fetchone()[0]==('2001:db8::1' if ipv6 else '192.0.2.1')
