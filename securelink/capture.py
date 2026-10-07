"""Transparent loopback proxy recording real socket bytes as LINKTYPE_USER0.

These are application stream observations, NOT Ethernet/IP/TCP packets. The
5-byte observer prefix is direction + connection number, not protocol data.
No synthetic network headers or invented retransmission measurements are used.
"""
import socket
import struct
import threading
import time
from pathlib import Path
from .service import TCPService

class StreamCapture(TCPService):
    def __init__(self, target, output, **kwargs):
        super().__init__(**kwargs)
        self.target=target
        Path(output).parent.mkdir(parents=True,exist_ok=True)
        self.output=open(output,'wb')
        self.output.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,131072,147))
        self.write_lock=threading.Lock()
        self.next_connection=0

    def record(self,data,direction,connection):
        timestamp=time.time()
        prefix=struct.pack('!BI',direction,connection)
        body=prefix+data
        with self.write_lock:
            self.output.write(struct.pack('<IIII',int(timestamp),int(timestamp%1*1000000),len(body),len(body))+body)
            self.output.flush()

    def handle(self,conn,addr):
        with socket.create_connection(self.target,timeout=3) as upstream:
            conn.settimeout(15);upstream.settimeout(15)
            with self.write_lock:
                self.next_connection+=1
                connection=self.next_connection
            def pump(source,destination,direction):
                try:
                    while True:
                        data=source.recv(65536)
                        if not data:break
                        self.record(data,direction,connection)
                        destination.sendall(data)
                except OSError:
                    pass
                finally:
                    try:destination.shutdown(socket.SHUT_WR)
                    except OSError:pass
            reverse=threading.Thread(target=pump,args=(upstream,conn,1),daemon=True)
            reverse.start()
            pump(conn,upstream,0)
            reverse.join(timeout=16)

    def stop(self):
        super().stop()
        self.output.close()


def stream_records(path):
    with open(path,'rb') as source:
        header=source.read(24)
        if len(header)!=24 or struct.unpack('<IHHIIII',header)[-1]!=147 or header[:4]!=b'\xd4\xc3\xb2\xa1':
            raise ValueError('Not a SecureLink USER0 stream capture; use --backend pyshark for network PCAP')
        index=0
        while True:
            header=source.read(16)
            if not header:break
            if len(header)!=16:raise ValueError('Truncated PCAP record')
            sec,usec,length,original=struct.unpack('<IIII',header)
            if not 5<=length<=131072 or original!=length:raise ValueError('Invalid stream capture record size')
            body=source.read(length)
            if len(body)!=length:raise ValueError('Truncated capture data')
            direction,connection=struct.unpack('!BI',body[:5])
            if direction not in (0,1):raise ValueError('Invalid stream direction')
            index+=1
            yield {'number':index,'timestamp':sec+usec/1e6,'length':length,
                   'connection':connection,'direction':direction,'payload':body[5:],
                   'source':'client' if direction==0 else 'server',
                   'destination':'server' if direction==0 else 'client',
                   'retransmission':None,'kind':'application_stream'}
