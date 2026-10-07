import argparse
import subprocess
from securelink.analysis import tshark_path
from securelink.capture import StreamCapture

if __name__=='__main__':
    p=argparse.ArgumentParser(description='Capture only the SecureLink lab traffic')
    p.add_argument('--mode',choices=['stream','network','interfaces'],default='stream')
    p.add_argument('--target-host',default='127.0.0.1')
    p.add_argument('--target-port',type=int,default=9999)
    p.add_argument('--listen-port',type=int,default=10000)
    p.add_argument('--interface')
    p.add_argument('--duration',type=int,default=30)
    p.add_argument('--output',default='captures/session_stream.pcap')
    args=p.parse_args()
    if args.mode=='stream':
        service=StreamCapture((args.target_host,args.target_port),args.output,port=args.listen_port)
        print(f'Application stream observer at {service.address}; point client here. Not a network packet capture.',flush=True)
        try:service.serve_forever()
        except KeyboardInterrupt:pass
        finally:service.stop()
    else:
        executable=tshark_path()
        if not executable:raise SystemExit('Install Wireshark/TShark first')
        command=[executable,'-D'] if args.mode=='interfaces' else [executable,'-i',args.interface or '1',
            '-f',f'tcp port {args.target_port}','-a',f'duration:{args.duration}','-w',args.output]
        subprocess.run(command,check=True)
