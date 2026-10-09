import argparse
import json
from securelink.analysis import analyze
if __name__ == '__main__':
    p=argparse.ArgumentParser(description='Convert PCAP to SQLite and XML, validate counts and summarize')
    p.add_argument('capture')
    p.add_argument('--backend',choices=['pyshark'],default='pyshark')
    p.add_argument('--output',default='results/pcap_analysis')
    p.add_argument('--marker',default='"amount_paise"')
    args=p.parse_args()
    print(json.dumps(analyze(args.capture,args.output,args.backend,args.marker.encode()),indent=2))
