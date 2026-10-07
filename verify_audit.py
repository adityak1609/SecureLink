import argparse
from securelink.audit import AuditLog, WitnessClient
from securelink.credentials import load

if __name__ == '__main__':
    p=argparse.ArgumentParser(description='Verify log against independent witness without changing checkpoints')
    p.add_argument('--log',default='runtime/audit/events.jsonl')
    p.add_argument('--credentials',default='secrets/server.json')
    p.add_argument('--witness-host',default='127.0.0.1')
    p.add_argument('--witness-port',type=int,default=9998)
    args=p.parse_args();config=load(args.credentials)
    # Verification only: do not construct AuditLog (which recovers pending anchors).
    audit=AuditLog.__new__(AuditLog)
    from pathlib import Path
    audit.path=Path(args.log)
    audit.witness=WitnessClient((args.witness_host,args.witness_port),config['audit_identity'],bytes.fromhex(config['audit_secret']))
    count,head=audit.verify()
    print(f'Verified {count} records; chain head {head}; witness {audit.witness.get()}')
