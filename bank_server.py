import argparse
from securelink.audit import AuditLog, WitnessClient
from securelink.credentials import load, devices
from securelink.server import BankServer

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='SecureLink authenticated multimedia server')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=9999)
    p.add_argument('--credentials', default='secrets/server.json')
    p.add_argument('--signing-keys', help='Pinned Ed25519 public-key registry JSON')
    p.add_argument('--state', default='runtime/bank')
    p.add_argument('--audit-log', default='runtime/audit/events.jsonl')
    p.add_argument('--witness-host', default='127.0.0.1')
    p.add_argument('--witness-port', type=int, default=9998)
    p.add_argument('--ready-file', help='Write bound address for local demo orchestration')
    args = p.parse_args()
    config = load(args.credentials)
    witness = WitnessClient((args.witness_host,args.witness_port),config['audit_identity'],bytes.fromhex(config['audit_secret']))
    audit = AuditLog(args.audit_log, witness)
    server = BankServer(args.state, devices(config), audit, host=args.host, port=args.port,
                        signing_keys=devices(load(args.signing_keys)) if args.signing_keys else None)
    if args.ready_file:
        import json
        from pathlib import Path
        Path(args.ready_file).write_text(json.dumps(server.address),encoding='utf-8')
    print(f'SecureLink listening on {server.address}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
