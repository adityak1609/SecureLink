import argparse
from securelink.audit import Witness
from securelink.credentials import load, devices

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Independent audit checkpoint service')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9998)
    parser.add_argument('--credentials', default='secrets/witness.json')
    parser.add_argument('--database', default='runtime/witness/checkpoints.sqlite')
    parser.add_argument('--ready-file')
    args = parser.parse_args()
    service = Witness(args.database, devices(load(args.credentials)), host=args.host, port=args.port)
    if args.ready_file:
        import json
        from pathlib import Path
        Path(args.ready_file).write_text(json.dumps(service.address),encoding='utf-8')
    print(f'Audit witness listening on {service.address}', flush=True)
    try:
        service.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()
