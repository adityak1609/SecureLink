import argparse
from securelink.client import Client
from securelink.credentials import load

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Upload/download authenticated multimedia files')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=9999)
    p.add_argument('--credentials', default='secrets/client.json')
    sub = p.add_subparsers(dest='command', required=True)
    upload = sub.add_parser('upload')
    upload.add_argument('file')
    upload.add_argument('--request-id', help='Reuse this ID to resume safely')
    download = sub.add_parser('download')
    download.add_argument('request_id')
    download.add_argument('destination')
    args = p.parse_args()
    config = load(args.credentials)
    with Client((args.host,args.port),config['device'],bytes.fromhex(config['secret']),config['server']) as client:
        if args.command == 'upload':
            import uuid
            request = args.request_id or uuid.uuid4().hex
            print(f'Request ID: {request} (retain to resume)', flush=True)
            result = client.upload(args.file, request)
            print(f'Completed {result["metadata"]["size"]} bytes; SHA-256 {result["metadata"]["sha256"]}')
        else:
            print(f'Verified download: {client.download(args.request_id,args.destination)}')
        print(f'Reconnections: {client.retries}')
