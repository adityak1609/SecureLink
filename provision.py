import argparse
from securelink.credentials import provision

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate distinct random device and audit credentials')
    parser.add_argument('--directory', default='secrets')
    args = parser.parse_args()
    for path in provision(args.directory):
        print(f'Created {path} (keep private; do not commit)')
