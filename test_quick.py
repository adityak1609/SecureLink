"""Run real multimedia roundtrip tests against isolated simulated endpoints."""
import subprocess
import sys
if __name__ == '__main__':
    raise SystemExit(subprocess.call([sys.executable,'-m','pytest','tests/test_security.py','-k','real_media_roundtrip','-v']))
