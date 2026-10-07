"""Run adversarial regression tests; failures produce a nonzero exit status."""
import subprocess
import sys
if __name__ == '__main__':
    raise SystemExit(subprocess.call([sys.executable,'-m','pytest','tests/test_security.py','-v','--junitxml=results/security_tests.xml']))
