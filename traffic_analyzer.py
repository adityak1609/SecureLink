"""Traffic analysis entry point; see capture_traffic.py for acquisition."""
import runpy
if __name__ == '__main__':
    runpy.run_module('pcap_analyzer',run_name='__main__')
