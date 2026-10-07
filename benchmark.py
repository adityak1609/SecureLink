import argparse
import json
from securelink.benchmarks import run
if __name__ == '__main__':
    p=argparse.ArgumentParser(description='Benchmark actual acknowledged transfers')
    p.add_argument('--iterations',type=int,default=30)
    p.add_argument('--output',default='results/benchmark')
    args=p.parse_args()
    print(json.dumps(run(args.output,args.iterations),indent=2))
