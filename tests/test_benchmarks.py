import csv
from securelink.benchmarks import run

def test_end_to_end_benchmark_produces_measured_results(tmp_path):
    report=run(tmp_path/'benchmark',iterations=2)
    assert len(report['summary'])==6
    assert all(row['success_rate']==1 for row in report['summary'])
    assert all(row['median_latency_ms']>0 for row in report['summary'])
    with (tmp_path/'benchmark/measurements.csv').open() as stream:
        rows=list(csv.DictReader(stream))
    assert len(rows)==12
    assert all(int(row['client_protocol_bytes'])>int(row['bytes']) for row in rows)
    assert (tmp_path/'benchmark/comparison.png').stat().st_size>0
