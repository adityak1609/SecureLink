"""Focused benchmarks measure the active algorithms and preserve saved evidence."""
import csv
import json

import pytest

from securelink.experiments import run, validate
from securelink.gui import Application
from tests.test_gui import gui, http, job


@pytest.mark.parametrize('category,algorithms,expected',[
    ('aead',['AES-256-GCM'],4),
    ('hash',['SHA-256'],2),
    ('signature',['Ed25519'],4),
])
def test_crypto_benchmarks_use_measured_bytes_and_reject_changes(tmp_path,category,algorithms,expected):
    directory=tmp_path/category
    report=run(directory,{'category':category,'algorithms':algorithms,'sizes':[1024],
                          'iterations':2})
    assert report['observations']==expected
    assert all(row['n']==2 and row['success_rate']==1 for row in report['summary'])
    assert all(row['metrics']['milliseconds']['median']>=0 for row in report['summary'])
    assert all(item['passed']>0 for item in report['checks'])
    if category=='aead':
        assert {item['name'] for item in report['checks']}=={
            'round trip bytes match','changed ciphertext rejected','changed header rejected'}
    if category=='signature':
        assert {row['operation'] for row in report['summary']}=={'sign','verify'}
    with (directory/'observations.csv').open(newline='',encoding='utf-8') as stream:
        observations=list(csv.DictReader(stream))
    assert len(observations)==expected
    assert {row['algorithm'] for row in observations}==set(algorithms)
    assert not {'cpu_ms','peak_rss_mib','protocol_bytes','protocol_overhead_percent'} & set(observations[0])
    for row in observations:
        if category == 'aead':
            assert float(row['throughput_mib_s']) == pytest.approx(
                1024 / 1048576 / (float(row['milliseconds']) / 1000))
        else:
            assert row['throughput_mib_s'] == ''
    assert (directory/'comparison.png').stat().st_size>1000


@pytest.mark.parametrize('category,algorithm', [
    ('transfer','Plaintext lab'), ('transfer','AES-256-GCM'),
    ('transfer','AES-256-GCM + Ed25519'), ('aead','AES-128-GCM'),
    ('aead','ChaCha20-Poly1305'), ('hash','SHA-512'), ('hash','SHA3-256'),
    ('signature','ECDSA-P256-SHA256'), ('signature','RSA-PSS-3072-SHA256'),
])
def test_removed_comparisons_cannot_start_a_benchmark(tmp_path, category, algorithm):
    directory = tmp_path/'removed'
    with pytest.raises(ValueError):
        run(directory, {'category':category, 'algorithms':[algorithm],
                        'sizes':[1024], 'iterations':2})
    assert not directory.exists()


def test_experiment_api_access_exports_and_invalid_inputs(gui):
    config={'category':'hash','algorithms':['SHA-256'],
            'sizes':[1024],'iterations':2}
    assert http(gui,'POST','/api/benchmarks/run',config,authenticated=False)[0]==401
    assert http(gui,'POST','/api/benchmarks/run',{**config,'algorithms':['unknown']})[0]==400
    assert http(gui,'POST','/api/benchmarks/run',{**config,'algorithms':[{}]})[0]==400
    assert http(gui,'POST','/api/benchmarks/run',{**config,'category':'transfer'})[0]==400
    assert http(gui,'POST','/api/benchmarks/run',{**config,'algorithms':['SHA-512']})[0]==400
    result=job(gui,'/api/benchmarks/run',config)
    assert result['status']=='complete',result
    run_id=result['result']['run_id']
    assert gui[0].state()['benchmarks'][0]['id']==run_id
    status,data=http(gui,'GET',f'/api/benchmarks/{run_id}')
    assert status==200 and json.loads(data)['observations']==2
    status,data=http(gui,'GET',f'/api/benchmarks/{run_id}/observations')
    assert status==200 and len(json.loads(data))==2
    for format in ('json','csv','png'):
        assert http(gui,'GET',f'/api/benchmarks/{run_id}/export/{format}')[0]==200
        assert http(gui,'GET',f'/api/benchmarks/{run_id}/export/{format}',authenticated=False)[0]==401
    assert http(gui,'GET','/api/benchmarks/../../credentials/client.json')[0] in (400,404)


def test_experiment_input_limits():
    with pytest.raises(ValueError):
        validate({'category':'hash','algorithms':['SHA-256'],
                  'sizes':[1024],'iterations':51})
    with pytest.raises(ValueError):
        validate({'category':'aead','algorithms':['AES-256-GCM'],
                  'sizes':[],'dataset':'samples','iterations':2})
    with pytest.raises(ValueError):
        validate({'category':'aead','algorithms':['AES-256-GCM'],
                  'sizes':[True],'iterations':2})
    with pytest.raises(ValueError):
        validate({'category':'hash','algorithms':['SHA-256'],
                  'sizes':[{}],'iterations':2})


def test_saved_benchmarks_survive_restart_and_old_reports_remain_on_disk(tmp_path):
    state=tmp_path/'gui'
    first=Application(state)
    assert first.benchmark_runs() == []
    report=run(state/'benchmarks'/'1234567890abcdef',
               {'category':'hash','algorithms':['SHA-256'],'sizes':[1024],'iterations':2})
    legacy = state/'benchmarks'/'abcdef1234567890'
    legacy.mkdir()
    legacy_report = {**report, 'schema_version':1, 'origin':'Archived project benchmark',
                     'config':{'category':'transfer','algorithms':['Plaintext lab'],
                               'sizes':[1024],'dataset':'sizes','iterations':2}}
    legacy_bytes = json.dumps(legacy_report).encode('utf-8')
    (legacy/'report.json').write_bytes(legacy_bytes)
    first.close()
    second=Application(state)
    try:
        ids={item['id'] for item in second.benchmark_runs()}
        assert ids == {'1234567890abcdef'}
        assert (legacy/'report.json').read_bytes() == legacy_bytes
        assert report['summary'][0]['n']==2
    finally:
        second.close()
