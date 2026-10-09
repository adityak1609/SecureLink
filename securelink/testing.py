"""Requirement mapping for real, isolated pytest results."""
import xml.etree.ElementTree as ET

REQUIREMENTS=[
    {'goal':'Confidentiality & integrity','expected':'Fresh directional keys; altered ciphertext/header rejected',
     'tests':['test_fresh_sessions_and_direction_keys','test_tampering_rejected']},
    {'goal':'Authentication','expected':'Incorrect credentials and expired timestamps rejected',
     'tests':['test_wrong_secret_and_server_identity','test_expired_handshake_timestamp_rejected']},
    {'goal':'Digital signatures','expected':'Valid signatures accepted; wrong key and changed manifest rejected',
     'tests':['test_signed_transfer_metrics_and_persistence','test_signature_context_tampering_rejected','test_server_requires_pinned_signature']},
    {'goal':'Accountability','expected':'Audit edits, truncation and checkpoint rollback detected',
     'tests':['test_audit_attacks_detected','test_witness_rejects_rollback_and_conflict']},
    {'goal':'Availability & replay','expected':'Interrupted transfers resume; duplicate requests remain idempotent',
     'tests':['test_lost_ack_recovery_and_idempotency','test_download_recovers_after_disconnect','test_exact_record_replay_rejected']},
    {'goal':'Four media types & GUI','expected':'Real files transfer and retrieve; browser API access is protected',
     'tests':['test_gui_real_multimedia_roundtrips_audit_exports_and_restart','test_gui_http_boundary_and_no_credential_disclosure']},
    {'goal':'Wireshark / PyShark module','expected':'Real TShark decode, validated XML/SQLite exports, no parser fallback',
     'tests':['test_pcap_conversion_counts_and_cross_record_marker','test_pyshark_only_no_custom_fallback']},
    {'goal':'Efficiency measurements','expected':'Measured crypto calls and transfer latency, no invented timing',
     'tests':['test_signed_transfer_metrics_and_persistence','test_end_to_end_benchmark_produces_measured_results']},
    {'goal':'Transfer evidence & image metrics','expected':'Actual ciphertext samples, UTC logs, matching hashes and measured image fidelity',
     'tests':['test_ciphertext_sample_is_the_actual_transmitted_and_verified_record',
              'test_invalid_ciphertext_is_not_reported_as_a_verified_received_sample',
              'test_image_metrics_measure_exact_pixels_and_detect_changed_pixels',
              'test_gui_real_multimedia_roundtrips_audit_exports_and_restart']},
]


def parse_results(path,returncode):
    cases=[]
    for case in ET.parse(path).getroot().iter('testcase'):
        status='failed' if case.find('failure') is not None or case.find('error') is not None else 'skipped' if case.find('skipped') is not None else 'passed'
        cases.append({'name':case.attrib['name'],'module':case.attrib.get('classname',''),
                      'seconds':float(case.attrib.get('time','0')),'status':status})
    requirements=[]
    for requirement in REQUIREMENTS:
        matches=[case for case in cases if case['name'].split('[')[0] in requirement['tests']]
        present={case['name'].split('[')[0] for case in matches}
        status='failed' if any(case['status']=='failed' for case in matches) else 'incomplete' if present!=set(requirement['tests']) or any(case['status']=='skipped' for case in matches) else 'passed'
        requirements.append({**requirement,'status':status,'executed_cases':len(matches)})
    result={name:sum(case['status']==name for case in cases) for name in ('passed','failed','skipped')}
    return {**result,'total':len(cases),'returncode':returncode,'success':returncode==0 and bool(cases) and result['failed']==0,
            'requirements_complete':all(row['status']=='passed' for row in requirements),
            'requirements':requirements,'cases':cases,'duration_seconds':sum(case['seconds'] for case in cases)}
