from securelink.testing import parse_results


def test_missing_or_skipped_requirement_is_not_reported_as_passed(tmp_path):
    report=tmp_path/'results.xml'
    report.write_text('<testsuites><testsuite><testcase name="test_fresh_sessions_and_direction_keys" time="0.1"/><testcase name="test_tampering_rejected[header]" time="0.2"><skipped/></testcase></testsuite></testsuites>')
    result=parse_results(report,0)
    assert result['passed']==1 and result['skipped']==1
    assert result['requirements'][0]['status']=='incomplete'
    assert not result['requirements_complete']


def test_collection_failure_or_empty_run_is_not_success(tmp_path):
    report=tmp_path/'results.xml'
    report.write_text('<testsuites/>')
    assert not parse_results(report,0)['success']
    report.write_text('<testsuites><testsuite><testcase name="test_fake"><error/></testcase></testsuite></testsuites>')
    result=parse_results(report,2)
    assert result['failed']==1 and not result['success']
