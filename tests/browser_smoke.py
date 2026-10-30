"""Real-browser acceptance check; run separately from the backend pytest suite.

Requires requirements-dev.txt and an installed Chrome browser. Uses isolated
temporary state, actual encrypted services, and synthetic demonstration media.
"""
from pathlib import Path
import json
import sys
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from securelink.gui import Application, LocalServer
from playwright.sync_api import sync_playwright


def run():
    output = ROOT / 'runtime' / 'browser_qa' / uuid.uuid4().hex
    output.mkdir(parents=True)
    app = Application(output / 'state')
    server = LocalServer(app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel='chrome', headless=True)
            page = browser.new_page(viewport={'width': 1440, 'height': 1100}, accept_downloads=True)
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(server.origin + '/#token=' + app.token)
            page.wait_for_function('() => initialized')
            formatted=page.evaluate('''() => {
                const root=document.createElement('div');
                root.innerHTML=timestampMarkup('2026-10-09T23:59:59.123456+00:00');
                const time=root.querySelector('time');
                return {date:root.querySelector('.timestamp-date').textContent,
                    clock:root.querySelector('.timestamp-clock').textContent,
                    original:time.getAttribute('datetime'),title:time.title};
            }''')
            assert formatted['date']=='10 Oct 2026'
            assert formatted['clock']=='05:29:59.123 IST'
            assert formatted['original']=='2026-10-09T23:59:59.123456+00:00'
            assert formatted['original'] in formatted['title']
            assert 'Not recorded' in page.evaluate('timestampMarkup(null)')
            assert 'Unavailable' in page.evaluate('timestampMarkup("not-a-time")')
            assert page.title() == 'SecureLink — Secure workspace'
            assert '#token=' not in page.url
            assert page.locator('#send-button').is_disabled()
            page.screenshot(path=str(output / 'workspace_offline.png'), full_page=True)

            def operation(selector):
                count = page.evaluate('state.jobs.length')
                page.locator(selector).click()
                page.wait_for_function('(count) => state.jobs.length > count && !busy()', arg=count, timeout=45000)
                result = page.evaluate('state.jobs.at(-1)')
                assert result['status'] == 'complete', result.get('error')
                return result

            page.locator('.nav-item[data-view="cryptolab"]').click()
            lab_text=('Confidential text — नमस्ते. '*180)+'<script>plain text only</script>'
            page.locator('#lab-text').fill(lab_text)
            encrypted=operation('#lab-encrypt-text')
            lab_id=encrypted['result']['run_id']
            page.wait_for_function('(id) => labUI.report?.id===id && document.querySelector("#lab-original pre")',arg=lab_id)
            assert page.locator('#lab-original pre').inner_text()==lab_text
            assert page.locator('#lab-cipher-next').is_enabled()
            page.locator('#lab-cipher-next').click()
            page.wait_for_function('() => labUI.offset===4096')
            assert '00001000' in page.locator('#lab-ciphertext').inner_text()
            assert page.locator('.lab-sensitivity-chart').count()==2
            for label in ('Confusion','Diffusion','avalanche','Pre-image resistance','Second pre-image resistance','Collision resistance','No match in the bounded candidate set'):
                assert label in page.locator('#lab-results').inner_text(),label
            operation('#lab-decrypt')
            page.wait_for_function('() => labUI.report?.decrypted && document.querySelector("#lab-recovered pre")')
            assert page.locator('#lab-recovered pre').inner_text()==lab_text
            assert page.evaluate('labUI.report.signature_verified')
            assert page.evaluate('labUI.report.decryption_metrics.decryption.throughput_mib_s')>0
            for selector,filename in (('#lab-save-ciphertext','lab_ciphertext.bin'),('#lab-export','lab_report.json'),('#lab-signature','lab_signature.json'),('#lab-save-recovered','lab_recovered.txt')):
                with page.expect_download() as download_info:
                    page.locator(selector).click()
                download_info.value.save_as(str(output/filename))
            assert (output/'lab_recovered.txt').read_bytes()==lab_text.encode('utf-8')
            assert len((output/'lab_ciphertext.bin').read_bytes())==len(lab_text.encode('utf-8'))+16
            saved_lab=json.loads((output/'lab_report.json').read_text())
            assert saved_lab['metadata']['sha256']==saved_lab['received_sha256']
            page.screenshot(path=str(output/'crypto_lab_text.png'),full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),'Crypto lab overflows on mobile'
            page.screenshot(path=str(output/'crypto_lab_mobile.png'),full_page=True)
            page.set_viewport_size({'width':1440,'height':1100})
            count=page.evaluate('state.jobs.length')
            page.locator('#lab-file').set_input_files(str(ROOT/'sample_data/fixtures/identity.png'))
            page.wait_for_function('(count) => state.jobs.length>count && !busy()',arg=count,timeout=45000)
            assert page.evaluate('state.jobs.at(-1).status')=='complete'
            page.wait_for_function('() => labUI.report?.metadata.media==="image" && document.querySelector("#lab-original img")?.naturalWidth>0')
            operation('#lab-decrypt')
            page.wait_for_function('() => labUI.report?.decrypted && document.querySelector("#lab-recovered img")?.naturalWidth>0')
            assert page.evaluate('labUI.report.image_metrics.pixels_equal')
            page.screenshot(path=str(output/'crypto_lab_image.png'),full_page=True)
            page.locator('.nav-item[data-view="workspace"]').click()
            operation('#start-demo')
            assert len(set(page.evaluate('Object.values(state.topology)'))) == 3
            for name in ('transaction.txt', 'identity.png', 'audio.wav'):
                sent = operation(f'[data-sample="{name}"]')
                request = sent['result']['request']
                operation(f'[data-receive="{request}"]')
                page.locator(f'[data-preview="{request}"]').click()
                page.wait_for_selector('#preview-dialog[open]')
                if name.endswith('.txt'):
                    assert 'amount_paise' in page.locator('#preview-content pre').inner_text()
                elif name.endswith('.png'):
                    page.wait_for_function('() => document.querySelector("#preview-content img")?.naturalWidth > 0')
                else:
                    kind = 'audio'
                    page.wait_for_function('(kind) => document.querySelector("#preview-content " + kind)?.readyState >= 1', arg=kind)
                    assert page.locator(f'#preview-content {kind}').evaluate('(media) => media.duration') > 0
                page.locator('[data-close="preview-dialog"]').click()
                with page.expect_download() as download_info:
                    page.locator(f'[data-save="{request}"]').click()
                download = download_info.value
                download.save_as(str(output / name))
                assert (output / name).read_bytes() == (ROOT / 'sample_data/fixtures' / name).read_bytes()

            page.locator('[data-composer="text"]').click()
            page.locator('#message').fill('A real GUI message — नमस्ते. <script>not executable</script>')
            sent = operation('#send-button')
            request = sent['result']['request']
            operation(f'[data-receive="{request}"]')
            page.locator(f'[data-preview="{request}"]').click()
            page.wait_for_selector('#preview-dialog[open]')
            assert '<script>not executable</script>' in page.locator('#preview-content pre').inner_text()
            page.locator('[data-close="preview-dialog"]').click()
            page.locator('[data-composer="files"]').click()
            page.locator('#file-input').set_input_files(str(ROOT / 'sample_data/fixtures' / 'identity.jpg'))
            page.wait_for_function('() => document.querySelector("#selected-preview img")?.naturalWidth > 0')
            operation('#send-button')
            assert page.locator('#metric-files').inner_text() == '5'

            page.locator('.nav-item[data-view="performance"]').click()
            page.locator('#metrics-file').select_option(page.evaluate('state.transfers[0].request'))
            assert 'Ed25519 signed file manifest' in page.locator('#metrics-content').inner_text()
            assert 'AES-256-GCM encryption' in page.locator('#metrics-content').inner_text()
            assert 'Ed25519 signing' in page.locator('#metrics-content').inner_text()
            assert page.locator('#metrics-content .crypto-table').count()==1  # Selected JPEG has not yet been received.
            assert page.locator('#metrics-content .crypto-chart').count()==2
            assert page.locator('#metrics-content .crypto-chart-row').count()==9
            assert 'MiB/s' in page.locator('#metrics-content').inner_text()
            with page.expect_download() as download_info:
                page.locator('[data-metrics-export="csv"]').click()
            download_info.value.save_as(str(output/'crypto_metrics.csv'))
            assert 'signature_verification' in (output/'crypto_metrics.csv').read_text()
            page.screenshot(path=str(output/'performance.png'),full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Crypto chart overflows on mobile'
            page.set_viewport_size({'width':1440,'height':1100})

            page.locator('.nav-item[data-view="benchmarks"]').click()
            assert page.locator('#benchmark-category option').evaluate_all('(options) => options.map(option => option.value)') == ['aead','hash','signature']
            assert page.locator('#benchmark-algorithms, #benchmark-dataset, #benchmark-compare').count()==0
            assert 'Run a benchmark' in page.locator('#benchmark-result').inner_text()
            page.locator('#benchmark-category').select_option('hash')
            page.locator('#benchmark-iterations').select_option('2')
            page.locator('[name="benchmark-size"][value="65536"]').uncheck()
            page.locator('[name="benchmark-size"][value="1048576"]').uncheck()
            operation('#benchmark-run')
            page.wait_for_function('() => document.querySelector("#benchmark-result h2")?.textContent.includes("SHA-256")')
            hash_run=page.locator('#benchmark-history').input_value()
            assert page.locator('#benchmark-result svg').count()==1
            assert page.locator('#benchmark-result .benchmark-dot').count()==2
            assert 'changed input differs' in page.locator('#benchmark-result').inner_text()
            with page.expect_download() as download_info:
                page.locator('[data-benchmark-export="csv"]').click()
            download_info.value.save_as(str(output/'benchmark_observations.csv'))
            assert len((output/'benchmark_observations.csv').read_text().splitlines())==3
            page.locator('#benchmark-category').select_option('aead')
            assert page.locator('#benchmark-metric option').all_text_contents()==['Time (ms)']
            page.locator('[name="benchmark-size"][value="65536"]').check()
            operation('#benchmark-run')
            page.wait_for_function('() => document.querySelector("#benchmark-result h2")?.textContent.includes("AES-256-GCM")')
            assert set(page.locator('#benchmark-operation option').all_text_contents())=={'encrypt','decrypt'}
            page.locator('#benchmark-metric').select_option('throughput_mib_s')
            page.locator('#benchmark-operation').select_option('decrypt')
            assert 'MiB/s' in page.locator('#benchmark-result').inner_text()
            assert page.locator('#benchmark-result svg circle').count()==2
            page.screenshot(path=str(output/'benchmark_aes_speed.png'),full_page=True)
            page.locator('#benchmark-category').select_option('signature')
            operation('#benchmark-run')
            page.wait_for_function('() => document.querySelector("#benchmark-result h2")?.textContent.includes("Ed25519")')
            assert set(page.locator('#benchmark-operation option').all_text_contents())=={'sign','verify'}
            assert page.locator('#benchmark-metric option').all_text_contents()==['Time (ms)']
            assert page.locator('#benchmark-history option').count()==3
            for label in ('PROTOCOL BYTES','CLIENT HASH','CLIENT SIGN','SERVER VERIFY','key generation'):
                assert label not in page.locator('#benchmark-result').inner_text()
            page.locator('#benchmark-operation').select_option('verify')
            page.screenshot(path=str(output/'benchmark_signatures.png'),full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Benchmark page overflows on mobile'
            page.screenshot(path=str(output/'benchmark_mobile.png'),full_page=True)
            page.set_viewport_size({'width':1440,'height':1100})
            page.locator('#benchmark-history').select_option(hash_run)
            page.wait_for_function('() => document.querySelector("#benchmark-result h2")?.textContent.includes("SHA-256")')

            page.locator('.nav-item[data-view="evidence"]').click()
            image_request=page.evaluate('state.transfers.find(row => row.name === "identity.png").request')
            page.locator('#evidence-file').select_option(image_request)
            page.wait_for_function('(request) => evidenceRecord?.transfer.request === request',arg=image_request)
            evidence_text=page.locator('#evidence-content').inner_text()
            for label in ('Timestamps · IST','Original and received SHA-256 values match.',
                          'Actual ciphertext prefix','AES-GCM tag','Nonce (12 bytes)',
                          'Mean squared error','Infinity (identical pixels)',
                          'transfer_complete','download_verified','signature_verified'):
                assert label in evidence_text,label
            assert page.evaluate('evidenceRecord.transfer.image_metrics.mse')==0
            assert page.locator('#evidence-content .timestamp').count()>=10
            assert all('+00:00' in value for value in page.locator('#evidence-content time').evaluate_all('(elements) => elements.map(element => element.dateTime)'))
            assert all('IST' in text for text in page.locator('#evidence-content .timestamp-clock').all_text_contents())
            with page.expect_download() as download_info:
                page.locator('#export-evidence').click()
            download_info.value.save_as(str(output/'transfer_evidence.json'))
            saved_evidence=json.loads((output/'transfer_evidence.json').read_text())
            assert saved_evidence['transfer']['received_sha256']==saved_evidence['transfer']['sha256']
            assert saved_evidence['transfer']['created'].endswith('+00:00')
            with page.expect_download() as download_info:
                page.locator('#export-audit').click()
            download_info.value.save_as(str(output/'server_audit.jsonl'))
            assert 'signature_verified' in (output/'server_audit.jsonl').read_text()
            page.screenshot(path=str(output/'evidence.png'),full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),'Evidence page overflows on mobile'
            page.screenshot(path=str(output/'evidence_mobile.png'),full_page=True)
            page.set_viewport_size({'width':1440,'height':1100})

            page.locator('.nav-item[data-view="security"]').click()
            operation('#verify-audit')
            assert 'checkpoint match' in page.locator('#audit-summary').inner_text()
            assert page.locator('#audit-summary time').count()==1
            assert page.locator('#audit-rows time').count()>0
            page.screenshot(path=str(output / 'security.png'), full_page=True)
            page.locator('.nav-item[data-view="traffic"]').click()
            operation('#analyze')
            assert page.evaluate('state.analysis.backend')=='pyshark'
            assert 'PyShark + Wireshark/TShark' in page.locator('#analysis-content').inner_text()
            assert page.locator('.timeline-column').count()==12
            assert page.locator('.flow-row').count()==2
            page.locator('#analysis-content details summary').click()
            page.wait_for_timeout(1200)  # Polling must not collapse the expanded data table.
            assert page.locator('#analysis-content details').evaluate('(element) => element.open')
            assert page.locator('#analysis-content details tbody tr').count()==12
            assert page.locator('[data-export="sqlite"]').is_enabled()
            with page.expect_download() as download_info:
                page.locator('[data-export="xml"]').click()
            download_info.value.save_as(str(output / 'packets.xml'))
            page.screenshot(path=str(output / 'traffic.png'), full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Traffic charts overflow on mobile'
            page.set_viewport_size({'width':1440,'height':1100})
            page.locator('.nav-item[data-view="testing"]').click()
            count=page.evaluate('state.jobs.length')
            page.locator('#run-tests').click()
            page.wait_for_function('(count) => state.jobs.length > count && !busy()',arg=count,timeout=300000)
            report=page.evaluate('state.tests')
            assert report['success'] and report['requirements_complete'],report
            assert report['skipped']==0 and report['failed']==0
            assert page.locator('#test-summary time').count()==1
            with page.expect_download() as download_info:
                page.locator('[data-test-export="json"]').click()
            download_info.value.save_as(str(output/'test_results.json'))
            page.screenshot(path=str(output/'testing.png'),full_page=True)
            page.locator('.nav-item[data-view="guide"]').click()
            assert page.locator('.guide-steps li').count() == 5
            with page.expect_download() as download_info:
                page.locator('[data-report="PROTOCOL.md"]').click()
            assert download_info.value.suggested_filename == 'PROTOCOL.md'
            page.locator('.nav-item[data-view="workspace"]').click()
            page.reload()
            page.wait_for_function('() => initialized && state.connected')
            assert page.locator('#metric-files').inner_text() == '5'
            assert len(page.evaluate('state.crypto_lab'))==2
            assert page.locator('#transfer-rows time').count()==5
            page.screenshot(path=str(output / 'workspace.png'), full_page=True)
            page.set_viewport_size({'width': 390, 'height': 844})
            page.screenshot(path=str(output / 'mobile.png'), full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile page overflows'
            operation('#disconnect')
            assert page.locator('#send-button').is_disabled()
            assert not app.processes
            assert not errors, errors
            browser.close()
        summary = {'passed': True, 'completed_uploads': 5, 'verified_downloads': 4,
                   'media_previews': ['text', 'image', 'audio'], 'browser_errors': errors,
                   'responsive_width': 390, 'audit_verified': True, 'pcap_exports': True,
                   'analysis_engine':'PyShark + Wireshark/TShark','digital_signature':'Ed25519',
                   'crypto_timings_displayed':True,'gui_test_suite':{'passed':report['passed'],'failed':report['failed'],'skipped':report['skipped'],
                   'requirements_complete':report['requirements_complete']},
                   'transfer_evidence_displayed':True,'actual_ciphertext_displayed':True,
                   'utc_logs_exported':True,'image_mse':saved_evidence['transfer']['image_metrics']['mse'],
                   'source_received_hashes_match':True,'crypto_lab_text_image_roundtrips':True,
                   'complete_ciphertext_exported':True,'text_sensitivity_graphs':True,'hash_resistance_criteria':3}
        (output / 'summary.json').write_text(json.dumps(summary, indent=2))
        print(json.dumps({'output': str(output), **summary}, indent=2))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        app.close()


if __name__ == '__main__':
    run()
