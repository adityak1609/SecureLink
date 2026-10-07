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
            page.wait_for_function('initialized')
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

            operation('#start-demo')
            assert len(set(page.evaluate('Object.values(state.topology)'))) == 3
            for name in ('transaction.txt', 'identity.png', 'audio.wav', 'video.mp4'):
                sent = operation(f'[data-sample="{name}"]')
                request = sent['result']['request']
                operation(f'[data-receive="{request}"]')
                page.locator(f'[data-preview="{request}"]').click()
                page.wait_for_selector('#preview-dialog[open]')
                if name.endswith('.txt'):
                    assert 'amount_paise' in page.locator('#preview-content pre').inner_text()
                elif name.endswith('.png'):
                    page.wait_for_function('document.querySelector("#preview-content img")?.naturalWidth > 0')
                else:
                    kind = 'audio' if name.endswith('.wav') else 'video'
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
            page.wait_for_function('document.querySelector("#selected-preview img")?.naturalWidth > 0')
            operation('#send-button')
            assert page.locator('#metric-files').inner_text() == '6'

            page.locator('.nav-item[data-view="security"]').click()
            operation('#verify-audit')
            assert 'checkpoint match' in page.locator('#audit-summary').inner_text()
            page.screenshot(path=str(output / 'security.png'), full_page=True)
            page.locator('.nav-item[data-view="traffic"]').click()
            operation('#analyze')
            assert page.locator('[data-export="sqlite"]').is_enabled()
            with page.expect_download() as download_info:
                page.locator('[data-export="xml"]').click()
            download_info.value.save_as(str(output / 'packets.xml'))
            page.screenshot(path=str(output / 'traffic.png'), full_page=True)
            page.locator('.nav-item[data-view="guide"]').click()
            assert page.locator('.guide-steps li').count() == 5
            with page.expect_download() as download_info:
                page.locator('[data-report="PROTOCOL.md"]').click()
            assert download_info.value.suggested_filename == 'PROTOCOL.md'
            page.locator('.nav-item[data-view="workspace"]').click()
            page.reload()
            page.wait_for_function('initialized && state.connected')
            assert page.locator('#metric-files').inner_text() == '6'
            page.screenshot(path=str(output / 'workspace.png'), full_page=True)
            page.set_viewport_size({'width': 390, 'height': 844})
            page.screenshot(path=str(output / 'mobile.png'), full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile page overflows'
            operation('#disconnect')
            assert page.locator('#send-button').is_disabled()
            assert not app.processes
            assert not errors, errors
            browser.close()
        summary = {'passed': True, 'completed_uploads': 6, 'verified_downloads': 5,
                   'media_previews': ['text', 'image', 'audio', 'video'], 'browser_errors': errors,
                   'responsive_width': 390, 'audit_verified': True, 'pcap_exports': True}
        (output / 'summary.json').write_text(json.dumps(summary, indent=2))
        print(json.dumps({'output': str(output), **summary}, indent=2))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        app.close()


if __name__ == '__main__':
    run()
