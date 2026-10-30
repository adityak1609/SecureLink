# SecureLink testing requirements

This plan maps the supplied ISL requirements to implemented tests. It is a project test plan, not a claim that an additional teacher-specific checklist has been supplied.

| Requirement | Test action | Expected result |
|---|---|---|
| Confidentiality | Compare known content in secured/plaintext captures; inspect fresh directional session keys | Secured transfer does not expose the marker; keys differ by session/direction. Marker absence alone is not proof of encryption |
| Integrity | Change encrypted payload/header, chunk offsets or final file digest | Reject the altered frame or transfer; do not publish an unverified file |
| Authentication | Wrong PSK/server identity, unknown device, expired timestamp | Handshake rejected |
| Digital signatures | Correct Ed25519 signature, wrong public key, corrupt signature, changed file hash/name/device/request | Accept valid pinned-key signatures; reject all changed contexts and missing required signatures |
| Accountability | Edit/rewrite/truncate logs or roll back witness checkpoint | Verification fails against the independently stored checkpoint |
| Availability | Disconnect upload/download, lose acknowledgement, stall a peer or exceed a connection limit | Bounded failures; legitimate service recovers; saved offsets support resume |
| Replay / duplicate prevention | Repeat encrypted frame or committed transaction request | Frame rejected; same owner/request creates only one transaction |
| Multimedia / GUI | Upload and receive text, PNG/JPEG and WAV/MP3; preview/play in browser; reject MP4 uploads | Original and received bytes match; supported media decodes; video is rejected |
| ISL traffic / PCAP module | Decode real USER0 captures with PyShark/TShark; export SQLite/XML | Matching observation counts and decoded directions/payloads; no Python decoder fallback |
| Efficiency | Measure actual crypto calls per file/direction and end-to-end transfer tests | Real durations/counts/bytes; explicit measurement scope and exported observations |
| Text/image encryption lab | Encrypt and explicitly decrypt TXT, PNG and JPEG; page through ciphertext; export original, recovered bytes, signature and report | Complete ciphertext matches exported bytes; recovered content matches; signature/GCM/hash verified; private keys never exported |
| Confusion / diffusion / avalanche | Check a published AES-256 block vector, flip each input/key bit, independently count changed output bits and characters | Real trial data and percentages with labeled 50%/100% references; byte/hex definitions and AES-core/GCM distinction |
| Three hash criteria | Search full SHA-256 digests for bounded pre-image, second pre-image and collision candidates; include a known guessable input | Accurate attempt counts and observed matches; no security-proof claim from a finite search |
| Encryption speed | Divide known processed-byte counts by measured crypto duration; exercise failure and zero-duration cases | Correct MiB/s in GUI/exports; undefined speeds remain unavailable |
| Transfer evidence | Compare recorded ciphertext with real transmitted/verified AES-GCM records; inspect UTC activity/audit events and both file hashes | Actual bounded samples, valid tag/nonce/header, per-request logs, matching independently computed hashes; no secret keys exposed |
| Image fidelity | Compare identical and deliberately changed decoded image pixels | Correct dimensions/size, MSE 0 and infinite PSNR for identical pixels; finite PSNR and nonzero MSE after a change; bounded decoding |
| Browser interface access | Missing API token, foreign origin/host, unsafe filename/path | Request rejected and credentials remain private |

## Run through the GUI

Open **Testing & results** and choose **Run tests**. It invokes `pytest tests` in a background process with fresh temporary test services and state. It does not point tests at your active GUI transfer database. Inspect the case list and requirement table, then export JSON and JUnit XML. Skipped or absent test coverage remains incomplete, even when the executed cases pass. Collection/empty-run failures are not marked successful.

The test table reports each case's elapsed time; these are test durations, not cryptographic operation times. Use **Crypto performance** for AES-GCM, SHA-256 and Ed25519 timings. Select each file and inspect upload and receive separately, then export CSV/JSON for tables or charts.

## Run through the CLI

```powershell
.\.venv\Scripts\python -m pytest tests -q -p no:cacheprovider --junitxml=results/security_tests.xml
.\.venv\Scripts\python tests/browser_smoke.py
```

Install requirements.txt and Wireshark/TShark first. The browser acceptance check additionally needs requirements-dev.txt and installed Chrome. It exercises real media playback, saved downloads, metrics/signature display, PyShark analysis, the GUI Run tests operation and a narrow-screen layout. Its state, screenshots and detailed logs stay under ignored runtime storage.

## Academic evaluation procedure

1. Demonstrate three distinct client/server/witness processes, or reproduce the documented physical two-device lab setup.
2. Send and receive text, image and audio files. Save received copies and show their hashes and Ed25519 verification results.
3. Show encryption/decryption, file hashing, signing and verification times with the endpoint, direction, units, file size and operation count. Do not confuse full transfer latency with crypto-only timing.
4. Run the isolated security suite and explain expected versus observed outcomes for tampering, replay, invalid signatures and interruption recovery.
5. Decode the captured evidence using PyShark/TShark and open it in Wireshark. Explain USER0 socket observations versus IP/TCP packets. Live network capture needs the appropriate driver; no IP/TCP headers are invented.
6. For a new performance study, collect repeated observations for each media/size on the same hardware, report medians/p95 and state timer/I/O/retry limits. Earlier benchmark_v3 results are for unsigned transfers and should not be relabelled as measurements of the new signing extension.

Remaining environment-dependent validation: physical-device replication and live Windows IP/TCP capture with Npcap. These are not silently marked complete by the local simulation.

The browser acceptance run also exercises the crypto lab while offline, Unicode text and image recovery, complete ciphertext pagination/download, signature/report downloads, text security graphs, all three hash criteria and the 390-pixel layout. Backend tests additionally corrupt ciphertext, signatures and signed metadata and check that failed verification blocks recovered-file access. Requirement coverage is calculated from tests that actually ran; no GUI completion percentage is fabricated.
