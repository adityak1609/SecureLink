# SecureLink Secure Multimedia Communication

SecureLink is an educational Python client/server framework that demonstrates confidentiality, integrity, mutual device authentication, accountability and bounded recovery from communication failures. It transfers valid text, images, audio and video over TCP, supports authenticated resumable uploads and downloads, and records events against a separately operated audit witness.

Approved ISL modules implemented:

- **Traffic Analysis:** Wireshark/TShark and PyShark capture inspection; descriptive entropy and payload statistics.
- **PCAP Analysis:** PCAP to SQLite and XML with matching record-count verification.

This is a banking-style transaction simulation, not a payment system or a claim of PCI DSS/RBI compliance. The version 3 protocol intentionally replaces the old wire format and hardcoded keys. Original files are preserved in `backups/pre_upgrade_*`. The original root `benchmark_results.csv` predates this upgrade and must not be used as current evidence.

## Start here

### Graphical application (recommended for presentation)

Double-click **Launch SecureLink.cmd** to open the application in your browser, without a terminal window. On a fresh clone, first double-click **Setup SecureLink.cmd** to install dependencies. Python must already be installed.

The GUI includes a transfer workspace, device connection view, text composer, file picker and drag-and-drop, acknowledged chunk progress, persistent transfer history, resumable uploads, verified receiving, image/text previews, playable audio/video, audit verification, and PCAP-to-SQLite/XML exports. All transfers use the existing authenticated AES-GCM backend; no security results are mocked.

1. Click **Start local demo**. The GUI starts the server and audit witness as separate hidden processes, on automatically selected ports, and authenticates the client.
2. Send your own file/text, or use the four sample buttons. Supported formats are TXT, PNG/JPG, WAV/MP3 and MP4, up to 32 MiB.
3. Choose **Receive** to retrieve the server's copy through the encrypted channel and verify its SHA-256. Then use **Preview** or **Save**.
4. Open **Security & audit**, click **Verify audit chain**, and show the witness checkpoint and recorded events.
5. Open **Traffic analysis**, analyze the current captured stream, and export PCAP, SQLite, XML or JSON for the report.
   Decoding runs through **PyShark → Wireshark/TShark**, using the Wireshark Lua dissector for the USER0 observer envelope. There is no custom Python parser fallback. **Open in Wireshark** opens the analyzed snapshot in the desktop viewer.
6. Use **Disconnect devices** to stop the simulated services, or the power icon in the sidebar to close the application. Closing only the browser tab leaves the local application running; launching again reopens that instance.

The GUI provisions its own random keys under excluded `runtime/gui/credentials/` and retains transfers in `runtime/gui/`. It does not overwrite CLI keys or existing CLI state. Restarting the local demo retains its server transfers and history. If a transfer fails, **Resume** reuses its original request ID. The interface displays controls separately from verification results; an audit is marked verified only after its head and count match the live authenticated witness.

**Crypto performance** displays measured encryption, decryption, SHA-256 file hashing, Ed25519 signing and signature verification times for each upload/receive, separately for client and server. It shows call counts, processed bytes, failures, file digest, public signing key and signature, and exports CSV/JSON. Times surround the actual library operations. Hash timing includes file reads; server measurements stop before encoding the final acknowledgement, and cover the last connection when retries occur. Unperformed operations show a dash rather than a fabricated zero.

GUI transfers use real **Ed25519 digital signatures**, distinct from handshake HMAC authentication. The signed manifest binds the file SHA-256, original filename/media/size, device and request ID. The receiver verifies against a pinned public key before accepting the transfer; receive also checks the signature and full-file hash. GUI signing keys are provisioned separately as `signing_private.json` and `signing_public.json`. Older unsigned GUI transfers can use **Sign & resend** with their original request ID to add a signature without duplicating a committed transaction.

**Transfer evidence** consolidates the professor's review items for a selected file: full UTC timestamps, client activity and matching server audit logs, all five crypto timings, original/received SHA-256 values, Ed25519 signature/public key, and a real bounded ciphertext sample with its AES-GCM nonce/tag. Images show dimensions, format/mode, encoded size and original-versus-received RGBA MSE/PSNR. Identical received pixels give MSE 0 and infinite PSNR; these measure fidelity, not encryption strength. Export Evidence JSON and the complete local server audit JSONL. New operations collect ciphertext; historic transfers are not given invented samples. See [the evidence scope and limits](docs/GUI.md).

**Testing & results → Run tests** runs the actual isolated pytest suite and displays passed, failed and skipped cases, timings and requirement coverage. Missing/skipped coverage remains incomplete. Download JSON and JUnit XML for your review. See [the testing plan](docs/TESTING.md).

Install Wireshark with TShark enabled before using capture analysis or its tests on a fresh machine. Python dependencies alone do not install TShark. Npcap is only required for live Windows IP/TCP capture, not for decoding saved USER0 captures. Retained `benchmark_v3` evidence measured the earlier unsigned v3 transfers; newly displayed signature timings are live observations, not retroactive additions to that benchmark.

For a remote server, choose **Connect a device** and enter its host and port. Provision matching client/server device credentials as described in [the GUI guide](docs/GUI.md). The browser UI is restricted to `127.0.0.1`; device communication can use a lab LAN. The same-host browser-to-Python interface uses local HTTP with an unguessable API token, origin checks and host validation. AES-GCM protects the client-to-server TCP leg. This local academic UI is not an internet-hosted web service.

Alternative launch:

```powershell
.\.venv\Scripts\python app.py
```

GUI backend checks are included in `pytest tests`. Optional real-browser acceptance checks use installed Chrome:

```powershell
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\.venv\Scripts\python tests/browser_smoke.py
```

The browser check uses isolated local state and exercises all four media previews, real encrypted round trips, file-picker/text uploads, saved downloads, audit verification, exports and a 390-pixel viewport. Screenshots and its summary stay under excluded `runtime/browser_qa/`.

### Command-line evaluation tools

Tested with Python 3.14.3 on Windows 11. Use the project virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python provision.py
.\.venv\Scripts\python generate_samples.py
.\.venv\Scripts\python -m pytest tests -q
```

The fixture generator creates and validates real PNG/JPEG, WAV/MP3 and H.264 MP4 files. It uses Pillow and the FFmpeg binary bundled in `imageio-ffmpeg`; it does not download personal data or contact a media service.

Run the full demonstration with isolated state and actual socket captures:

```powershell
.\.venv\Scripts\python run_demo.py --output results/demo_new
.\.venv\Scripts\python demo_two_processes.py --output results/process_demo_new
.\.venv\Scripts\python benchmark.py --iterations 30 --output results/benchmark_new
.\.venv\Scripts\python attack_simulator.py
```

Use a fresh output directory for each run. `run_demo.py` compares secured and explicitly unsecured lab transfers, decodes received media, tests recovery after a lost completion ACK, and produces PCAP/SQLite/XML evidence. `demo_two_processes.py` launches separate bank and witness processes, acts as a client process, transfers all four media categories both ways, verifies hashes and stops the child services on exit.

## Run services manually

Provision once; this refuses to overwrite existing credentials:

```powershell
.\.venv\Scripts\python provision.py
```

This creates three files in the excluded `secrets/` directory: client credentials, server device registry plus audit credentials, and witness registry. Keys are cryptographically random, separate for device transport and auditing, and are never printed. On Windows, provision in an access-controlled user directory; POSIX mode bits alone do not configure Windows ACLs. Do not commit these files or share them in the report.

For a fresh clone, run provisioning once before starting the manual services. If the files already exist, reuse them; provisioning deliberately refuses to overwrite existing keys. Downloaded tools and local runtime state are excluded from the repository. The retained result files contain only the synthetic academic demonstration evidence.

Start these commands in separate terminals, in order:

```powershell
.\.venv\Scripts\python witness_server.py
.\.venv\Scripts\python bank_server.py
.\.venv\Scripts\python client_terminal.py upload sample_data/fixtures/transaction.txt
.\.venv\Scripts\python client_terminal.py upload sample_data/fixtures/identity.png
.\.venv\Scripts\python client_terminal.py upload sample_data/fixtures/audio.wav
.\.venv\Scripts\python client_terminal.py upload sample_data/fixtures/video.mp4
```

Each upload prints its request ID before sending. Save it. Substitute that ID below:

```powershell
.\.venv\Scripts\python client_terminal.py download REQUEST_ID runtime/downloaded/video.mp4
.\.venv\Scripts\python client_terminal.py upload sample_data/fixtures/video.mp4 --request-id REQUEST_ID
.\.venv\Scripts\python verify_audit.py
```

The second upload resumes the same file or returns its committed result. The same request ID with different content is rejected. A fresh ID deliberately creates a new transfer. Only the authenticated owner can download a transfer.

## Two physical devices or VMs

The automated evidence is a simulation on one Windows machine with separate TCP endpoints, including a three-process demonstration. To reproduce across two machines:

1. Device A runs the client and audit witness. Device B runs the bank server.
2. Provision locally and transfer only the needed credential file to each device through a secure channel. Keep witness storage inaccessible to the bank service account.
3. On A: run `witness_server.py --host A_LAN_IP`. On B: run `bank_server.py --host B_LAN_IP --witness-host A_LAN_IP`.
4. On A: run `client_terminal.py --host B_LAN_IP upload sample_data/fixtures/video.mp4` and repeat for the other media types.
5. Permit the configured TCP ports (9998 witness, 9999 bank) only between the lab endpoints on the private lab network. Record the OS, CPU, memory and network topology in your report.
6. Verify received hashes, decode/play the received audio/video, capture the lab port traffic, and run controlled disconnect tests.

Device A's witness must be independently protected for the checkpoint threat model to hold. A same-user loopback witness demonstrates the algorithm but does not provide independent protection against host compromise.

## Protocol and security goals

| Goal | Implemented control | Validation |
|---|---|---|
| Confidentiality | AES-256-GCM, fresh derived session keys, unique per-direction counter nonces | Known marker present in plaintext stream, absent in secured stream; valid media round trips |
| Integrity | GCM authentication covers payload and version/session/sequence/type/chunk metadata | Ciphertext and header mutation rejected; final SHA-256 verifies complete file |
| Authentication | Per-device random PSK; HMAC over identities, protocol version, timestamp, both nonces and distinct roles | Wrong secret, wrong server identity, expired timestamp and unknown device rejected |
| Accountability | Canonical hash-chained events with device/session/request identities, fsync and authenticated external checkpoints | Edit, rewrite, truncation, deletion, rollback and concurrent-write tests |
| Availability | Absolute record/handshake deadlines, bounded connections/rate/frame/file/storage, retry with backoff and jitter, durable resume | Interrupted upload/download, lost ACK, partial state recovery, slow peer and connection-limit recovery |
| Replay resistance | Handshake timestamp window, strict session sequence checks plus durable owner/request IDs | Expired-timestamp, exact encrypted-frame replay and old-session frame rejected; duplicate simulated transaction creates one ledger entry |

See [protocol and threat model](docs/PROTOCOL.md). PSK compromise does not preserve past confidentiality: **there is no forward secrecy**. Shared-secret authentication is not third-party non-repudiation. This custom protocol is an educational implementation; production deployment would require a standard reviewed transport such as TLS and a broader security assessment.

Only UTF-8 TXT, PNG, JPEG, WAV, MP3 and MP4 are accepted. Filename syntax, extension/media mapping, file signatures, total length and full-file hash are checked. Signature checks are not antivirus scanning or full parsing. Fixtures and downloaded demonstration files are separately decoded for verification.

Files are read/written in 64 KiB chunks, capped at 32 MiB each. The server reserves at most 256 MiB across 1,024 transfers, including unfinished transfers. It allows 8 concurrent connections, 120 new connections per source IP per minute, 1,000 records per session per second, a 5-second handshake deadline and a 10-second per-record deadline. Lab benchmark helpers explicitly raise the connection-attempt limit to allow repeated local measurements. They do not weaken the normal CLI server.

The transaction demonstration accepts a small JSON TXT file with `action`, `source`, `destination`, and integer `amount_paise`. Completion and ledger insertion are one SQLite transaction. It records simulated requests; it does not maintain real bank balances, authorize account ownership, or transfer funds. Completion acknowledgements follow persistence and audit anchoring. Loss of the audit witness intentionally fails closed; this trades availability for accountable completion.

## Capture and analysis

**The checked-in demonstration evidence uses actual socket-stream bytes in USER0 PCAP.** These observations come from a transparent lab proxy and contain no invented Ethernet/IP/TCP headers. A record is a socket read, not a TCP packet. They cannot measure retransmissions or TCP RTT. Encrypted media still leaks message sizes, timing, direction and authenticated public headers. High entropy also occurs in compressed unencrypted media and is not proof of encryption.

Capture application streams without a driver:

```powershell
.\.venv\Scripts\python capture_traffic.py --mode stream --listen-port 10000 --target-port 9999
.\.venv\Scripts\python client_terminal.py --port 10000 upload sample_data/fixtures/video.mp4
.\.venv\Scripts\python pcap_analyzer.py captures/session_stream.pcap --backend pyshark --output results/stream_analysis
```

`tools/securelink_user0.lua` makes the observer direction, connection number and observed bytes visible in Wireshark/TShark (`-X lua_script:tools/securelink_user0.lua`). PyShark loads this dissector automatically. It decodes the capture wrapper inside Wireshark's engine and does not decrypt application data. Python summarizes decoded fields and creates SQLite/XML exports; it does not replace Wireshark's capture decoder.

For actual network packets, install Wireshark/TShark and the Npcap driver on Windows (libpcap on Linux), then:

```powershell
.\.venv\Scripts\python capture_traffic.py --mode interfaces
.\.venv\Scripts\python capture_traffic.py --mode network --interface INTERFACE_ID --target-port 9999 --duration 30 --output captures/network.pcapng
.\.venv\Scripts\python pcap_analyzer.py captures/network.pcapng --backend pyshark --output results/network_analysis
```

Run transfers during the 30-second capture. Capture filters restrict acquisition to the configured lab TCP port. The network backend handles IPv4/IPv6 and reports Wireshark retransmission flags. Network marker searches are packet-local, so absence is inconclusive when a marker crosses TCP segments. Use Wireshark Follow TCP Stream for a reassembled view. The USER0 decoder preserves observed stream order for cross-read marker searches. PyShark handles both capture types and reports descriptive entropy, validate SQLite/XML counts and expose sample SQL queries:

```sql
SELECT COUNT(*), SUM(length), SUM(payload_size) FROM packets;
SELECT source, destination, COUNT(*), SUM(payload_size)
FROM packets GROUP BY source, destination;
SELECT COUNT(*) FROM packets WHERE retransmission = 1;
```

Npcap is not installed on the development machine. Stream evidence and network-packet evidence are explicitly distinguished throughout the report.

## Evaluation and evidence

- [Revised synopsis](docs/SYNOPSIS.html)
- [Evaluation report](docs/EVALUATION.html)
- `results/security_tests.xml`: automated backend and GUI regression results (see the report for the latest count).
- `results/demo_v3/demo_results.json`: secured/plaintext comparison and lost-ACK recovery.
- `results/two_process_v3/results.json`: separate-process topology and verified transfers.
- `results/benchmark_v3/measurements.csv`: 240 observations, 30 per mode/media combination.
- `results/benchmark_v3/summary.json` and `comparison.png`: medians, p95, goodput, CPU time, sampled RSS, handshake time and protocol bytes.
- `results/demo_v3/{secure,plaintext}/analysis/`: validated SQLite, XML and descriptive capture summaries.

Measurements include hashing, actual transfer, disk persistence and audit acknowledgement. They use identical chunking and audit policy in both modes, alternate execution order and discard one warmup per mode/file. CPU and RSS are aggregate values for simulated endpoints sharing a process. RSS sampling can miss short spikes; Windows CPU timer quantization can report zero for short operations. Client-server byte counts exclude TCP/IP overhead and separate audit-witness traffic. Do not infer performance on a different device or a congested network from these loopback observations.

`build_report.py` regenerates the HTML synopsis/evaluation from saved evidence. Retained results are observations, not universal security guarantees. Audit corruption tests use temporary files and do not erase user logs.

## Project layout

`frontend/` contains the responsive browser UI; `app.py` and `securelink/gui.py` launch and operate the local graphical application. `securelink/protocol.py` implements authentication, session derivation and framing; `client.py` and `server.py` implement transfers; `storage.py` owns durable idempotency; `audit.py` implements logs/checkpoints; `service.py` provides bounded TCP workers; `capture.py` and `analysis.py` implement traffic evidence; `benchmarks.py` evaluates actual transfers. Root scripts also provide CLI evaluation tools. Tests are isolated in `tests/`.

## References

- [Cryptography AES-GCM documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/)
- [Cryptography HKDF documentation](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf)
- [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Wireshark TCP analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)
- [Wireshark Windows capture requirements](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html)


