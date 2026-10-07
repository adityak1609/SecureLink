# SecureLink Secure Multimedia Communication

SecureLink is an educational Python client/server framework that demonstrates confidentiality, integrity, mutual device authentication, accountability and bounded recovery from communication failures. It transfers valid text, images, audio and video over TCP, supports authenticated resumable uploads and downloads, and records events against a separately operated audit witness.

Approved ISL modules implemented:

- **Traffic Analysis:** Wireshark/TShark and PyShark capture inspection; descriptive entropy and payload statistics.
- **PCAP Analysis:** PCAP to SQLite and XML with matching record-count verification.

This is a banking-style transaction simulation, not a payment system or a claim of PCI DSS/RBI compliance. The version 3 protocol intentionally replaces the old wire format and hardcoded keys. Original files are preserved in `backups/pre_upgrade_*`. The original root `benchmark_results.csv` predates this upgrade and must not be used as current evidence.

## Start here

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
.\.venv\Scripts\python pcap_analyzer.py captures/session_stream.pcap --backend stream --output results/stream_analysis
```

Optional `tools/securelink_user0.lua` makes the observer direction, connection number and observed bytes visible in Wireshark/TShark (`-X lua_script:tools/securelink_user0.lua`). The file does not decrypt application data.

For actual network packets, install Wireshark/TShark and the Npcap driver on Windows (libpcap on Linux), then:

```powershell
.\.venv\Scripts\python capture_traffic.py --mode interfaces
.\.venv\Scripts\python capture_traffic.py --mode network --interface INTERFACE_ID --target-port 9999 --duration 30 --output captures/network.pcapng
.\.venv\Scripts\python pcap_analyzer.py captures/network.pcapng --backend pyshark --output results/network_analysis
```

Run transfers during the 30-second capture. Capture filters restrict acquisition to the configured lab TCP port. The network backend handles IPv4/IPv6 and reports Wireshark retransmission flags. Network marker searches are packet-local, so absence is inconclusive when a marker crosses TCP segments. Use Wireshark Follow TCP Stream for a reassembled view. The stream backend handles markers crossing observed reads. Both backends report descriptive entropy, validate SQLite/XML counts and expose sample SQL queries:

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
- `results/security_tests.xml`: automated regression results (47 tests).
- `results/demo_v3/demo_results.json`: secured/plaintext comparison and lost-ACK recovery.
- `results/two_process_v3/results.json`: separate-process topology and verified transfers.
- `results/benchmark_v3/measurements.csv`: 240 observations, 30 per mode/media combination.
- `results/benchmark_v3/summary.json` and `comparison.png`: medians, p95, goodput, CPU time, sampled RSS, handshake time and protocol bytes.
- `results/demo_v3/{secure,plaintext}/analysis/`: validated SQLite, XML and descriptive capture summaries.

Measurements include hashing, actual transfer, disk persistence and audit acknowledgement. They use identical chunking and audit policy in both modes, alternate execution order and discard one warmup per mode/file. CPU and RSS are aggregate values for simulated endpoints sharing a process. RSS sampling can miss short spikes; Windows CPU timer quantization can report zero for short operations. Client-server byte counts exclude TCP/IP overhead and separate audit-witness traffic. Do not infer performance on a different device or a congested network from these loopback observations.

`build_report.py` regenerates the HTML synopsis/evaluation from saved evidence. Retained results are observations, not universal security guarantees. Audit corruption tests use temporary files and do not erase user logs.

## Project layout

`securelink/protocol.py` implements authentication, session derivation and framing; `client.py` and `server.py` implement transfers; `storage.py` owns durable idempotency; `audit.py` implements logs/checkpoints; `service.py` provides bounded TCP workers; `capture.py` and `analysis.py` implement traffic evidence; `benchmarks.py` evaluates actual transfers. Root scripts provide runnable CLI entry points. Tests are isolated in `tests/`.

## References

- [Cryptography AES-GCM documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/)
- [Cryptography HKDF documentation](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf)
- [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Wireshark TCP analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)
- [Wireshark Windows capture requirements](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html)


