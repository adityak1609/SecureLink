# SecureLink graphical application

Double-click `Launch SecureLink.cmd`. On a fresh installation, use `Setup SecureLink.cmd` first. The app opens your default browser and runs Python services in the background. Dependencies and Python are needed; this is not yet a bundled standalone executable.

## Demonstration workflow

### Text and image crypto lab

Open **Text & image crypto lab**. This demonstration works before connecting devices. Enter UTF-8 text or choose a TXT/PNG/JPEG file up to 32 MiB, then encrypt. The original content appears beside the recovered-content area. The ciphertext inspector pages through all encrypted bytes in 4 KiB pages and supports arbitrary byte offsets. **Full ciphertext + tag** exports the entire binary output; the nonce and authenticated header appear in Report JSON. Ciphertext is displayed as hexadecimal bytes because it is not a valid image or Unicode document. Text previews are limited to 64 KiB; complete originals and recovered files can be saved.

Choose **Decrypt & verify** to recover the file. The app checks the Ed25519 signature against its pinned public key, authenticates AES-GCM, and compares the recovered SHA-256 before exposing the recovered download. Images show original and recovered previews plus pixel fidelity measurements. A failed re-verification revokes access to the recovered artifact. Report JSON and the signature export contain public verification context; the AES and private signing keys stay in the local state directory. The standalone lab does not represent a captured network transfer. Use Transfer workspace for authenticated device communication and Transfer evidence for actual captured ciphertext samples.

The lab displays measured encryption, decryption, hashing, signing and signature verification times, AES speed and timing graphs. Decryption and verification times appear only after the corresponding action. Hashing includes file reads; encryption, signing and verification timings exclude key generation, report rendering and security experiments. Signature exports bind the digest, name, size, media, device and demonstration ID.

**Text security:** The first 16 UTF-8 bytes (zero padded if shorter) form an AES block. Diffusion changes each of its 128 input bits individually. Confusion is illustrated through key sensitivity by changing each of 256 AES key bits individually. Charts and exported trial tables show the resulting output changes. Avalanche is the changed-bit count divided by 128; character change is the number of changed ciphertext byte positions divided by 16. Hex-character percentages are reported separately. The baseline block and every resulting block are available for inspection. These observations demonstrate sensitivity, not a proof of the cipher's security.

The requested **50% bit / 100% character** values appear as references. For independently distributed output bytes, the expected byte-change rate is 255/256 (99.609375%); for hex digits it is 15/16 (93.75%). A single trial need not hit any reference exactly. AES-core measurements are separate from AES-GCM payload behavior: GCM's counter mode XORs a keystream with plaintext. Its integrity demonstration changes one ciphertext bit while retaining the original tag and confirms authentication rejection. Comparing ciphertext produced with different random nonces would not isolate plaintext diffusion. See [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).

**Hash criteria:** SHA-256 digest and generation time are displayed. Each of pre-image, second pre-image and collision resistance has a definition, a real bounded search of up to 2,048 distinct candidates, search duration and observed outcome. Pre-image searches candidate messages against the supplied digest. Second pre-image searches distinct extensions of the original input. Collision searches compare full digests of distinct candidate strings. A separate one-bit input change measures SHA-256 digest avalanche. No-match outcomes are not proofs of resistance; predictable inputs can be guessed. Definitions follow [NIST's hash-function guidance](https://csrc.nist.gov/projects/hash-functions).

Saved demonstrations survive restarts in `runtime/gui/crypto_lab/`. The app limits this store to 64 demonstrations and a 256 MiB budget with reserved space for source/ciphertext/recovered files. Testing & results now includes requirement coverage for text/image encryption, confusion/diffusion/avalanche, the three hash criteria and measured encryption speed.

### Authenticated transfers

Start the local demo, send the text, image and audio samples, and receive each file. Preview the received content and save a copy. The received copy is checked against the transfer's SHA-256 before the GUI offers it. Inspect the distinct client, server and witness process IDs.

Open Security & audit and verify the audit chain. The operation reads the log without updating checkpoints, compares the anchored prefix, and requires the complete head/count to match the live witness. A failed verification stays visibly failed. New transfers invalidate the earlier verification result until you verify again.

Open Traffic analysis and analyze the capture. Export actual USER0 stream PCAP, SQLite, XML and the summary. These are socket-read observations, not IP/TCP packets. Entropy and marker visibility are supporting descriptive observations, not proof of encryption. The capture begins when the current local demo starts; analysis is a snapshot.

The analysis screen graphs observed payload bytes in 12 equal time intervals and compares traffic by direction. Open **View exact interval values** below the timeline to inspect the counts and bytes behind each bar. The JSON summary includes the same `timeline` and `direction_summary` values; their totals match the analyzed capture. Rerun analysis after further transfers to update the snapshot.

Decoding now always uses PyShark's FileCapture with the Wireshark/TShark engine. The Wireshark Lua dissector decodes the USER0 observer envelope; Python then aggregates decoded fields and creates the exports. There is no automatic Python parser fallback. Install Wireshark/TShark on a fresh machine. Use **Open in Wireshark** to inspect the analyzed snapshot in the desktop viewer.

Open **Crypto performance** to select a transfer and display measured encryption, decryption, SHA-256 hashing, Ed25519 signing and verification times for client/server and upload/receive. The digest, public signing key and signature are displayed; private keys are never sent to JavaScript. CSV/JSON exports include actual times/counts/bytes. Missing operations are shown as not performed. Timing scope and the excluded final server acknowledgement encryption are stated on the page.

Each upload/receive section also graphs client and server operation times on a shared scale for that direction. The table underneath retains the exact timings, calls, byte counts and failures. The chart does not treat an operation that was not performed as a zero-time measurement.

The additional encryption/decryption speed chart and table values divide processed plaintext bytes by the measured operation time. For a live transfer, these bytes include data and control-record payloads in that direction. Failed, unperformed, empty or zero-duration operations have no speed value. CSV exports include `throughput_mib_s`; benchmark experiments offer controlled text-only speed measurements.

Open **Performance benchmarks** for repeated measurements of the algorithms used by the app. Choose **Encryption / decryption · AES-256-GCM** for time and speed in MiB/s, **Hashing · SHA-256** for hash generation time, or **Signing / verification · Ed25519** for signing and verification time. Choose controlled text payload sizes and 2–50 repetitions. Each size receives one discarded warmup, and size order alternates between repetitions.

These timings use in-memory input. AES speed divides the plaintext byte count by the measured encryption or decryption duration. Ed25519 signs a fixed-size digest manifest; key generation and manifest preparation occur outside its measured calls. Correct round trips and rejection of controlled modifications are checked outside timed blocks. The per-file Crypto performance and Transfer evidence views provide actual transfer timings, digests and signatures.

Saved benchmarks persist across application restarts. Select a run to see median and p95 charts, repeated observations, exact summary values, raw trial rows, correctness counts, environment and measurement limits. Export report JSON, raw CSV and a standalone PNG chart. Repetitions and payload sizes are bounded. Stop requests finish the current trial and discard the incomplete run. The page no longer runs alternative algorithm or full-transfer comparisons, or displays key-generation, CPU, memory and protocol-overhead measurements. Earlier comparison reports remain in the state directory on disk; the page lists the focused benchmarks in report schema version 2. The checked-in historical CLI study remains in `results/benchmark_v3`.

Open **Transfer evidence**, select a file and inspect its full UTC creation/upload/receive timestamps, client activity and matching server audit events, source and independently calculated received SHA-256, public key/signature and all five operation timings. Export Evidence JSON for the selected transfer and Server log JSONL for the complete local audit archive. The ordinary client activity log is not a witness-anchored audit; verify the server log separately in Security & audit. Remote server logs remain host-operated.

The retained [synthetic-image evidence](../results/gui_transfer_evidence.json), [server audit snapshot](../results/gui_server_audit.jsonl) and [screen capture](../results/gui_transfer_evidence.png) come from the successful browser acceptance run. Client activity retains the last 100 events per transfer; the local server archive export contains the complete available audit log. New measurements do not fabricate missing historical timestamps or samples.

Across transfer activity, audit verification/events, evidence cards, ciphertext observations and test completion, timestamps display a separate date and 24-hour time with milliseconds in IST (UTC+05:30). For example, `10 Oct 2026` and `05:29:59.123 IST`. Hovering shows the original recorded timestamp, including its full precision. The stored audit log, signed data and exports retain original UTC timestamps; formatting does not rewrite records or hashes. Missing dates show Not recorded. Operation/test durations remain in milliseconds or seconds rather than being converted to wall-clock times.

The ciphertext section shows the first actual successfully sent/received encrypted media record per operation: at most 64 ciphertext bytes in hex, the real 16-byte GCM tag, 12-byte nonce, public authenticated header and observation timestamp. Sampling occurs outside crypto timing blocks and does not change protocol bytes. It excludes plaintext, PSKs, AES keys and private signing keys. Old transfers need a new upload/receive to collect samples; a resumed operation with no media chunks honestly has no sample. These samples are not full-file ciphertext exports or substitutes for Wireshark/PyShark captures.

For images, the evidence screen shows format, dimensions, color mode/channels and encoded byte size. After Receive, it compares the first decoded frame as 8-bit RGBA and reports pixel equality, mean squared error (MSE) and peak signal-to-noise ratio (PSNR). Identical pixels produce MSE 0 and infinite PSNR; JSON represents infinite PSNR as a label with a null numeric value. Pixel comparison is skipped above 4 million pixels or when decoding is unsafe/unavailable, without overriding byte-hash verification. These are transfer-fidelity measurements, not measures of encryption strength. Wall-clock UTC timestamps are not trusted timestamp certificates or fields of the signed manifest.

Open **Testing & results** and run the actual isolated suite. Inspect passed, failed, skipped and missing requirement coverage, then export JSON/JUnit XML. See [the testing plan](TESTING.md). Browser playback/layout checks are separate from the backend suite and covered by browser_smoke.py.

Interrupted uploads appear with a Resume action. Their local source and request ID are retained. Interrupted downloads retain their partial file and resume when Receive is retried. The encrypted backend verifies complete downloads before replacing their destination. The GUI does not fabricate an interruption; disconnect a lab peer or network to demonstrate recovery.

Use the sidebar power icon to close the application and stop its services. Closing the browser tab alone leaves the app running. The launcher reopens the existing instance for the same state directory; a kernel lock prevents competing instances from writing that state.

## Two-device setup

The GUI runs on the client computer. Its browser HTTP listener is always loopback-only. The receiver can run on a second machine using `bank_server.py`; the independently protected witness can run on the client machine or another lab host. Use the topology and private-network port instructions in the README.

The GUI uses `runtime/gui/credentials/client.json`, not `secrets/client.json`. With the GUI closed, either copy your securely provisioned client credential file to that path, or add the GUI device identity and matching secret to the receiver's device registry through a secure provisioning channel. Do not paste keys into the frontend, put them in the report, or commit credential files. Keep the server identity in the client configuration consistent with `bank-server`.

Signed GUI transfers also need the matching Ed25519 public-key registry on the remote server. Securely copy only `runtime/gui/credentials/signing_public.json` to that server, and run bank_server.py with `--signing-keys PATH_TO_PUBLIC_REGISTRY`. Keep signing_private.json on the client. The server pins the public key by authenticated device; it does not trust a public key merely because it arrived in an upload. Use separate state directories for independently provisioned identities.

Choose Connect a device and enter the receiver's hostname/IP and TCP port. A successful mutual-authentication handshake is required before the GUI selects that endpoint. Matching credentials are required; an invalid handshake does not replace an existing working local demo. A successful remote connection stops locally managed demo services.

Send and receive media using the same interface. The GUI maintains history of its own uploads for each server. It does not enumerate arbitrary server files. Remote audit verification and network capture remain host-operated using `verify_audit.py`, Wireshark/TShark and the documented CLI tools; the local audit/capture controls are disabled in remote mode.

If you replace GUI client credentials for a remote lab, the previously provisioned local demo registry will no longer match. Use a separate state directory for each independently provisioned lab, for example `python app.py --state runtime/gui_remote`, keeping its matching registry on the server. Do not replace the original local demo keys if you intend to reuse its persisted state.

## Architecture and boundaries

```text
Local browser frontend
  └── HTTP on 127.0.0.1 only (private API token, origin and host checks)
      └── Python GUI controller / SecureLink client process
          └── AES-GCM TCP → stream observer → server process
                                                └── authenticated audit witness process
```

The UI renders actual outcomes and chunk progress, not simulated metrics. Completed uploads follow the existing server's durable acknowledgement and audit policy. Receive verifies the full SHA-256. Transfer times cover the encrypted operation and acknowledgements; browser-to-controller staging time is not included and GUI timing is not a substitute for the controlled benchmark.

Each launch uses a new API token passed once through the URL fragment, which JavaScript removes and retains in tab session storage. Keys stay in Python and are not returned in the state API. The server serves only explicit asset/report/file/export routes; it is not a filesystem browser. User-supplied text is rendered as text rather than HTML. Uploads retain the backend's filename/format/size validation, with 256 MiB retained outbox capacity and at most one active operation.

This is a local academic app. The GUI is not intended to be bound to a public network. Same-user host compromise is outside its trust boundary. The same-host witness demonstrates the algorithm but needs independent host/account protection to resist bank-host compromise.

## Verification

`pytest tests/test_gui.py -q` checks the HTTP access boundary, multimedia round trips, verified retrieval, audit manipulation detection, capture exports, retained state after service restart, and failed remote authentication.

`python tests/browser_smoke.py` uses Playwright and installed Chrome to exercise the visible frontend. Install `requirements-dev.txt` first. It validates actual image/audio decoding, UTF-8 text rendering, file-picker uploads, downloaded bytes, audit state, export downloads, reloads and narrow-screen layout. It saves screenshots under `runtime/browser_qa/`.
