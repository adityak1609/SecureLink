# SecureLink protocol and threat model

## Trust and attacker model

An attacker can observe, alter, replay, reorder or interrupt network traffic, open connections, submit malformed frames, and attempt to impersonate an endpoint without its secret. A separate audit-file attacker can edit, delete or recompute the bank's local log, but cannot alter the previously stored witness checkpoints. Endpoint code, device secret provisioning, the server's SQLite state and the independent witness are trusted.

Compromise of both the bank and witness, compromise of a device PSK, malware on endpoints, operating-system administrators, disk failure, traffic-analysis resistance, Internet-scale denial of service and real banking authorization are outside the claim. A witness running under the same OS account as the bank does not constitute an independent trust boundary. Checkpoint protection extends only through the latest accepted checkpoint; unanchored crash tails cannot have the same guarantee.

## Authentication

All handshake records use a 4-byte big-endian length followed by canonical JSON, limited to 4,096 bytes. The overall receive deadline is five seconds. The client sends version 3, its device ID, expected server ID, a random 256-bit nonce and a Unix epoch timestamp. The server rejects timestamps more than 60 seconds from its own clock, adds its random 256-bit nonce and proves knowledge of that device's random 256-bit PSK with HMAC-SHA256 over the canonical transcript and a server role label. The client verifies before responding with a client-labelled HMAC. The server verifies and returns a finished-labelled HMAC. Duplicate JSON keys, unexpected fields, unknown identities, invalid nonces and expired timestamps are rejected. No key material is sent. The timestamp additionally bounds the accepted age of a connection request.

Endpoint clocks must remain within the configured 60-second window for authentication to succeed. Fresh handshake nonces and transcript verification provide the handshake replay protection; the timestamp additionally bounds the age of a connection request.

HKDF-SHA256 derives 64 bytes using the PSK as input, SHA-256 of the full transcript as salt and a protocol/direction context string. The halves are independent client-to-server and server-to-client AES-256 keys. SHA-256 of the transcript is the session ID. Fresh nonces make distinct sessions; no ephemeral Diffie-Hellman is used, so the construction does not provide forward secrecy.

## Encrypted records

The wire format is a 4-byte total length, 2-byte header length, JSON header and AES-GCM ciphertext with its 16-byte tag. The header is authenticated associated data and includes version, session ID, monotonically increasing sequence, message kind and operation metadata. Header bytes are capped at 2,048; total record bytes at 131,072. The GCM nonce is four zero bytes followed by the eight-byte sequence counter. Directional keys are distinct, and a new session always derives fresh keys before resetting counters. A sender fails before counter exhaustion.

The receiver checks the session and exact next sequence, then verifies the GCM tag before dispatching the plaintext. Type changes, chunk-offset changes, payload modification and replay therefore fail. A framing error closes the connection; an attacker can disrupt a connection but cannot turn unauthenticated bytes into a committed transfer. Public headers, byte lengths, identities during handshake and timing remain visible.

Each record has a total receive deadline, which is not reset when another partial byte arrives. The server also applies connection, new-connection rate, per-session record rate, file-size and aggregate reserved-storage bounds.

## Transfers and retries

`begin` encrypts the original basename, media category, exact size and SHA-256. Its authenticated public metadata carries a 128-bit request ID. The server indexes requests by authenticated device plus request ID. Reusing an ID with different metadata fails. An existing matching request returns its persisted offset or completed status.

`chunk` authenticates the request and byte offset. The server accepts only the exact current offset and at most 64 KiB; it writes and fsyncs the chunk before persisting the new offset and acknowledging it. If a process crashes between writing the file and updating SQLite, a subsequent begin truncates the uncommitted suffix to the stored offset. Short files relative to committed offsets fail validation.

`finish` requires the exact expected length, matching full-file hash and format consistency. The server anchors a finalize-intent event, atomically commits completion plus any simulated transaction ledger insertion in SQLite, and anchors a completion event before sending its acknowledgement. A crash between commitment and acknowledgement is resolved by retrying the same request ID. A second ledger entry cannot be inserted for that device/request pair. This is durable idempotent commitment, not a claim of exactly-once network delivery. The final intent and durable SQLite record support recovery if the completion audit event was interrupted; a retry records completion again.

The client makes at most four attempts with bounded exponential backoff and jitter, re-authenticating after a lost connection. Authentication, integrity or semantic failures are not retried as transient network faults. Request IDs printed before transfer support manual resume after the client process exits.

`status` and `read` permit downloads only for the authenticated owner's completed transfers. Download chunks authenticate the request and offset. The client retains a partial file after a connection failure, verifies the final SHA-256 and then requests an anchored download-completion event before publishing the destination file. A stale/corrupted partial file fails the final hash check and must be discarded explicitly before retrying.

## Signed file manifests and measurements

The GUI adds an Ed25519 signed-transfer extension to v3. Transport HMAC authentication remains separate and is not labelled a digital signature. A signed `begin` body contains `{metadata, signature}`; the signature has algorithm `Ed25519`, the sender's public key, and its 64-byte signature encoded as hex. The signed bytes are the domain separator `SecureLink/file-signature/Ed25519/v1\0` followed by canonical JSON containing device, request ID and the complete metadata (name, media, size and SHA-256).

The receiver accepts signed transfers only against that authenticated device's provisioned, pinned public key. When a signing key is registered, unsigned begins are rejected. An arbitrary public key supplied by a sender cannot establish trust. Accepted signatures are retained in SQLite beside the owner/request record and must remain unchanged on retries. File completion still requires the declared length, final SHA-256 and format checks, so the accepted signature binds the committed file contents through their digest.

For signed GUI receives, the client verifies the saved signature against its own provisioned sender public key and the returned manifest before writing media, then verifies the complete downloaded SHA-256. A changed request, device, filename or file digest invalidates the signature. This authenticates the provisioned signing key; public identity certification, legal non-repudiation and private-key-compromise protection are not claimed.

Actual AES-GCM encrypt/decrypt, SHA-256 file-read/hash and Ed25519 sign/verify calls are timed using `perf_counter_ns`. Reports retain operation counts, elapsed nanoseconds/milliseconds, processed bytes and failures. Client counters reset per upload/receive and include retries. Server counters cover the final connection up to encoding its last response, excluding that response's encryption; they are reported inside authenticated encrypted acknowledgements. The GUI labels this scope and does not present missing measurements as zeros. File hashing includes file I/O; handshake time includes communication and is separate from cryptographic-call timing. These observations include instrumentation overhead and are not universal algorithm-performance estimates.

## Audit evidence

Each canonical JSONL event includes a sequential index, UTC timestamp, previous entry hash, event, authenticated device, session, request, outcome and limited non-content details. SHA-256 covers all these fields. A lock serializes concurrent writes; data is fsynced before anchoring. An independently operated witness authenticates a different audit PSK and stores the latest count/head pair in SQLite.

The witness accepts only the next count chained to its current head, or an exact duplicate after a lost acknowledgement. It rejects rollback and conflicting heads. Verification recomputes every event and compares the historical prefix with the witness checkpoint, detecting ordinary edits, recomputed chains, suffix truncation and deletion. A bank cannot silently replace a previously anchored prefix without also compromising the witness. This does not make events truthful or provide public non-repudiation.

Witness loss deliberately stops accountable completion; the system has no replicated witness or automatic failover. On restart, a valid local tail after the checkpoint is submitted in order. Log rotation and long-term archival require a separate retention design. Do not silently delete logs or SQLite state to resolve a validation failure.

## Evaluation limits

The automated separate-process demo simulates two communicating devices and a witness on one host. It verifies the implementation without claiming physical isolation. Benchmarks use in-process TCP endpoints for repeatable measurement, with aggregate process CPU and memory. A second physical-machine run and a network-level PCAP require the documented LAN setup and an appropriate capture driver.

The portable observer records real application stream bytes in PCAP LINKTYPE_USER0, prefixed by observer direction and connection number. Record boundaries are socket reads, not packet boundaries. Statistics from these captures must not be called TCP retransmission rates, TCP RTT or physical-link bandwidth. PyShark's network backend is intended for separately acquired IP/TCP captures.
