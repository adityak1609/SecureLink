# SecureLink graphical application

Double-click `Launch SecureLink.cmd`. On a fresh installation, use `Setup SecureLink.cmd` first. The app opens your default browser and runs Python services in the background. Dependencies and Python are needed; this is not yet a bundled standalone executable.

## Demonstration workflow

Start the local demo, send the text/image/audio/video samples, and receive each file. Preview the received content and save a copy. The received copy is checked against the transfer's SHA-256 before the GUI offers it. Inspect the distinct client, server and witness process IDs.

Open Security & audit and verify the audit chain. The operation reads the log without updating checkpoints, compares the anchored prefix, and requires the complete head/count to match the live witness. A failed verification stays visibly failed. New transfers invalidate the earlier verification result until you verify again.

Open Traffic analysis and analyze the capture. Export actual USER0 stream PCAP, SQLite, XML and the summary. These are socket-read observations, not IP/TCP packets. Entropy and marker visibility are supporting descriptive observations, not proof of encryption. The capture begins when the current local demo starts; analysis is a snapshot.

Interrupted uploads appear with a Resume action. Their local source and request ID are retained. Interrupted downloads retain their partial file and resume when Receive is retried. The encrypted backend verifies complete downloads before replacing their destination. The GUI does not fabricate an interruption; disconnect a lab peer or network to demonstrate recovery.

Use the sidebar power icon to close the application and stop its services. Closing the browser tab alone leaves the app running. The launcher reopens the existing instance for the same state directory; a kernel lock prevents competing instances from writing that state.

## Two-device setup

The GUI runs on the client computer. Its browser HTTP listener is always loopback-only. The receiver can run on a second machine using `bank_server.py`; the independently protected witness can run on the client machine or another lab host. Use the topology and private-network port instructions in the README.

The GUI uses `runtime/gui/credentials/client.json`, not `secrets/client.json`. With the GUI closed, either copy your securely provisioned client credential file to that path, or add the GUI device identity and matching secret to the receiver's device registry through a secure provisioning channel. Do not paste keys into the frontend, put them in the report, or commit credential files. Keep the server identity in the client configuration consistent with `bank-server`.

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

`python tests/browser_smoke.py` uses Playwright and installed Chrome to exercise the visible frontend. Install `requirements-dev.txt` first. It validates actual image/audio/video decoding, UTF-8 text rendering, file-picker uploads, downloaded bytes, audit state, export downloads, reloads and narrow-screen layout. It saves screenshots under `runtime/browser_qa/`.
