# Phase 2 — Python/TShark Network Sensor

**Status:** ✅ Complete. Live tests on 2026-10-19; archive review on 2026-10-28.

A Python/TShark sensor captures IPv4 ICMP echo-request **metadata** and writes a JSON alert when a source exceeds **40 observed requests in one fixed 60-second window**.

| Case | Requests | JSON alerts | Result |
|---|---:|---:|---|
| Idle baseline | 0 | 0 | ✅ PASS |
| Exact threshold | 40 | 0 | ✅ PASS |
| Threshold exceeded | 41 | 1 | ✅ PASS |

CSV rows, summaries, TShark logs and alert-file counts all agree. All 13 archived evidence files match the original SHA-256 manifest, and the 13 offline tests pass.

📄 **Full report:** [docs/phase-2-live-validation.md](docs/phase-2-live-validation.md). It covers the architecture, configuration, commands, results, problems and fixes, screenshots and limitations.

## Contents

| Path | Purpose |
|---|---|
| [`src/soc_capture.py`](src/soc_capture.py) | Sensor: Linux-only, non-root, scoped local destination, exclusive output creation |
| [`tests/test_soc_capture.py`](tests/test_soc_capture.py) | 13 offline tests on synthetic metadata |
| [`evidence/`](evidence) | 6 screenshots + archive/closeout verification records + offline test log |

## Safety design

- Python standard library + local `tshark` only: no webhook, model call, API key or upload.
- Refuses to run as root. Requires an explicit interface, local destination, authorized source list, purpose and a new output directory. The `any` interface is rejected.
- Non-promiscuous (`-p`), no name resolution (`-n`), 64-byte snaplen. Only six metadata fields are kept: no PCAP, no payload.
- Rejects duplicate or out-of-order frames, invalid timestamps, out-of-scope traffic and metadata spanning more than the window.
- An alert is a **threshold observation**, not proof of malicious intent, a flood or impact. No MITRE mapping or intent is invented.

## Limitations

- Loopback-only validation; separate-VM traffic is Phase 3.
- Capture-loss completeness is not established.
- The generated alert hasn't been sent to the Phase 1 AI analyst yet (Phase 4).
- The screenshots are captures of the archived evidence made during the review on 2026-10-28, not live terminal screenshots from the test day.
