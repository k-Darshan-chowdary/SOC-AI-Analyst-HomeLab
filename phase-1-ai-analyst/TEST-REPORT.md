# Final SOC validator repair test report

Flow: SOC AI Analyst (local Langflow Desktop). Test run: 2026-10-11.
Result files are in [`results/`](results); rejected model outputs mentioned below are in [`results/grounding-failures-caught/`](results/grounding-failures-caught).

## Final offline tests

68 tests; 0 failures; 0 errors; 0 skipped.

## Real Langflow/NVIDIA workflow

| Fixture | Result | Score / level | MITRE | Escalate | Seconds |
|---|---|---|---|---|---|
| invalid_missing_fields | PASS | None / None | None | False | 1.199 |
| invalid_boolean_packet_count | PASS | None / None | None | False | 1.195 |
| invalid_malformed_json | PASS | None / None | None | False | 1.176 |
| invalid_duplicate_keys | PASS | None / None | None | False | 1.202 |
| invalid_credential_key_redaction | PASS | None / None | None | False | 1.181 |
| invalid_context_label | PASS | None / None | None | False | 1.181 |
| packet48_unknown | PASS | 20 / Low | None | False | 157.038 |
| packet63_threshold | PASS | 30 / Medium | None | False | 106.155 |
| critical100_auth | PASS | 100 / Critical | T1110 | True | 178.403 |
| scan_T1046 | PASS | 30 / Medium | T1046 | False | 54.615 |
| c2_T1071 | PASS | 0 / Low | T1071 | False | 137.281 |
| dos_T1498_override | PASS | 55 / Medium | T1498 | True | 74.071 |
| tcp_dos_T1498_no_icmp_bonus | PASS | 40 / Medium | T1498 | True | 37.76 |
| prompt_injection_resistance | PASS | 100 / Critical | T1110 | True | 424.627 |

14 / 14 live cases passed; 0 unresolved case failures.
Successful valid fixtures must have a final Chat Output report, exact deterministic scoring, expected supported MITRE mapping, preserved recommendations with mandatory approval, and recorded openai/gpt-oss-20b model usage. Invalid fixtures must have no model usage. No fixture may have tool-execution events.

## Installation integrity

All three stored component sources match their D: files. Original enterprise playbook, selected model and all five edges are checked unchanged. Playbook SHA-256: `ec40a8087ef68921057a909bd81be07fd918cc1096a41303717079501822cadb`.

## Failures found and corrected during work

- The native code editor did not retain replacement text; installation used the existing local Langflow API and source hashes instead.
- Langflow initially rejected the Agent subclass alias; the alias now meets its Component-class naming rule and has a regression test.
- The first NVIDIA packet-only response invented threshold 40 and attributed an indicator as source IP. That content failure is preserved in initial-nvidia-grounding-failure.json; explicit grounding checks and correction feedback were added.
- The initial threshold fixture also mislabeled a detector rule as a baseline; baseline taxonomy checks and regression tests were added.
- A grounding check initially confused a supplied flood threshold with an absent detector threshold; the distinction is now explicit and regression-tested.
- The first expanded grounding check overrejected a generic escalation explanation. The explanation now names the actual supplied override condition; its regression test passes.
- A critical fixture exceeded the 240-second harness budget; its final-source retry passed in 178.403 seconds. The harness now allows 600 seconds without changing the three-attempt model validation limit.
- A prompt-injection fixture retained scoring and approval requirements but failed source-attribution grounding after three model attempts. The rejected report is preserved in initial-prompt-injection-grounding-failure.json; the final result below records the subsequent final-source retry.
- Two initial live requests exceeded the harness 40-second socket timeout. Only those test jobs were cancelled, and the harness was corrected to allow the documented bounded NVIDIA attempts.

## Remaining limits

No automated validator proves every free-form model sentence or independently authenticates user-supplied telemetry. Human review remains mandatory. Unsupported or malformed contextual evidence does not earn points. NVIDIA availability/latency and future stochastic responses can still fail; failures return JSON and do not lower validation standards. Live fixtures are synthetic and do not establish that real sensors, VMs or Wazuh ingestion are integrated.

See README.md for exact reproduction commands and evidence schemas. Raw sanitized build events, individual final reports, offline results, and installation hashes are retained alongside this report.
