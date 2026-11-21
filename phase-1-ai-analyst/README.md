# Phase 1 — AI SOC Analyst (Langflow + NVIDIA)

**Goal:** an LLM-based SOC Tier 1 triage analyst whose output can be trusted: validated input, deterministic scoring, grounded analysis, and mandatory human review.

## Workflow

```
Chat Input ─► SOC Input Validation ─► Agent (NVIDIA openai/gpt-oss-20b) ─► SOC Output Review Gate ─► Chat Output
    └──────────── original alert JSON ───────────────────────────────────────────►┘
```

- **Invalid input** → a complete rejection envelope. The Agent does no model analysis, and no score, classification, MITRE technique or action is invented.
- **Valid input** → normalized, credential-redacted and scored locally. The Agent receives only the current alert plus a deterministic contract. History and tools are disabled.
- The Agent gets **at most 3 attempts**. A remaining failure returns JSON `verification_failed` / `model_error`. Validation standards are never lowered, and provider error details are never exposed.
- All recommendations require human approval, and every report requires human review.

## Files

| File | Purpose |
|---|---|
| [`soc_policy.py`](soc_policy.py) | Canonical pure validation / scoring / report-verification policy |
| [`build_components.py`](build_components.py) | Embeds the policy into three self-contained Langflow components |
| [`soc_input_validation.py`](soc_input_validation.py) | Langflow component: strict input validation + redaction + scoring |
| [`soc_agent_guard.py`](soc_agent_guard.py) | Minimal Agent subclass: invalid-input short-circuit, bounded retries |
| [`soc_output_review_gate.py`](soc_output_review_gate.py) | Langflow component: independent report verification |
| [`update_langflow.py`](update_langflow.py) | Installs component source into an existing flow via the local Langflow API, then verifies the playbook, model and edges are unchanged |
| [`enterprise-soc-playbook-v1.0.md`](enterprise-soc-playbook-v1.0.md) | Master system instructions / SOC triage playbook |
| [`test_soc_validators.py`](test_soc_validators.py) | 68 offline tests (no network or model) |
| [`verify_nvidia_workflow.py`](verify_nvidia_workflow.py) | 14 synthetic cases through the real Langflow graph + NVIDIA |
| [`audit_live_results.py`](audit_live_results.py) | Audits live results and builds the test report |
| [`TEST-REPORT.md`](TEST-REPORT.md) | Final results and the failures found and fixed along the way |

## Risk scoring (deterministic, in code)

| Component | Points |
|---|---|
| Packet tier (exactly one) | 0–30 → 0 · 31–50 → 20 · 51–100 → 30 · 101+ → 40 |
| Repeated activity (≥2 distinct events < 60 s apart) | +20 |
| Privileged / sensitive service targeted | +20 |
| ICMP flood-like behavior (supported evidence only) | +15 |
| Suspicious authentication (≥2 observed failures) | +25 |

Total = min(100, sum). **Low** 0–29 · **Medium** 30–59 · **High** 60–79 · **Critical** 80–100.
High and Critical require escalation; Critical means P1, with immediate Tier 2 escalation.

Every component cites supporting evidence or states that the condition wasn't established. Zero is not evidence of absence. The source IP is never inferred from `indicator_value`.

## Optional evidence contract

Context only earns points when it is **structured telemetry with provenance**: a non-empty `source` and `reference`, bound to the alert's subject. Titles, labels or a port number alone don't count. Supported containers include:

`repeated_events`, `related_alerts`, `service_context`, `asset_criticality`, `authentication_events`, `documented_flood_threshold`, `historical_baseline`, `connection_attempts` (→ T1046), `c2_evidence` (→ T1071), `system_impact` (→ T1498 with flood evidence), `confirmed_compromise`, `authorized_test`.

The full rules are in [`soc_policy.py`](soc_policy.py) and the fixtures in [`verify_nvidia_workflow.py`](verify_nvidia_workflow.py).

## Security checks

- **Strict JSON:** rejects duplicate keys, non-finite numbers, non-object input and malformed syntax.
- **Field checks:** rejects boolean, fractional or negative packet counts, invalid IPs and non-positive windows. Reserved `_soc_` keys are blocked.
- **Redaction:** credential-like keys and token/password patterns (`nvapi-`, `sk-`, `Bearer`, `password=`) are redacted before reaching NVIDIA and in reports.
- **Output gate:** checks exact numbers, all five score entries, escalation, mandatory review, a supported classification, and valid MITRE ID/name/tactic combinations.
- **Recommendations:** offensive, executable or destructive ones are rejected, as is unsupported disruptive containment.
- **Grounding:** rejects the hallucinations seen in testing (an invented threshold, indicator-as-source, contradictory missing-field claims). High confidence requires multiple provenance sources.

## Reproduce

Offline tests (no network or model calls):

```powershell
python -B test_soc_validators.py
```

Live tests need Langflow running locally with an NVIDIA-configured flow built from these components. They use synthetic data only:

```powershell
$env:SOC_FLOW_ID = "<your-flow-id>"
python -B verify_nvidia_workflow.py                    # all 14 cases
python -B verify_nvidia_workflow.py --case scan_T1046  # one case
```

## Results

See [TEST-REPORT.md](TEST-REPORT.md) and [`results/`](results).

- **68 / 68** offline tests pass.
- **14 / 14** live cases pass, covering invalid input ×6, Low/Medium/Critical scoring, T1046 / T1071 / T1498 / T1110, a TCP DoS without the ICMP bonus, and prompt-injection resistance.

## Limits (honest)

- No automated check proves every free-form sentence the model writes. Human review stays mandatory.
- User-supplied telemetry provenance is not authenticated.
- Live fixtures are synthetic. Integration with the real sensor (Phase 2) is Phase 4.
- NVIDIA latency and availability, and the model's stochastic output, can still cause failures. Those return JSON errors; standards are never lowered.
