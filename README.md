# SC3030 — Network Configuration Security Validator

A transparent, local **Python + Streamlit** proof of concept for evaluating a limited subset of **Cisco IOS extended IPv4 access-control lists (ACLs)** against defined security and connectivity requirements. Prepared for an SC3030 Advanced Computer Networks coursework presentation.

**This repository contains no LLM prompt generator, no embedded generation prompts, no AI service integration and no API keys.** It accepts configuration text supplied by the user and evaluates predefined test flows.

## Quick start (Windows)

1. Download or clone this repository into a short **local** folder (for example `C:\SC3030_Validator`). Avoid UNC/network share paths, which can break Python DLL loading on Windows.
2. Double-click `start_windows.bat` or use a terminal in the project root:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe -m streamlit run app.py
   ```

3. Open `http://localhost:8501` (Streamlit may use another available port).
4. Choose **Expanded — 8 policies** in the sidebar.
5. Under **Reproduce all four experiment configurations**, click **Load ORIGINAL A (expected 5/8)**, then **Validate configuration**. Repeat with **ORIGINAL B**, **NEW A**, and **NEW B**.
6. Expand **Show reproducible comparison across both policy suites** to see scores computed directly from the saved configuration files.
7. Inspect the rule traces and optionally download the evidence CSV.

### Test suites

The **original suite (4 policies)** contains two security and two operational checks. The **expanded suite (8 policies)** retains those original four and adds four checks:

| ID | Category | Source → Destination | Protocol | Expected |
|---|---|---|---|---|
| SEC-01 | Security | 192.168.20.10 → 10.0.0.10 | TCP/22 SSH | DENY |
| SEC-02 | Security | 192.168.20.10 → 192.168.10.10 | TCP/22 SSH | DENY |
| **SEC-03 (added)** | Security | 192.168.20.11 → 10.0.0.10 | TCP/22 SSH | DENY |
| **SEC-04 (added)** | Security | 192.168.20.11 → 192.168.10.10 | TCP/22 SSH | DENY |
| **SEC-05 (added)** | Security | 192.168.20.10 → 10.0.0.10 | TCP/443 HTTPS | DENY |
| OPS-01 | Operations | 192.168.20.10 → 10.0.0.10 | UDP/53 DNS | ALLOW |
| OPS-02 | Operations | 192.168.10.10 → 10.0.0.10 | TCP/443 HTTPS | ALLOW |
| **OPS-03 (added)** | Operations | 192.168.20.11 → 10.0.0.10 | UDP/53 DNS | ALLOW |

**SEC-03, SEC-04, SEC-05 and OPS-03** are the four new checks. Source-of-truth definitions are `POLICIES` and `EXPANDED_POLICIES` in [`validator.py`](validator.py).

## Demonstration and research evidence

Four **preserved** configurations are provided, not four samples drawn from new model runs. Both original configurations were generated for the original four requirements; the new configurations were generated with all eight requirements specified. One generation was captured per condition.

| File / UI button | Prompt condition | Original 4-check suite | Expanded 8-check suite |
|---|---|---:|---:|
| `experiment_configs/A_original_4_requirements.txt` — ORIGINAL A | Basic; **4 requirements** | 4/4 PASS | **5/8 FAIL** |
| `experiment_configs/B_original_4_requirements.txt` — ORIGINAL B | Security-guided; **4 requirements** | 4/4 PASS | **5/8 FAIL** |
| `experiment_configs/A_basic_8_requirements.txt` — NEW A | Basic; **8 requirements** | 4/4 PASS | **8/8 PASS** |
| `experiment_configs/B_guided_8_requirements.txt` — NEW B | Security-guided; **8 requirements** | 4/4 PASS | **8/8 PASS** |

### Reproduce the 5/8 finding

1. Select **Expanded — 8 policies** in the left sidebar (the default).
2. Click **Load ORIGINAL A (expected 5/8)**.
3. Click **Validate configuration**.
4. Confirm **5/8 overall, 2/5 security, 3/3 operational**. The failures are **SEC-03**, **SEC-04**, and **SEC-05**. These access-control gaps follow from the host-specific deny rules and a general `permit ip any any`.
5. Repeat with **Load ORIGINAL B (expected 5/8)**.
6. Then load **NEW A** and **NEW B**, validating each: both score 8/8 in the same expanded test suite.

* `samples/` contains three deliberately constructed illustrative configurations (unsafe, corrected, and overblocking). **They are not LLM experiment results.**
* `experiment_configs/` contains all four actual configurations supplied in the conversation, preserved as text without changes.
* `evidence/expanded_results_all_four.csv` records every check for all four configurations under the expanded test suite.
* `evidence/comparison_by_suite.csv` summarizes both test suites for all four configurations.

**Interpretation:** The original configurations were generated before the expanded security requirements were introduced. Their 5/8 result is a retrospective coverage check, **not** evidence that they failed requirements specified in their original prompts. Both new methods scored 8/8 on one generated configuration each, so these results do not establish that one prompting method performs better than the other. A passing score is not exhaustive security validation.

## Method and exact limitations

The validator implements **deterministic, ordered first-match ACL analysis** for selected IPv4 flows:

* Parses `ip access-list extended NAME` with ordered `permit`/`deny` actions and attaches named ACLs using `ip access-group NAME in/out`.
* Supports `ip`, `tcp`, `udp`, `icmp`, `any`, `host`, standard IPv4 wildcard masks, numeric destination-port `eq`, and optional sequence numbers.
* Checks traffic passing between **directly connected networks** using inbound ACL on the source interface and outbound ACL on the destination interface, including implicit deny.
* Reports whether each expected allow/deny result matches the modeled configuration, alongside evidence indicating the matching ACL entry.

**Not modeled:** arbitrary Cisco syntax, IOS device acceptance or commit success, port/source-state or established sessions, stateful firewalls, routing protocols, NAT, non-ACL policy, device availability, real packets, real network traffic, topology outside the three connected networks, or every possible host/port combination. Unknown ACL syntax is treated as *not evaluated* rather than silently permitted. Other (non-ACL) CLI commands are outside the validator scope.

A passing score is **not a proof of security, operational safety or deployment readiness**. In particular, the eight checks are sampled source/destination/protocol combinations, not exhaustive verification of subnet-wide access.

## Automated tests

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The test suite covers original/expanded requirements, rule ordering, implicit deny, interface direction, invalid ACL references, unsupported syntax and preservation of experiment outcomes.

## Project layout

```text
app.py                         Streamlit user interface (no generated prompts)
validator.py                   Static ACL parser and eight policy-test definitions
samples/                       Constructed diagnostic cases
experiment_configs/            All four preserved experiment configurations
evidence/                      Reproducible CSV outputs for 4 and 8 check suites
requirements.txt               Python dependencies
start_windows.bat              Windows launcher
tests/                         Automated regression tests
```

All tests and results are specific to this deliberately limited model. This is a coursework proof of concept, not a reproduction of the complete ConfGen, CAP, TDD or Intent-LLM frameworks.
