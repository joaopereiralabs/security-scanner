# Reviewed delivery roadmap

| Milestone | Current assessment | Acceptance evidence / remaining work |
|---|---|---|
| v0.1 Foundation | Implemented, included in 0.2.0 | Installable CLI, doctor, settings, validated models, scope denial and DNS tests |
| v0.2 Network Scanner | Implemented; pre-stable | Real subprocess adapter, parsing, limits, cleanup, local integration; Kali validation remains |
| v0.3 Web Analysis | Next | HTTP/HTTPS pinned transport, request budget, redirects, header/cookie analysis, certificate chain/name/expiry, negotiated TLS tests |
| v0.4 Reporting | Partially anticipated | HTML/JSON/Markdown, SQLite and comparison work for TCP; web findings, richer risk summaries and migrations remain |
| v0.5 Terminal UI | Planned | Textual dashboard, eight functional areas, worker progress, cancellation, real screenshot capture |
| v1.0 Stable | Planned | Independent security review, platform matrix, packaging release, comprehensive web/TUI tests |

## v0.1 review

Default-deny scope is mandatory for active execution, including programmatic orchestration.
Malformed targets and out-of-scope destinations fail before target connections. Passive
imports never resolve DNS or invoke a process. Configuration is deliberately small and
validated. No shell switches are accepted. See `test_scope.py` and `test_workflow.py`.

## v0.2 review

No simulated scan results are used at runtime. The XML parser rejects incomplete, unsafe
and oversized input. Nmap is supervised with a timeout and cleanup. Only approved numeric
IP/port endpoints are accepted in active results. Scope and commands are persisted before
execution. Real Nmap integration is tested only against an owned loopback test service.
There is no independent host-discovery sweep: selected-port reachability is the current scope.

## Early v0.4 review

Reports preserve evidence and limitations, escape attacker-controlled markup, and include
authorization and coverage. SQL parameters prevent query injection. Comparisons reject
incomplete runs and different active coverage; imported coverage is explicitly unverified.
Missing observations are never called proven remediation. Open services remain informational.

## Next milestone gate: v0.3

Before exposing `--profile web`, implement and test transport-level IP pinning with correct
Host/SNI, explicit schemes and ports, scoped redirect chains, total timeout/request budgets,
header-only/minimal-body retrieval and cookie attribute redaction. Cover local trusted,
expired and hostname-mismatched certificates, failed handshakes and inconclusive results.
No public-target test dependencies. Only then add HTTP/TLS findings and update reports.

## Optional advisory correlation

After core analysis, consider locally imported NVD/CISA data with documented provenance,
dataset timestamps and explicit potential-match labels. External refresh must be opt-in.
Product/version matches never establish exploitation, compromise or confirmed vulnerability.
