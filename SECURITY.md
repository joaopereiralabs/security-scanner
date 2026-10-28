# Security policy

This is pre-stable software. The current development line is 0.2.x; there is no promised
long-term support or response SLA. Do not assume a security audit has validated the tool.

For a vulnerability in SecurityScanner itself, use the repository's **Report a vulnerability**
option if GitHub private reporting has been enabled by the owner. Its availability has not
been assumed or verified. If unavailable, open a minimal issue requesting a private contact
channel without exploit details, credentials or target data. Do not publish real audit logs.

Useful reports include version, OS, reproduction using a local fixture, expected behavior,
observed behavior and a proposed mitigation. Scope bypass, arbitrary process execution,
unsafe report rendering, XML entity expansion and data disclosure are especially relevant.

Only scan assets you own or have explicit authorization to audit. The `--authorized` flag
records an assertion; it does not independently verify permission. An exact hostname allow
entry approves its initial DNS addresses, so trust the configured resolver and review the
resolved scope stored in the audit record. Use literal IP allow entries for tighter control.

The local user, Nmap executable, Python environment and data directory are trusted. Protect
the data directory from other writers; this is not a multi-user sandbox. POSIX private modes
apply to newly created files; Windows ACLs and existing directory permissions are operator
responsibilities. SQLite and audit logs are not encrypted or tamper-evident.

No telemetry or remote advisory requests are implemented. Active hostname scans use OS DNS;
Nmap connects only to pinned numeric IPs, with reverse DNS disabled. Version probes are
optional and can send application payloads. Do not use them on fragile production devices
without separately evaluating impact. No raw HTTP responses or credentials are collected by
the application, but service identity fields may contain sensitive text supplied by a server.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for boundaries and [ROADMAP.md](docs/ROADMAP.md)
for features that are intentionally not implemented yet.
