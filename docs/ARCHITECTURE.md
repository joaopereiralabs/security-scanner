# Architecture and threat model

## Boundaries

1. Typer parses options. The orchestrator independently checks the selected profile and
   authorization; a CLI wrapper cannot silently remove the scope policy.
2. Scope rejects ranges, wildcards, URLs, option syntax, unsafe address classes and malformed
   hostnames. Exact hostname entries authorize initial resolved addresses. Literal IP entries
   do not implicitly authorize unrelated hostnames that resolve to them.
3. DNS runs in a Python subprocess with a five-second deadline. All targets are checked
   before target connections. Resolution is repeated before each task; any changed address
   set aborts. The Nmap target is the approved numeric IP, never the hostname. A DNS change
   after revalidation cannot retarget that numeric connection.
4. Only fixed Nmap options are constructed. `shell=False`, `-sT`, `-n`, `-Pn`, unprivileged
   mode and disabled ARP ping avoid privileged scan requirements and reverse DNS. Each task
   handles one IP and at most 32 ports; all tasks are sequential. A hard process deadline
   kills and waits for Nmap on timeout/cancellation. Nmap's own host timeout also applies.
5. XML accepts a plain Nmap DOCTYPE but forbids entities/external references. Input is capped
   at 8 MiB. Failed/incomplete results are rejected. Only selected open TCP fields survive
   parsing; arbitrary NSE output, fingerprints, MAC addresses and hostname metadata do not.
6. Pydantic validates persisted models. SQLite uses parameterized SQL and schema version 1.
   A record is stored before execution and updated after each command and on finalization.
   Audit JSON Lines stores commands, approval and outcome. Storage errors stop processing.
7. Findings distinguish information, potential issues, confirmed issues and inconclusive
   checks. This version generates only informational open-service observations. Severity is
   an enum, not an automatically generated CVSS number.
8. HTML uses Jinja autoescape, offline CSS, no active links from evidence and restrictive CSP.
   Markdown escapes markup and HTML. JSON preserves structured data. New reports use exclusive
   creation to avoid overwriting a prior audit.

## Trust and limitations

The operator, local executable search path, Nmap binary/data files and writable storage are
trusted. An attacker controlling them can bypass policy outside this application. The scope
system prevents accidental out-of-scope application requests; it is not a network firewall,
an OS sandbox or a legal authorization service. Name resolution can contact configured DNS
infrastructure; network routing, NAT and compromised resolvers remain outside the boundary.

TCP-only inventory cannot prove host absence, patch status or lack of vulnerabilities. A
port-table label is explicitly distinguished from a probed identity. Version probes may use
Nmap's built-in protocol/version detection, and `--max-rate` is not a strict application
request budget. Raw subprocess output is held in temporary files and removed on normal
completion; its disk use is not streamed with a strict quota, although task duration and
selected ports are bounded. The parser reads at most 8 MiB. Sensitive identity strings are
possible; version probing is opt-in and reports should remain private.

Cancellation preserves already completed tasks, not partially parsed XML. A hard kill can
leave `running` history; recovery marking is planned. Logs do not rotate, cannot prove their
own integrity and are not encrypted. SQLite currently keeps validated scan payloads in one
transactional table to avoid redundant model/schema drift at this stage; indexed relational
finding queries can be added with a migration when needed.

No redirect transport exists in v0.2. HTTP/TLS implementation must add independent tests for
every redirect, DNS rebinding, Host/SNI preservation and pinned socket connections before
the web profile is exposed. A generic HTTP client's implicit DNS/redirect behavior must not
be used without those controls.

## References consulted

- [Nmap timing and performance](https://nmap.org/book/man-performance.html)
- [Nmap service/version detection](https://nmap.org/book/man-version-detection.html)
- [Nmap host discovery](https://nmap.org/book/man-host-discovery.html)

Nmap is an external dependency under its own license; its source is not copied or bundled.
