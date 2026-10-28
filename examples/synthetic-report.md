# SecurityScanner audit

João Pereira Labs

ID: SYNTHETIC\-EXAMPLE\-NOT\-A\-REAL\-AUDIT
Started: 2026\-01\-01 00:00:00\+00:00
Finished: 2026\-01\-01 00:00:00\+00:00
Duration: 0.0 seconds
Profile: passive; Status: completed
Authorization confirmed: False
Allowed scope: \[\]
Targets: \[\]
Resolved scope: \{\}
Ports: \[\]; Version probes: False

## Executive summary

1 open TCP services observed.
Open services alone are not confirmed vulnerabilities.
\{&\#x27;Critical&\#x27;: 0, &\#x27;High&\#x27;: 0, &\#x27;Medium&\#x27;: 0, &\#x27;Low&\#x27;: 0, &\#x27;Informational&\#x27;: 1\}

## Services

| Address | Port | Service | Product | Version | Method |
|---|---|---|---|---|---|
| 192\.0\.2\.10 | 443 | https | Synthetic Example Server | 1\.0 | probed |

## Findings

### Informational — Open TCP service observed

- identifier: NET\-001
- title: Open TCP service observed
- description: A TCP endpoint was observed open\. This is not proof of a vulnerability\.
- evidence: 443/tcp; name=https; product=Synthetic Example Server; version=1\.0; detection=probed
- asset: \[192\.0\.2\.10\]:443/tcp
- severity: Informational
- confidence: high
- kind: information
- impact: Reachable services increase exposure only when unnecessary or misconfigured\.
- recommendation: Confirm business need, patch status and access restrictions\.
- references: \[\]
- detected_at: 2026\-01\-01 00:00:00\+00:00
- source: nmap

## Limitations and inconclusive checks

- SYNTHETIC DOCUMENTATION DATA — not a real audit or an assertion about a real system\.
- Imported scope, original capture date and authorization are not verified\.
- No HTTP/TLS analysis or CVE correlation was performed\.
