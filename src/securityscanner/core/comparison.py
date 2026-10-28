from securityscanner.core.models import Scan


def compare(a: Scan, b: Scan) -> dict[str, list[str]]:
    if a.status != "completed" or b.status != "completed":
        raise ValueError(
            "Only completed scans can be compared; failed/cancelled results are partial."
        )
    if (a.profile, a.pinned, a.ports, a.versions) != (b.profile, b.pinned, b.ports, b.versions):
        raise ValueError("Scan scope, resolved IPs, ports, profile and version mode must match.")
    sa, sb = {s.key for s in a.services}, {s.key for s in b.services}
    fa, fb = {f.key for f in a.findings}, {f.key for f in b.findings}
    return {
        "new_services": sorted(sb - sa),
        "services_no_longer_observed": sorted(sa - sb),
        "new_findings": sorted(fb - fa),
        "findings_no_longer_observed": sorted(fa - fb),
        "persistent_findings": sorted(fa & fb),
        "limitations": [
            "No longer observed does not prove remediation; validate reachability and coverage.",
            "Passive imports have no verified original scope or capture date. Compare with care.",
        ],
    }
