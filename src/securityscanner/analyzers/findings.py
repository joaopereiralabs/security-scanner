from securityscanner.core.models import Finding, Service


def analyze(services: list[Service]) -> list[Finding]:
    return [
        Finding(
            identifier="NET-001",
            title="Open TCP service observed",
            description="A TCP endpoint was observed open. This is not proof of a vulnerability.",
            evidence=(
                f"{s.port}/tcp; name={s.name}; product={s.product}; "
                f"version={s.version}; detection={s.detection}"
            ),
            asset=f"[{s.address}]:{s.port}/tcp",
            confidence="high",
            impact="Reachable services increase exposure only when unnecessary or misconfigured.",
            recommendation="Confirm business need, patch status and access restrictions.",
        )
        for s in services
    ]
