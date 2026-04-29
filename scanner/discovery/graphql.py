from __future__ import annotations

from urllib.parse import urljoin

from ..models import Asset, DiscoveryCandidate, RequestTemplate


SAFE_GRAPHQL_CANDIDATES = ["/graphql"]
ACTIVE_GRAPHQL_CANDIDATES = ["/graphql", "/api/graphql"]
DEEP_GRAPHQL_CANDIDATES = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/api/v1/graphql"]

GRAPHQL_MARKERS = (
    "cannot query field",
    "must provide query string",
    "graphql",
    "\"errors\"",
    "errors",
)


def graphql_candidates(base_url: str, mode: str = "safe") -> list[DiscoveryCandidate]:
    if mode == "deep":
        paths = DEEP_GRAPHQL_CANDIDATES
    elif mode == "active":
        paths = ACTIVE_GRAPHQL_CANDIDATES
    else:
        paths = SAFE_GRAPHQL_CANDIDATES
    return [
        DiscoveryCandidate(
            method="POST",
            url=urljoin(base_url.rstrip("/") + "/", path.lstrip("/")),
            source="graphql-common",
            reason="Common GraphQL endpoint path; requires safe validation before checks",
            confidence="Low",
            tags={"api", "graphql", "candidate"},
            discovered_from=base_url,
        )
        for path in paths
    ]


def graphql_templates(base_url: str, mode: str = "safe") -> list[RequestTemplate]:
    return [
        RequestTemplate(
            method=candidate.method,
            url=candidate.url,
            json_body={"query": "query AdvscanTypename { __typename }"},
            content_type="application/json",
            source="graphql-discovery",
            tags={"api", "graphql", "candidate"},
            discovered_from=candidate.discovered_from,
        )
        for candidate in graphql_candidates(base_url, mode)
    ]


async def validate_graphql_candidate(candidate: DiscoveryCandidate, client) -> tuple[DiscoveryCandidate, Asset | None, RequestTemplate | None]:
    template = RequestTemplate(
        method="POST",
        url=candidate.url,
        json_body={"query": "query AdvscanTypename { __typename }"},
        content_type="application/json",
        source="graphql-validation",
        tags={"api", "graphql", "validation"},
        discovered_from=candidate.discovered_from,
    )
    try:
        snapshot = await client.send(template, check_name="graphql-validation")
    except Exception as exc:
        candidate.validation_evidence = f"validation skipped: {exc.__class__.__name__}"
        return candidate, None, None

    body = snapshot.text_sample or ""
    lower = body.lower()
    content_type = (snapshot.content_type or "").lower()
    graphql_like = False
    evidence = ""
    if "application/json" in content_type and ('"data"' in lower or '"errors"' in lower):
        graphql_like = True
        evidence = f"JSON GraphQL-like response with data/errors key (HTTP {snapshot.status_code})"
    elif snapshot.status_code in {400, 405} and any(marker in lower for marker in GRAPHQL_MARKERS):
        graphql_like = True
        evidence = f"HTTP {snapshot.status_code} GraphQL-like error response"
    elif any(marker in lower for marker in GRAPHQL_MARKERS) and "<html" not in lower[:500]:
        graphql_like = True
        evidence = f"GraphQL marker in non-HTML response (HTTP {snapshot.status_code})"

    if not graphql_like:
        candidate.validated = False
        candidate.validation_evidence = f"not confirmed as GraphQL (HTTP {snapshot.status_code})"
        return candidate, None, None

    candidate.validated = True
    candidate.confidence = "High"
    candidate.validation_evidence = evidence
    asset = Asset(
        type="graphql",
        url=candidate.url,
        method="POST",
        source=candidate.source,
        evidence=f"GraphQL endpoint validated: {evidence}",
        tags={"api", "graphql"},
        confidence="High",
    )
    validated_template = RequestTemplate(
        method="POST",
        url=candidate.url,
        json_body={"query": "query AdvscanTypename { __typename }"},
        content_type="application/json",
        source="graphql-validated",
        tags={"api", "graphql", "validated"},
        discovered_from=candidate.discovered_from,
    )
    return candidate, asset, validated_template
