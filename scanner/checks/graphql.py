from __future__ import annotations

from ..models import Finding, RequestTemplate
from .base import ActiveCheck


INTROSPECTION_QUERY = "query AdvscanIntrospection { __schema { queryType { name } types { name } } }"


class GraphQLCheck(ActiveCheck):
    name = "graphql"
    description = "Safe GraphQL endpoint, error, and introspection checks."
    max_requests_per_target = 2

    def supports(self, template):
        return "graphql" in template.tags and "validated" in template.tags

    async def run(self, template, client, baseline, config):
        findings = []
        if config.mode not in {"active", "deep"} and not getattr(config, "enable_graphql_introspection_probe", False):
            return findings
        probe = RequestTemplate(
            method="POST",
            url=template.url,
            json_body={"query": INTROSPECTION_QUERY},
            content_type="application/json",
            source=self.name,
            tags={"graphql"},
        )
        try:
            snapshot = await client.send(probe, check_name=self.name)
        except Exception:
            return []
        body = (snapshot.text_sample or "").lower()
        if snapshot.status_code == 200 and "__schema" in body and "querytype" in body:
            findings.append(Finding(
                type="GraphQL introspection enabled",
                title="GraphQL introspection enabled",
                severity="Medium",
                confidence="High",
                url=template.url,
                method="POST",
                evidence="Safe introspection query returned __schema data.",
                request_summary={"query": "AdvscanIntrospection"},
                response_summary={"status": snapshot.status_code},
                remediation="Disable introspection for production or require authorization if schema details are sensitive.",
                source=self.name,
                tags={"graphql", "active"},
            ))
        elif "errors" in body and ("stack" in body or "exception" in body):
            findings.append(Finding(
                type="GraphQL verbose error leakage",
                title="Verbose GraphQL error response",
                severity="Low",
                confidence="Medium",
                url=template.url,
                method="POST",
                evidence="GraphQL response includes verbose error markers.",
                response_summary={"status": snapshot.status_code},
                remediation="Return generic GraphQL errors to unauthenticated clients and log details server-side.",
                source=self.name,
                tags={"graphql", "active"},
            ))
        return findings
