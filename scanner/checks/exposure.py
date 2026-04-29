from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

from ..http_client import redact_value
from ..models import Finding, RequestTemplate
from .base import ActiveCheck


@dataclass(frozen=True)
class ExposureRule:
    path: str
    severity: str
    signatures: tuple[str, ...] = ()
    negative_signatures: tuple[str, ...] = ("<html", "<!doctype html")
    content_type_hints: tuple[str, ...] = ()
    max_bytes: int = 200_000
    rationale: str = ""


EXPOSURE_RULES = [
    ExposureRule("/.env", "High", ("app_key=", "database_url=", "password=", "secret", "aws_")),
    ExposureRule("/.env.local", "High", ("app_key=", "database_url=", "password=", "secret", "aws_")),
    ExposureRule("/.env.production", "High", ("app_key=", "database_url=", "password=", "secret", "aws_")),
    ExposureRule("/.env.development", "High", ("app_key=", "database_url=", "password=", "secret", "aws_")),
    ExposureRule("/.env.backup", "High", ("app_key=", "database_url=", "password=", "secret", "aws_")),
    ExposureRule("/.git/HEAD", "Medium", ("ref: refs/heads/",)),
    ExposureRule("/.git/config", "High", ("[core]", "repositoryformatversion", "[remote ")),
    ExposureRule("/.svn/entries", "Medium", ("dir", "svn", "committed-rev")),
    ExposureRule("/.hg/hgrc", "Medium", ("[paths]", "default =")),
    ExposureRule("/backup.zip", "Medium", (), negative_signatures=("<html",), content_type_hints=("application/zip", "octet-stream"), rationale="binary backup archive with non-HTML response"),
    ExposureRule("/db.sql", "High", ("create table", "insert into", "mysqldump")),
    ExposureRule("/database.sql", "High", ("create table", "insert into", "mysqldump")),
    ExposureRule("/users.sql", "High", ("create table", "insert into", "mysqldump", "users")),
    ExposureRule("/data.sql", "High", ("create table", "insert into", "mysqldump")),
    ExposureRule("/latest.sql", "High", ("create table", "insert into", "mysqldump")),
    ExposureRule("/composer.lock", "Low", ('"packages"', '"packages-dev"', '"content-hash"')),
    ExposureRule("/package-lock.json", "Low", ('"lockfileversion"', '"packages"', '"dependencies"')),
    ExposureRule("/pnpm-lock.yaml", "Low", ("lockfileversion", "dependencies:", "packages:")),
    ExposureRule("/.npmrc", "High", ("_auth", "authtoken", "registry=")),
    ExposureRule("/.yarnrc", "Low", ("yarn-path", "registry", "npmAuthToken")),
    ExposureRule("/actuator/health", "Info", ('"status"', "components", "diskspace")),
    ExposureRule("/actuator/env", "High", ("propertysources", "activeprofiles", "systemenvironment")),
    ExposureRule("/actuator/configprops", "Medium", ("contexts", "beans", "prefix")),
    ExposureRule("/actuator/mappings", "Medium", ("dispatcherServlets", "handler", "predicate")),
    ExposureRule("/actuator/beans", "Medium", ("contexts", "beans", "aliases")),
    ExposureRule("/actuator/loggers", "Low", ("configuredlevel", "effectivelevel", "loggers")),
    ExposureRule("/actuator/threaddump", "Medium", ("threadName", "threadState", "stackTrace")),
]


class ExposureCheck(ActiveCheck):
    name = "exposure"
    description = "Checks common exposed configuration and metadata paths with signatures."
    max_requests_per_target = len(EXPOSURE_RULES)

    def supports(self, template):
        return template.method == "GET" and template.depth == 0 and template.source == "manual"

    async def run(self, template, client, baseline, config):
        findings = []
        for rule in EXPOSURE_RULES:
            target = urljoin(config.target_url.rstrip("/") + "/", rule.path.lstrip("/"))
            probe = RequestTemplate(method="GET", url=target, source=self.name, tags={"exposure"})
            try:
                snapshot = await client.send(probe, check_name=self.name)
            except Exception:
                continue
            if _matches_rule(rule, snapshot):
                findings.append(Finding(
                    type="Sensitive File/Dir Found" if rule.severity != "Info" else "Info",
                    title=f"Exposed {rule.path}",
                    severity=rule.severity,
                    confidence="High" if rule.signatures else "Medium",
                    url=target,
                    method="GET",
                    evidence=_evidence(rule, snapshot),
                    response_summary={"status": snapshot.status_code, "content_type": snapshot.content_type, "length": snapshot.length},
                    remediation="Remove exposed files/endpoints from the web root or require authentication and network allowlisting.",
                    source=self.name,
                    tags={"exposure", "active"},
                ))
        return findings


def _matches_rule(rule: ExposureRule, snapshot) -> bool:
    if snapshot.status_code in {401, 403} and rule.path.startswith("/actuator/"):
        return True
    if snapshot.status_code != 200:
        return False
    text = (snapshot.text_sample or "")[:rule.max_bytes].lower()
    content_type = (snapshot.content_type or "").lower()
    if any(negative in text[:500] for negative in rule.negative_signatures):
        if not any(hint in content_type for hint in rule.content_type_hints):
            return False
    if rule.signatures and any(signature.lower() in text for signature in rule.signatures):
        return True
    return bool(rule.content_type_hints and any(hint in content_type for hint in rule.content_type_hints) and snapshot.length > 0)


def _evidence(rule: ExposureRule, snapshot) -> str:
    if snapshot.status_code in {401, 403}:
        return f"{rule.path} exists but is access-restricted"
    text = snapshot.text_sample or ""
    for signature in rule.signatures:
        if signature.lower() in text.lower():
            return f"matched signature {redact_value(rule.path, signature)}"
    return rule.rationale or "matched exposure rule"
