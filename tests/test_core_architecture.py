import asyncio
import unittest

from bs4 import BeautifulSoup

from scanner.models import RequestTemplate, ScanConfig
from scanner.scope import is_in_scope, normalize_target_url
from scanner.discovery.forms import extract_forms
from scanner.discovery.js import extract_js_endpoints
from scanner.checks.baseline import normalize_dynamic_body
from scanner.checks.exposure import EXPOSURE_RULES
from scanner.checks.idor import PotentialIDORCheck
from scanner.checks.open_redirect import is_external_redirect
from scanner.checks.source_maps import is_valid_source_map
from scanner.scheduler import ScanScheduler
from scanner.checks.base import BaseCheck


class FakeSnapshot:
    def __init__(self, text, status_code=200, content_type="text/html"):
        self.text_sample = text
        self.status_code = status_code
        self.content_type = content_type
        self.headers = {}
        self.length = len(text)
        self.word_count = len(text.split())
        self.final_url = "https://example.test/profile"
        self.elapsed_ms = 10


class FakeClient:
    def __init__(self):
        self.requests_made = 0

    async def send(self, template, check_name="test"):
        self.requests_made += 1
        value = ""
        if template.params:
            value = " ".join(str(v) for v in template.params.values())
        if "2" in value:
            return FakeSnapshot("user_id=2 email=bob@example.test invoice=INV-2")
        return FakeSnapshot("user_id=1 email=alice@example.test invoice=INV-1")


class CountingCheck(BaseCheck):
    name = "counting"
    modes = {"safe", "active", "deep"}

    def __init__(self):
        self.calls = 0

    def supports(self, template):
        return True

    async def run(self, template, client, baseline, config):
        self.calls += 1
        await client.send(template, check_name=self.name)
        return []


class CoreArchitectureTest(unittest.TestCase):
    def test_scope_blocks_private_hosts_by_default_and_allows_lab_mode(self):
        config = ScanConfig(target_url="http://127.0.0.1:5005", allow_private_ips=False)
        self.assertFalse(is_in_scope("http://127.0.0.1:5005/", config))
        self.assertFalse(is_in_scope("file:///etc/passwd", config))

        lab_config = ScanConfig(target_url="http://127.0.0.1:5005", allow_private_ips=True)
        self.assertTrue(is_in_scope("http://127.0.0.1:5005/", lab_config))

    def test_request_template_fingerprint_normalizes_url_and_payload_helpers(self):
        left = RequestTemplate(method="GET", url="https://example.test/search?b=2&a=1", params={"q": "test"})
        right = RequestTemplate(method="get", url="https://example.test/search?a=1&b=2", params={"q": "test"})

        self.assertEqual(left.fingerprint(), right.fingerprint())
        self.assertEqual(left.normalized_url(), "https://example.test/search?a=1&b=2")
        changed = left.with_param_payload("q", "<x>")
        self.assertEqual(changed.params["q"], "<x>")
        self.assertEqual(left.params["q"], "test")

    def test_form_extraction_preserves_real_controls(self):
        soup = BeautifulSoup(
            """
            <form method="post" action="/profile" enctype="multipart/form-data">
              <input type="hidden" name="csrf" value="abc">
              <input name="email" value="a@example.test">
              <input type="checkbox" name="subscribe" value="yes" checked>
              <input type="radio" name="role" value="user" checked>
              <input type="radio" name="role" value="admin">
              <select name="country"><option value="ru">RU</option><option value="us" selected>US</option></select>
              <textarea name="bio">hello</textarea>
              <input type="submit" name="ignored" value="Save">
              <input type="file" name="avatar">
            </form>
            """,
            "html.parser",
        )

        forms = extract_forms("https://example.test/settings", soup)

        self.assertEqual(len(forms), 1)
        form = forms[0]
        self.assertEqual(form.method, "POST")
        self.assertEqual(form.url, "https://example.test/profile")
        self.assertEqual(form.content_type, "multipart/form-data")
        self.assertEqual(form.data["csrf"], "abc")
        self.assertEqual(form.data["subscribe"], "yes")
        self.assertEqual(form.data["role"], "user")
        self.assertEqual(form.data["country"], "us")
        self.assertNotIn("ignored", form.data)
        self.assertNotIn("avatar", form.data)

    def test_js_endpoint_extractor_finds_modern_api_calls(self):
        js = """
        fetch('/api/users?active=true')
        axios.post("/v1/orders", {id: 1})
        const xhr = new XMLHttpRequest(); xhr.open('GET', '/graphql');
        $.ajax({ url: '/api/search.json', method: 'POST' });
        """

        endpoints = extract_js_endpoints("https://example.test/static/app.js", js)
        by_url = {template.url: template for template in endpoints}

        self.assertIn("https://example.test/api/users?active=true", by_url)
        self.assertIn("https://example.test/v1/orders", by_url)
        self.assertIn("https://example.test/graphql", by_url)
        self.assertEqual(by_url["https://example.test/v1/orders"].method, "POST")

    def test_open_redirect_parser_rejects_userinfo_host_trick(self):
        self.assertFalse(is_external_redirect("https://example.com@example.test/path", "example.test"))
        self.assertFalse(is_external_redirect("https://sub.example.test/path", "example.test"))
        self.assertTrue(is_external_redirect("https://example.com/path", "example.test"))
        self.assertTrue(is_external_redirect("//example.com/path", "example.test"))

    def test_exposure_rules_cover_required_paths_with_signatures_or_rationale(self):
        required = {
            "/.env.local",
            "/.git/HEAD",
            "/actuator/mappings",
            "/actuator/beans",
            "/actuator/loggers",
            "/actuator/threaddump",
            "/latest.sql",
            "/pnpm-lock.yaml",
        }
        rules = {rule.path: rule for rule in EXPOSURE_RULES}

        self.assertTrue(required.issubset(rules))
        for rule in rules.values():
            self.assertTrue(rule.signatures or rule.rationale, rule.path)

    def test_idor_without_second_auth_context_is_potential_not_confirmed_high(self):
        async def run_check():
            check = PotentialIDORCheck()
            template = RequestTemplate(
                method="GET",
                url="https://example.test/profile",
                params={"user_id": "1"},
            )
            return await check.run(template, FakeClient(), None, ScanConfig(target_url="https://example.test", mode="active"))

        findings = asyncio.run(run_check())

        self.assertEqual(len(findings), 1)
        self.assertIn("Potential", findings[0].title)
        self.assertNotIn(findings[0].severity, {"Critical", "High"})
        self.assertEqual(findings[0].confidence, "Low")

    def test_baseline_normalizes_dynamic_tokens(self):
        left = "<input name='csrf' value='abc123def456'> time=2026-04-29T12:00:01 uuid=123e4567-e89b-12d3-a456-426614174000"
        right = "<input name='csrf' value='fff999aaa888'> time=2026-04-29T12:00:59 uuid=987e6543-e21b-12d3-a456-426614174999"

        self.assertEqual(normalize_dynamic_body(left), normalize_dynamic_body(right))

    def test_scheduler_respects_budget_and_cancellation(self):
        async def run_scheduler():
            templates = [
                RequestTemplate(method="GET", url=f"https://example.test/item/{i}", source="test")
                for i in range(5)
            ]
            check = CountingCheck()
            config = ScanConfig(target_url="https://example.test", mode="active", max_requests_total=2)
            scheduler = ScanScheduler(config, [check], cancel_cb=lambda: False)
            await scheduler.run(templates, FakeClient())
            return check.calls

        self.assertEqual(asyncio.run(run_scheduler()), 2)

    def test_source_map_validation_requires_real_json_shape(self):
        self.assertTrue(is_valid_source_map('{"version":3,"sources":["app.ts"],"mappings":""}'))
        self.assertFalse(is_valid_source_map("<html>not json</html>"))


if __name__ == "__main__":
    unittest.main()
