import unittest

from bs4 import BeautifulSoup

from scanner.checkers import (
    CRLFInjectionChecker,
    LDAPInjectionChecker,
    NoSQLChecker,
    OpenRedirectChecker,
    OSCommandChecker,
    PrototypePollutionChecker,
    SQLIChecker,
    SSTIChecker,
    XSSChecker,
    XPathInjectionChecker,
)
from scanner.crawler import Crawler
from scanner.payloads import (
    COMMON_EXPOSURE_PATHS,
    CRLF_PAYLOADS,
    FUZZ_PARAMS,
    GRAPHQL_PATHS,
    HEADER_FUZZ_PAYLOADS,
    LDAP_PAYLOADS,
    LFI_RFI_PAYLOADS,
    NOSQL_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    PROTOTYPE_POLLUTION_PAYLOADS,
    SSRF_PAYLOADS,
    SOURCE_MAP_CANDIDATES,
    SQLI_PAYLOADS,
    SSTI_PAYLOADS,
    XSS_PAYLOADS,
    XPATH_PAYLOADS,
)
from scanner.scanner import VulnerabilityScanner
from scanner.utils import normalize_target_url


class FakeResponse:
    def __init__(self, text="", headers=None, status_code=200, url="http://example.test", cookies=None):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code
        self.url = url
        self.cookies = cookies or []


class FakeSession:
    def get(self, *args, **kwargs):
        return FakeResponse()

    def options(self, *args, **kwargs):
        return FakeResponse(headers={"Allow": "GET, POST"})


class EchoSession:
    def get(self, url, params=None, **kwargs):
        return FakeResponse(text=params.get("q", ""))


class SqlErrorSession:
    def get(self, url, params=None, **kwargs):
        value = " ".join(str(v) for v in (params or {}).values())
        if "'" in value or '"' in value:
            return FakeResponse(text="You have an error in your SQL syntax")
        return FakeResponse(text="ok")


class BooleanSqlSession:
    def get(self, url, params=None, **kwargs):
        value = " ".join(str(v) for v in (params or {}).values())
        if "1=2" in value or "2>3" in value:
            return FakeResponse(text="No rows " + ("B" * 120))
        if "1=1" in value or "2>1" in value:
            return FakeResponse(text="Welcome " + ("A" * 1200))
        return FakeResponse(text="Welcome " + ("A" * 1200))


class SstiSession:
    def get(self, url, params=None, **kwargs):
        value = " ".join(str(v) for v in (params or {}).values())
        if "{{7331*3}}" in value:
            return FakeResponse(text="Rendered value: 21993")
        return FakeResponse(text="Rendered value: test")


class NoSqlErrorSession:
    def get(self, url, params=None, **kwargs):
        value = " ".join(str(v) for v in (params or {}).values())
        if "$ne" in value:
            return FakeResponse(text="MongoError: unknown operator $ne")
        return FakeResponse(text="ok")


class CrlfSession:
    def get(self, url, params=None, **kwargs):
        value = " ".join(str(v) for v in (params or {}).values())
        if "X-Advscan-CRLF" in value:
            return FakeResponse(headers={"X-Advscan-CRLF": "1"})
        return FakeResponse(text="ok")


class LdapErrorSession:
    def get(self, url, params=None, **kwargs):
        value = " ".join(str(v) for v in (params or {}).values())
        if "*" in value or ")(" in value:
            return FakeResponse(text="LDAPException: invalid DN syntax")
        return FakeResponse(text="ok")


class XPathErrorSession:
    def get(self, url, params=None, **kwargs):
        value = " ".join(str(v) for v in (params or {}).values())
        if " or " in value or "//*" in value:
            return FakeResponse(text="XPathException: invalid XPath expression")
        return FakeResponse(text="ok")


class PrototypeSession:
    def get(self, url, params=None, **kwargs):
        keys = set((params or {}).keys())
        if any("__proto__" in key or "constructor[prototype]" in key for key in keys):
            return FakeResponse(text='{"advscan_proto":"ADVSCAN_PROTO_POLLUTED"}')
        return FakeResponse(text="ok")


class OpenRedirectSession:
    def get(self, url, params=None, **kwargs):
        location = next(iter((params or {}).values()), "")
        return FakeResponse(status_code=303, headers={"Location": location})


class PlainIdSession:
    def get(self, url, params=None, **kwargs):
        return FakeResponse(text="profile id card with echo label")


class ExposureSession:
    def get(self, url, **kwargs):
        if "__advscan_missing" in url:
            return FakeResponse(text="not found", status_code=404, url=url)
        if url.endswith("/.git/config"):
            return FakeResponse(
                text="[core]\nrepositoryformatversion = 0\n[remote \"origin\"]",
                headers={"Content-Type": "text/plain"},
                url=url,
            )
        return FakeResponse(text="not found", status_code=404, url=url)

    def options(self, *args, **kwargs):
        return FakeResponse(headers={"Allow": "GET, POST"})


class WeakHeaderSession:
    def get(self, url, **kwargs):
        return FakeResponse(
            text="<html><title>ok</title></html>",
            headers={
                "Content-Security-Policy": "default-src * 'unsafe-inline' http:",
                "Strict-Transport-Security": "max-age=100",
                "Referrer-Policy": "unsafe-url",
            },
            url="https://example.test",
        )

    def options(self, *args, **kwargs):
        return FakeResponse(headers={"Allow": "GET, POST"})


class CorsReflectionSession:
    def get(self, url, headers=None, **kwargs):
        origin = (headers or {}).get("Origin", "")
        if origin:
            return FakeResponse(
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
                url=url,
            )
        return FakeResponse(url=url)


class GraphQLSession:
    def post(self, url, json=None, **kwargs):
        if "graphql" in url and "__schema" in (json or {}).get("query", ""):
            return FakeResponse(text='{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}', url=url)
        return FakeResponse(status_code=404, url=url)


class ScriptSecretSession:
    def get(self, url, **kwargs):
        if url.endswith("/app.js"):
            return FakeResponse(
                text="const access_token = 'abcdefghijklmnopqrstuvwxyz1234567890';",
                headers={"Content-Type": "application/javascript"},
                url=url,
            )
        return FakeResponse(text="<script src='/app.js'></script>", url=url)


class SourceMapSession:
    def get(self, url, **kwargs):
        if url.endswith("/app.js"):
            return FakeResponse(
                text="console.log('ok');\n//# sourceMappingURL=app.js.map",
                headers={"Content-Type": "application/javascript"},
                url=url,
            )
        if url.endswith("/app.js.map"):
            return FakeResponse(
                text='{"version":3,"sources":["app.ts"],"sourcesContent":["const api_key = '
                     '\'abcdefghijklmnopqrstuvwxyz1234567890\';"],"mappings":""}',
                headers={"Content-Type": "application/json"},
                url=url,
            )
        return FakeResponse(text="not found", status_code=404, url=url)


class CommonSourceMapSession:
    def get(self, url, **kwargs):
        if url.endswith("/static/js/main.js.map"):
            return FakeResponse(
                text='{"version":3,"sources":["main.ts"],"sourcesContent":["console.log(1)"],"mappings":""}',
                headers={"Content-Type": "application/json"},
                url=url,
            )
        return FakeResponse(text="not found", status_code=404, url=url)


class ConfigExposureSession:
    def get(self, url, **kwargs):
        if "__advscan_missing" in url:
            return FakeResponse(text="not found", status_code=404, url=url)
        if url.endswith("/application.properties"):
            return FakeResponse(
                text="spring.datasource.password=secret\nspring.datasource.url=jdbc:postgresql://db/app",
                headers={"Content-Type": "text/plain"},
                url=url,
            )
        return FakeResponse(text="not found", status_code=404, url=url)


class DebugExposureSession:
    def get(self, url, **kwargs):
        if "__advscan_missing" in url:
            return FakeResponse(text="not found", status_code=404, url=url)
        if url.endswith("/_profiler"):
            return FakeResponse(
                text="<html>Symfony Profiler profile token</html>",
                headers={"Content-Type": "text/html"},
                url=url,
            )
        return FakeResponse(text="not found", status_code=404, url=url)


class Soft404ExposureSession:
    def get(self, url, **kwargs):
        return FakeResponse(text="custom not found page", status_code=200, url=url)


class GenericFuzzSession:
    def get(self, url, params=None, **kwargs):
        value = " ".join(str(v) for v in (params or {}).values())
        if "{{7331*3}}" in value:
            return FakeResponse(text="Rendered 21993")
        if "$ne" in value:
            return FakeResponse(text="MongoError: unknown top level operator")
        if "*)(&" in value:
            return FakeResponse(text="LDAPException: invalid search filter")
        if " or " in value:
            return FakeResponse(text="XPathException: invalid XPath")
        if "CRLF" in value:
            return FakeResponse(headers={"X-Advscan-CRLF": "1"}, text="")
        if "__proto__" in value:
            return FakeResponse(text="ADVSCAN_PROTO_POLLUTED")
        return FakeResponse(text="ok")


class HeaderFuzzSession:
    def get(self, url, params=None, headers=None, **kwargs):
        header_text = " ".join(str(v) for v in (headers or {}).values())
        if "window.xssFlag" in header_text:
            return FakeResponse(text="<script>window.xssFlag=1</script>")
        if "' OR '1'='1" in header_text:
            return FakeResponse(text="You have an error in your SQL syntax")
        return FakeResponse(text="ok")


class FakeSourceMapSession:
    def get(self, url, **kwargs):
        return FakeResponse(
            text="<html>not actually a source map</html>",
            headers={"Content-Type": "text/html"},
            url=url,
        )


class ScannerBasicsTest(unittest.TestCase):
    def test_normalize_target_url_adds_scheme_and_drops_fragment(self):
        self.assertEqual(
            normalize_target_url("example.com/path/#section"),
            "https://example.com/path",
        )

    def test_normalize_target_url_rejects_non_http_schemes(self):
        with self.assertRaises(ValueError):
            normalize_target_url("file:///etc/passwd")

    def test_csrf_finding_keeps_evidence_payload(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1)
        try:
            soup = BeautifulSoup(
                '<form method="post" action="/profile"><input name="email"></form>',
                "html.parser",
            )
            vulns = scanner._check_csrf_forms("https://example.test/settings", soup)
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["type"], "CSRF")
        self.assertEqual(vulns[0]["payload"]["issue"], "missing CSRF token")
        self.assertEqual(vulns[0]["payload"]["form_action"], "https://example.test/profile")

    def test_passive_baseline_reports_missing_headers(self):
        scanner = VulnerabilityScanner("http://example.test", threads=1)
        try:
            scanner.session = FakeSession()
            vulns = scanner._check_passive_baseline()
        finally:
            scanner.executor.shutdown(wait=False)

        vuln_types = {v["type"] for v in vulns}
        self.assertIn("Unencrypted connection", vuln_types)
        self.assertIn("Missing Security Header: Content-Security-Policy", vuln_types)

    def test_query_targets_are_collected_for_active_checks(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="active")
        try:
            pages = [
                ("https://example.test/search?q=test&id=1", BeautifulSoup("", "html.parser")),
                ("https://example.test/search?q=test&id=1", BeautifulSoup("", "html.parser")),
            ]
            targets = scanner._collect_query_targets(pages)
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(targets, [("https://example.test/search", {"q": "test", "id": "1"})])

    def test_xss_checker_detects_raw_reflection(self):
        vulns = XSSChecker(EchoSession()).test("https://example.test/search", {"q": "test"}, "get")

        self.assertTrue(vulns)
        self.assertEqual(vulns[0]["type"], "XSS")
        self.assertEqual(vulns[0]["parameter"], "q")

    def test_sqli_checker_detects_error_signature(self):
        vulns = SQLIChecker(SqlErrorSession()).test("https://example.test/login", {"username": "test"}, "get")

        self.assertTrue(vulns)
        self.assertIn("SQL Injection", vulns[0]["type"])
        self.assertEqual(vulns[0]["parameter"], "username")

    def test_sqli_checker_detects_boolean_differential(self):
        vulns = SQLIChecker(BooleanSqlSession()).test("https://example.test/search", {"id": "1"}, "get")

        self.assertTrue(vulns)
        self.assertIn("boolean differential", vulns[0]["type"])
        self.assertEqual(vulns[0]["parameter"], "id")

    def test_ssti_checker_detects_evaluated_template_marker(self):
        vulns = SSTIChecker(SstiSession()).test("https://example.test/render", {"name": "test"}, "get")

        self.assertTrue(vulns)
        self.assertEqual(vulns[0]["type"], "Server-Side Template Injection")
        self.assertEqual(vulns[0]["parameter"], "name")

    def test_nosql_checker_detects_error_signature(self):
        vulns = NoSQLChecker(NoSqlErrorSession()).test("https://example.test/login", {"username": "test"}, "get")

        self.assertTrue(vulns)
        self.assertEqual(vulns[0]["type"], "NoSQL Injection")
        self.assertEqual(vulns[0]["parameter"], "username")

    def test_crlf_checker_detects_response_header_marker(self):
        vulns = CRLFInjectionChecker(CrlfSession()).test("https://example.test/redirect", {"next": "/"}, "get")

        self.assertTrue(vulns)
        self.assertEqual(vulns[0]["type"], "CRLF Injection")
        self.assertEqual(vulns[0]["parameter"], "next")

    def test_ldap_checker_detects_parser_error(self):
        vulns = LDAPInjectionChecker(LdapErrorSession()).test("https://example.test/login", {"user": "test"}, "get")

        self.assertTrue(vulns)
        self.assertEqual(vulns[0]["type"], "LDAP Injection")
        self.assertEqual(vulns[0]["parameter"], "user")

    def test_xpath_checker_detects_parser_error(self):
        vulns = XPathInjectionChecker(XPathErrorSession()).test("https://example.test/xml", {"q": "test"}, "get")

        self.assertTrue(vulns)
        self.assertEqual(vulns[0]["type"], "XPath Injection")
        self.assertEqual(vulns[0]["parameter"], "q")

    def test_prototype_pollution_checker_detects_marker(self):
        vulns = PrototypePollutionChecker(PrototypeSession()).test("https://example.test/api", {"name": "test"}, "get")

        self.assertTrue(vulns)
        self.assertEqual(vulns[0]["type"], "Prototype Pollution")
        self.assertTrue("__proto__" in vulns[0]["parameter"] or "prototype" in vulns[0]["parameter"])

    def test_open_redirect_checker_accepts_303_redirect(self):
        vulns = OpenRedirectChecker(OpenRedirectSession()).test(
            "https://example.test/login",
            {"next": "/"},
            "get",
        )

        self.assertTrue(vulns)
        self.assertEqual(vulns[0]["type"], "Open Redirect")

    def test_os_command_checker_ignores_plain_id_text_without_command_marker(self):
        vulns = OSCommandChecker(PlainIdSession()).test("https://example.test/search", {"q": "test"}, "get")

        self.assertEqual(vulns, [])

    def test_sensitive_pattern_detection_redacts_secret(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1)
        try:
            body = "window.token='ghp_abcdefghijklmnopqrstuvwxyz1234567890';"
            vulns = scanner._check_sensitive_patterns("https://example.test", body)
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["type"], "Information Disclosure: GitHub Token")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", vulns[0]["payload"]["evidence"])

    def test_common_exposure_detects_git_config(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="active")
        try:
            scanner.session = ExposureSession()
            vulns = scanner._check_common_exposures()
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["type"], "Sensitive File/Dir Found")
        self.assertEqual(vulns[0]["payload"]["path"], "/.git/config")

    def test_weak_security_headers_are_reported(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1)
        try:
            scanner.session = WeakHeaderSession()
            vulns = scanner._check_passive_baseline()
        finally:
            scanner.executor.shutdown(wait=False)

        vuln_types = {v["type"] for v in vulns}
        self.assertIn("Weak Security Header: Content-Security-Policy", vuln_types)
        self.assertIn("Weak Security Header: Strict-Transport-Security", vuln_types)
        self.assertIn("Weak Security Header: Referrer-Policy", vuln_types)

    def test_cors_origin_reflection_is_reported(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="active")
        try:
            scanner.session = CorsReflectionSession()
            vulns = scanner._check_cors_origin_reflection()
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["type"], "Permissive CORS")
        self.assertIn("credentials allowed", vulns[0]["payload"]["issues"])

    def test_graphql_introspection_detects_open_schema(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="deep")
        try:
            scanner.session = GraphQLSession()
            vulns = scanner._check_graphql_introspection()
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["type"], "GraphQL Introspection")
        self.assertTrue(vulns[0]["url"].endswith("/graphql"))

    def test_linked_script_secret_scan_redacts_secret(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1)
        try:
            scanner.session = ScriptSecretSession()
            pages = [("https://example.test", BeautifulSoup("<script src='/app.js'></script>", "html.parser"))]
            vulns = scanner._check_linked_script_secrets(pages)
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["type"], "Information Disclosure: Access Token")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", vulns[0]["payload"]["evidence"])

    def test_linked_script_source_map_is_reported_and_scanned(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1)
        try:
            scanner.session = SourceMapSession()
            pages = [("https://example.test", BeautifulSoup("<script src='/app.js'></script>", "html.parser"))]
            vulns = scanner._check_linked_script_secrets(pages)
        finally:
            scanner.executor.shutdown(wait=False)

        vuln_types = {v["type"] for v in vulns}
        self.assertIn("Source Map Disclosure", vuln_types)
        self.assertIn("Information Disclosure: Generic API Key", vuln_types)

    def test_common_source_map_candidates_are_checked_in_deep_mode(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="deep")
        try:
            scanner.session = CommonSourceMapSession()
            vulns = scanner._check_common_source_maps()
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["type"], "Source Map Disclosure")
        self.assertTrue(vulns[0]["url"].endswith("/static/js/main.js.map"))

    def test_common_exposure_detects_application_properties(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="active")
        try:
            scanner.session = ConfigExposureSession()
            vulns = scanner._check_common_exposures()
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["payload"]["path"], "/application.properties")

    def test_common_exposure_detects_debug_profiler(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="active")
        try:
            scanner.session = DebugExposureSession()
            vulns = scanner._check_common_exposures()
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["payload"]["path"], "/_profiler")

    def test_common_exposure_ignores_soft_404_responses(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="active")
        try:
            scanner.session = Soft404ExposureSession()
            vulns = scanner._check_common_exposures()
        finally:
            scanner.executor.shutdown(wait=False)

        self.assertEqual(vulns, [])

    def test_generic_fuzz_detects_new_deep_families(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="deep")
        try:
            scanner.session = GenericFuzzSession()
            vulns = scanner._generic_fuzz("https://example.test/search", {"q": "test"}, "get")
        finally:
            scanner.executor.shutdown(wait=False)

        vuln_types = {v["type"] for v in vulns}
        self.assertIn("Server-Side Template Injection", vuln_types)
        self.assertIn("NoSQL Injection", vuln_types)
        self.assertIn("LDAP Injection", vuln_types)
        self.assertIn("XPath Injection", vuln_types)
        self.assertIn("CRLF Injection", vuln_types)
        self.assertIn("Prototype Pollution", vuln_types)

    def test_header_fuzz_still_finds_xss_and_sqli(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="deep")
        try:
            scanner.session = HeaderFuzzSession()
            vulns = scanner._header_fuzz("https://example.test/search", {"q": "test"}, "get")
        finally:
            scanner.executor.shutdown(wait=False)

        vuln_types = {v["type"] for v in vulns}
        self.assertIn("XSS (header fuzz)", vuln_types)
        self.assertIn("SQL Injection (header fuzz)", vuln_types)

    def test_open_redirect_detects_backslash_normalized_location(self):
        checker = OpenRedirectChecker(OpenRedirectSession())

        self.assertTrue(checker._looks_external_redirect("/\\example.com"))
        self.assertTrue(checker._looks_external_redirect("///%5cexample.com"))
        self.assertFalse(checker._looks_external_redirect("https://example.com@example.test"))

    def test_fake_source_map_response_is_ignored(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1, scan_mode="deep")
        try:
            scanner.session = FakeSourceMapSession()
            self.assertIsNone(scanner._fetch_source_map("https://example.test/main.js.map"))
        finally:
            scanner.executor.shutdown(wait=False)

    def test_secret_patterns_cover_frontend_service_leaks(self):
        scanner = VulnerabilityScanner("https://example.test", threads=1)
        try:
            body = (
                "const firebase='https://demo.firebaseio.com';"
                "const dsn='https://0123456789abcdef0123456789abcdef@o1.ingest.sentry.io/123';"
            )
            vulns = scanner._check_sensitive_patterns("https://example.test/app.js", body)
        finally:
            scanner.executor.shutdown(wait=False)

        vuln_types = {v["type"] for v in vulns}
        self.assertIn("Information Disclosure: Firebase URL", vuln_types)
        self.assertIn("Information Disclosure: Sentry DSN", vuln_types)

    def test_payload_lists_do_not_have_duplicates(self):
        scalar_lists = [
            XSS_PAYLOADS,
            SQLI_PAYLOADS,
            NOSQL_PAYLOADS,
            LDAP_PAYLOADS,
            XPATH_PAYLOADS,
            PATH_TRAVERSAL_PAYLOADS,
            SSRF_PAYLOADS,
            OPEN_REDIRECT_PAYLOADS,
            CRLF_PAYLOADS,
            HEADER_FUZZ_PAYLOADS,
            FUZZ_PARAMS,
            COMMON_EXPOSURE_PATHS,
            GRAPHQL_PATHS,
            SOURCE_MAP_CANDIDATES,
        ]
        for payloads in scalar_lists:
            self.assertEqual(len(payloads), len(set(payloads)))
        self.assertEqual(len(PROTOTYPE_POLLUTION_PAYLOADS), len(set(PROTOTYPE_POLLUTION_PAYLOADS)))

    def test_payload_libraries_have_deeper_coverage(self):
        self.assertGreaterEqual(len(XSS_PAYLOADS), 40)
        self.assertGreaterEqual(len(SQLI_PAYLOADS), 45)
        self.assertGreaterEqual(len(SSTI_PAYLOADS), 12)
        self.assertGreaterEqual(len(NOSQL_PAYLOADS), 20)
        self.assertGreaterEqual(len(LDAP_PAYLOADS), 10)
        self.assertGreaterEqual(len(XPATH_PAYLOADS), 10)
        self.assertGreaterEqual(len(PROTOTYPE_POLLUTION_PAYLOADS), 7)
        self.assertGreaterEqual(len(OPEN_REDIRECT_PAYLOADS), 15)
        unsafe_fragments = ["; id", "whoami", "/etc/passwd", "php://filter", "file://", "169.254.169.254"]
        active_payloads = PATH_TRAVERSAL_PAYLOADS + LFI_RFI_PAYLOADS + SSRF_PAYLOADS + HEADER_FUZZ_PAYLOADS + FUZZ_PARAMS
        for payload in active_payloads:
            self.assertFalse(any(fragment in payload for fragment in unsafe_fragments), payload)
        self.assertIn("/actuator/configprops", COMMON_EXPOSURE_PATHS)
        self.assertIn("/application.properties", COMMON_EXPOSURE_PATHS)
        self.assertIn("/static/js/main.js.map", SOURCE_MAP_CANDIDATES)
        self.assertIn("/api/graphql", GRAPHQL_PATHS)

    def test_crawler_next_batch_drops_already_visited_urls(self):
        crawler = Crawler("https://example.test", concurrent=2)
        crawler.to_visit = {"https://example.test", "https://example.test/about"}
        crawler.visited = {"https://example.test"}

        batch = crawler._next_batch()

        self.assertEqual(batch, ["https://example.test/about"])
        self.assertEqual(crawler.to_visit, set())

    def test_crawler_normalizes_links_and_skips_non_http(self):
        crawler = Crawler("https://example.test")

        self.assertEqual(
            crawler._normalize_link("https://example.test/a/", "../b/#frag"),
            "https://example.test/b",
        )
        self.assertIsNone(crawler._normalize_link("https://example.test", "javascript:alert(1)"))


if __name__ == "__main__":
    unittest.main()
