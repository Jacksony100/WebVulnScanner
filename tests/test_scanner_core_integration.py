import asyncio
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from scanner.scanner import VulnerabilityScanner


class FakeTargetHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send(self, body, status=200, content_type="text/html", headers=None):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/":
            self._send(
                """
                <html><head><title>Lab</title><script src="/static/app.js"></script></head>
                <body>
                  <a href="/search?q=hello&id=1">Search</a>
                  <form method="post" action="/submit"><input name="name" value="alice"></form>
                </body></html>
                """
            )
        elif parsed.path == "/static/app.js":
            self._send(
                "fetch('/api/echo?q=hello'); axios.get('/api/sql?q=1');\n//# sourceMappingURL=app.js.map",
                content_type="application/javascript",
            )
        elif parsed.path == "/static/app.js.map":
            self._send('{"version":3,"sources":["app.ts"],"mappings":""}', content_type="application/json")
        elif parsed.path == "/sitemap.xml":
            host = f"http://{self.headers['Host']}"
            self._send(f"<urlset><url><loc>{host}/redirect?next=/</loc></url></urlset>", content_type="application/xml")
        elif parsed.path == "/robots.txt":
            self._send("Disallow: /admin\nAllow: /api/echo\n", content_type="text/plain")
        elif parsed.path == "/openapi.json":
            self._send(
                json.dumps({
                    "openapi": "3.0.0",
                    "paths": {
                        "/api/echo": {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}},
                        "/api/sql": {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}},
                    },
                }),
                content_type="application/json",
            )
        elif parsed.path == "/api/echo":
            self._send(f"echo {(qs.get('q') or [''])[0]}")
        elif parsed.path == "/api/sql":
            value = (qs.get("q") or [""])[0]
            if "'" in value or '"' in value:
                self._send("You have an error in your SQL syntax", status=500)
            else:
                self._send("ok")
        elif parsed.path == "/redirect":
            location = (qs.get("next") or ["/"])[0]
            self._send("", status=302, headers={"Location": location})
        elif parsed.path == "/admin":
            self._send("admin area", status=403)
        else:
            self._send("not found", status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/graphql":
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length).decode("utf-8", errors="ignore")
            if "__schema" in body:
                self._send('{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}', content_type="application/json")
            else:
                self._send('{"data":{"__typename":"Query"}}', content_type="application/json")
        elif parsed.path == "/submit":
            self._send("saved")
        else:
            self._send("not found", status=404)


class ScannerCoreIntegrationTest(unittest.TestCase):
    def test_scanner_discovers_modern_surface_and_runs_template_checks(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeTargetHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            scanner = VulnerabilityScanner(
                target,
                threads=4,
                scan_mode="active",
                allow_private_ips=True,
                enable_external_tools=False,
                max_requests_total=180,
                rate_limit_per_host=80,
            )
            findings = asyncio.run(scanner.run())
        finally:
            server.shutdown()
            server.server_close()

        titles = {finding["type"] for finding in findings}
        scan_info = scanner.get_scan_info()

        self.assertGreaterEqual(scan_info["request_templates_total"], 5)
        self.assertGreaterEqual(scan_info["forms_total"], 1)
        self.assertIn("Reflected input", titles)
        self.assertIn("SQL Injection (error-based)", titles)
        self.assertIn("Open Redirect", titles)
        self.assertTrue(any(asset.get("type") == "openapi" for asset in scan_info.get("assets", [])))
        self.assertIn("GraphQL introspection enabled", titles)
        self.assertIn("Source Map Disclosure", titles)
        for finding in findings:
            self.assertIn(finding.get("confidence"), {"High", "Medium", "Low"})
            self.assertNotIn("confirmed IDOR", finding.get("title", "").lower())

    def test_common_graphql_candidates_are_not_findings_when_404(self):
        class GraphQL404Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                self.send_response(200 if self.path == "/" else 404)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><title>Static lab</title></html>" if self.path == "/" else b"not found")

            def do_POST(self):
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"not found")

        server = ThreadingHTTPServer(("127.0.0.1", 0), GraphQL404Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            scanner = VulnerabilityScanner(
                target,
                threads=2,
                scan_mode="safe",
                allow_private_ips=True,
                enable_external_tools=False,
                max_requests_total=40,
                rate_limit_per_host=200,
            )
            findings = asyncio.run(scanner.run())
        finally:
            server.shutdown()
            server.server_close()

        titles = {finding["title"] for finding in findings}
        info = scanner.get_scan_info()
        self.assertNotIn("GraphQL endpoint discovered", titles)
        self.assertTrue(any("graphql" in candidate["url"] for candidate in info.get("discovery_candidates", [])))
        self.assertFalse(any(asset.get("type") == "graphql" for asset in info.get("assets", [])))

    def test_valid_graphql_is_asset_and_introspection_is_confirmed_finding(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeTargetHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            scanner = VulnerabilityScanner(
                target,
                threads=2,
                scan_mode="active",
                allow_private_ips=True,
                enable_external_tools=False,
                max_requests_total=100,
                rate_limit_per_host=200,
            )
            findings = asyncio.run(scanner.run())
        finally:
            server.shutdown()
            server.server_close()

        titles = {finding["title"] for finding in findings}
        info = scanner.get_scan_info()
        self.assertIn("GraphQL introspection enabled", titles)
        self.assertNotIn("GraphQL endpoint discovered", titles)
        self.assertTrue(any(asset.get("type") == "graphql" for asset in info.get("assets", [])))

    def test_site_profile_includes_headers_and_response_time(self):
        class ProfileHandler(BaseHTTPRequestHandler):
            server_version = "UnitTestServer"
            sys_version = ""

            def log_message(self, format, *args):
                return

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("X-Powered-By", "Express")
                self.end_headers()
                self.wfile.write(b"<html><head><title>Profile Lab</title></head></html>")

        server = ThreadingHTTPServer(("127.0.0.1", 0), ProfileHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            scanner = VulnerabilityScanner(
                target,
                threads=2,
                scan_mode="safe",
                allow_private_ips=True,
                enable_external_tools=False,
                max_requests_total=40,
                rate_limit_per_host=200,
            )
            asyncio.run(scanner.run())
        finally:
            server.shutdown()
            server.server_close()

        info = scanner.get_scan_info()
        self.assertEqual(info["status_code"], 200)
        self.assertIn("UnitTestServer", info["server"])
        self.assertEqual(info["powered_by"], "Express")
        self.assertEqual(info["title"], "Profile Lab")
        self.assertIsNotNone(info["response_time_ms"])
        self.assertIn("Express", info["technologies"])


if __name__ == "__main__":
    unittest.main()
