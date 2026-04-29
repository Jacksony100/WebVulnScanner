import json
import tempfile
import unittest
from pathlib import Path

from app import UI_TOKEN, app, scan_state
from scanner.external_engines import ExternalEngineRunner, detect_external_engines


class FakeCompleted:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class ExternalEnginesTest(unittest.TestCase):
    def test_detect_external_engines_reports_available_and_missing_tools(self):
        def fake_which(name):
            return f"/tools/{name}" if name in {"nuclei", "katana"} else None

        engines = detect_external_engines(which_func=fake_which)
        by_name = {engine["name"]: engine for engine in engines}

        self.assertTrue(by_name["nuclei"]["available"])
        self.assertEqual(by_name["nuclei"]["path"], "/tools/nuclei")
        self.assertTrue(by_name["katana"]["available"])
        self.assertFalse(by_name["sslyze"]["available"])
        self.assertIn("web", by_name["nuclei"]["category"])

    def test_safe_mode_only_reports_status_without_running_external_commands(self):
        calls = []

        def fake_runner(command, timeout):
            calls.append(command)
            return FakeCompleted()

        runner = ExternalEngineRunner(
            "https://example.test",
            mode="safe",
            command_runner=fake_runner,
            which_func=lambda name: f"/tools/{name}",
        )

        findings, summary = runner.run()

        self.assertEqual(findings, [])
        self.assertEqual(calls, [])
        self.assertTrue(summary["engines"]["nuclei"]["available"])
        self.assertEqual(summary["mode"], "safe")

    def test_active_mode_runs_nuclei_and_converts_jsonl_to_findings(self):
        calls = []

        def fake_runner(command, timeout):
            calls.append((command, timeout))
            if command[0].endswith("nuclei"):
                stdout = json.dumps({
                    "template-id": "exposed-env",
                    "matched-at": "https://example.test/.env",
                    "info": {"name": "Exposed env file", "severity": "high"},
                }) + "\n"
                return FakeCompleted(stdout=stdout)
            return FakeCompleted()

        runner = ExternalEngineRunner(
            "https://example.test",
            mode="active",
            command_runner=fake_runner,
            which_func=lambda name: f"/tools/{name}" if name == "nuclei" else None,
        )

        findings, summary = runner.run()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "Nuclei: Exposed env file")
        self.assertEqual(findings[0]["url"], "https://example.test/.env")
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(findings[0]["payload"]["engine"], "nuclei")
        self.assertEqual(summary["results"]["nuclei"]["findings"], 1)
        nuclei_call = next(command for command, _ in calls if command[0].endswith("nuclei"))
        nuclei_timeout = next(timeout for command, timeout in calls if command[0].endswith("nuclei"))
        self.assertIn("-as", nuclei_call)
        self.assertIn("-etags", nuclei_call)
        self.assertLessEqual(nuclei_timeout, 45)

    def test_active_mode_skips_deep_only_engines(self):
        calls = []

        def fake_runner(command, timeout):
            calls.append(Path(command[0]).name)
            return FakeCompleted()

        runner = ExternalEngineRunner(
            "https://example.test",
            mode="active",
            command_runner=fake_runner,
            which_func=lambda name: f"/tools/{name}",
        )

        _, summary = runner.run()

        self.assertEqual(calls, ["nuclei", "katana"])
        self.assertEqual(summary["results"]["sslyze"]["status"], "deep-only")
        self.assertEqual(summary["results"]["retire"]["status"], "deep-only")
        self.assertEqual(summary["results"]["ffuf"]["status"], "deep-only")

    def test_external_engine_budget_skips_remaining_engines(self):
        calls = []
        clock = {"now": 0.0}

        def fake_time():
            return clock["now"]

        def fake_runner(command, timeout):
            calls.append((Path(command[0]).name, timeout))
            clock["now"] += timeout + 0.5
            return FakeCompleted()

        runner = ExternalEngineRunner(
            "https://example.test",
            mode="active",
            command_runner=fake_runner,
            which_func=lambda name: f"/tools/{name}",
            max_seconds=1,
            time_func=fake_time,
        )

        _, summary = runner.run()

        self.assertEqual([name for name, _ in calls], ["nuclei"])
        self.assertLessEqual(calls[0][1], 1)
        self.assertEqual(summary["results"]["katana"]["status"], "skipped-budget")

    def test_retire_scans_downloaded_scripts_from_a_temp_path(self):
        calls = []

        def fake_runner(command, timeout):
            calls.append(command)
            if command[0].endswith("retire"):
                output_path = Path(command[command.index("--outputpath") + 1])
                output_path.write_text(
                    json.dumps([{
                        "file": "jquery.js",
                        "component": "jquery",
                        "version": "1.8.0",
                        "vulnerabilities": [{"severity": "high", "summary": "old jquery"}],
                    }]),
                    encoding="utf-8",
                )
            return FakeCompleted()

        class RetireDownloadSession:
            def get(self, url, **kwargs):
                if url.endswith("/app.js"):
                    return FakeCompleted(stdout="", stderr="", returncode=0)  # unused
                return FakeCompleted()

        runner = ExternalEngineRunner(
            "https://example.test",
            mode="deep",
            command_runner=fake_runner,
            which_func=lambda name: f"/tools/{name}" if name == "retire" else None,
        )
        runner._download_homepage_scripts = lambda: {"jquery.js": "/*! jQuery v1.8.0 */"}

        findings, summary = runner.run()

        retire_call = next(command for command in calls if command[0].endswith("retire"))
        self.assertIn("--path", retire_call)
        self.assertIn("--outputpath", retire_call)
        self.assertEqual(findings[0]["type"], "Retire.js: jquery")
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(summary["results"]["retire"]["findings"], 1)

    def test_deep_mode_runs_ffuf_with_bundled_wordlist_and_parses_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            wordlist = Path(tmp) / "discovery.txt"
            wordlist.write_text("admin\nbackup.zip\n", encoding="utf-8")

            def fake_runner(command, timeout):
                if command[0].endswith("ffuf"):
                    output_path = Path(command[command.index("-o") + 1])
                    output_path.write_text(
                        json.dumps({
                            "results": [{
                                "url": "https://example.test/admin",
                                "status": 200,
                                "length": 1234,
                                "words": 42,
                            }]
                        }),
                        encoding="utf-8",
                    )
                    return FakeCompleted()
                return FakeCompleted()

            runner = ExternalEngineRunner(
                "https://example.test",
                mode="deep",
                command_runner=fake_runner,
                which_func=lambda name: f"/tools/{name}" if name == "ffuf" else None,
                wordlist_path=wordlist,
            )

            findings, summary = runner.run()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "FFUF Discovery")
        self.assertEqual(findings[0]["url"], "https://example.test/admin")
        self.assertEqual(findings[0]["payload"]["status"], 200)
        self.assertEqual(summary["results"]["ffuf"]["findings"], 1)


class ExternalEngineUiTest(unittest.TestCase):
    def tearDown(self):
        scan_state.update({
            "running": False,
            "cancel_requested": False,
            "progress": {"message": "Ожидание", "current": 0, "total": 1, "done": False},
            "results": [],
            "cms_info": {"cms": "Не определено", "version": "N/A"},
            "scan_info": {},
            "report_path": None,
        })

    def test_index_keeps_jacksony_credit_and_engines_endpoint_is_json(self):
        client = app.test_client()

        index_response = client.get("/")
        engines_response = client.get("/engines")

        self.assertEqual(index_response.status_code, 200)
        self.assertIn("Coded by Jacksony (t.me/Smesharik_lair)", index_response.get_data(as_text=True))
        self.assertEqual(engines_response.status_code, 200)
        self.assertIn("engines", engines_response.get_json())

    def test_cancel_scan_sets_cancel_request_and_keeps_worker_running(self):
        client = app.test_client()
        scan_state.update({
            "running": True,
            "cancel_requested": False,
            "progress": {"message": "Внешние движки", "current": 2, "total": 22, "done": False},
        })

        response = client.post("/cancel_scan", headers={"X-Advscan-Token": UI_TOKEN})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "cancelling")
        self.assertTrue(scan_state["running"])
        self.assertTrue(scan_state["cancel_requested"])
        self.assertEqual(scan_state["progress"]["message"], "Останавливаю сканирование...")


if __name__ == "__main__":
    unittest.main()
