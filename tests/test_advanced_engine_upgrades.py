import asyncio
import tempfile
import unittest
from pathlib import Path

from scanner.core.async_engine import AsyncScanEngine
from scanner.core.deep_state import build_storage_mutation_plan
from scanner.modules.taint_analyzer import TaintAnalyzer, esprima
from scanner.utils.response_intelligence import ResponseIntelligenceAgent


class AdvancedEngineUpgradeTests(unittest.TestCase):
    def test_async_engine_sync_wrapper_runs_inside_existing_event_loop(self):
        class _AsyncScanner:
            async def scan_url_async(self, url, params, http):
                return [{"type": "xss-reflected", "param": "id", "severity": "High"}]

        async def runner():
            engine = AsyncScanEngine(max_concurrent=2, timeout=2)
            return engine.scan_urls_sync(
                [("http://example.test/users", {"id": "1"})],
                [_AsyncScanner()],
            )

        findings = asyncio.run(runner())

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["url"], "http://example.test/users")
        self.assertEqual(findings[0]["type"], "xss-reflected")

    def test_deep_state_plan_flips_privileged_storage_and_roles(self):
        snapshot = {
            "localStorage": {
                "appState": '{"isAdmin":false,"role":"user","wizardStep":0}',
            },
            "sessionStorage": {
                "featureFlags": '{"betaAccess":"false"}',
            },
            "indexedDB": [],
        }

        plan = build_storage_mutation_plan(snapshot)

        self.assertTrue(plan["mutations"])
        self.assertIn("appState", plan["localStorage"])
        self.assertIn('"isAdmin":true', plan["localStorage"]["appState"])
        self.assertIn('"role":"admin"', plan["localStorage"]["appState"])

    def test_response_intelligence_retries_on_block_pages(self):
        agent = ResponseIntelligenceAgent()
        analysis = agent.analyze_response(
            family="xss",
            payload='<script>alert("X1")</script>',
            marker="X1",
            status_code=403,
            text="Attention Required! Cloudflare Ray ID blocked your request",
            headers={"Server": "cloudflare", "CF-Ray": "abc"},
            reflection_context="html-body",
        )

        mutations = agent.generate_mutations(
            family="xss",
            payload='<script>alert("X1")</script>',
            marker="X1",
            analysis=analysis,
            max_variants=4,
        )

        self.assertTrue(agent.should_retry(analysis))
        self.assertEqual(analysis["outcome"], "waf-block")
        self.assertGreaterEqual(len(mutations), 2)

    def test_python_cross_file_taint_analysis_finds_route_to_query_sink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            (repo / "routes.py").write_text(
                "\n".join(
                    [
                        "from service import lookup_user",
                        "from fakeframework import app",
                        "",
                        "@app.get('/users')",
                        "def users(request):",
                        "    user_id = request.args.get('id')",
                        "    return lookup_user(user_id)",
                    ]
                ),
                encoding="utf-8",
            )
            (repo / "service.py").write_text(
                "\n".join(
                    [
                        "from repository import fetch_user",
                        "",
                        "def lookup_user(user_id):",
                        "    return fetch_user(user_id)",
                    ]
                ),
                encoding="utf-8",
            )
            (repo / "repository.py").write_text(
                "\n".join(
                    [
                        "def fetch_user(user_id):",
                        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"",
                        "    return db.execute(query)",
                    ]
                ),
                encoding="utf-8",
            )

            file_tree = {
                "python": [str(repo / "routes.py"), str(repo / "service.py"), str(repo / "repository.py")],
                "javascript": [],
                "all": [str(repo / "routes.py"), str(repo / "service.py"), str(repo / "repository.py")],
            }
            findings = TaintAnalyzer().scan_repo(str(repo), file_tree, {"primary_language": "python"})

        self.assertTrue(findings)
        self.assertTrue(any(finding["type"] == "sqli" for finding in findings))
        self.assertTrue(any("routes.py" in finding["evidence"] for finding in findings))
        self.assertTrue(any("repository.py" in finding["evidence"] for finding in findings))

    def test_javascript_cross_file_taint_analysis_finds_route_to_query_sink(self):
        if esprima is None:
            self.skipTest("esprima is not installed in this environment")

        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            (repo / "routes.js").write_text(
                "\n".join(
                    [
                        "const { loadUser } = require('./service');",
                        "router.get('/users', (req, res) => {",
                        "  const id = req.query.id;",
                        "  return loadUser(id);",
                        "});",
                    ]
                ),
                encoding="utf-8",
            )
            (repo / "service.js").write_text(
                "\n".join(
                    [
                        "function loadUser(id) {",
                        "  return db.query(`SELECT * FROM users WHERE id = ${id}`);",
                        "}",
                        "module.exports = { loadUser };",
                    ]
                ),
                encoding="utf-8",
            )

            file_tree = {
                "python": [],
                "javascript": [str(repo / "routes.js"), str(repo / "service.js")],
                "all": [str(repo / "routes.js"), str(repo / "service.js")],
            }
            findings = TaintAnalyzer().scan_repo(str(repo), file_tree, {"primary_language": "javascript"})

        self.assertTrue(findings)
        self.assertTrue(any(finding["type"] == "sqli" for finding in findings))


if __name__ == "__main__":
    unittest.main()
