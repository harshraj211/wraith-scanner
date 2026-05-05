import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from scanner.core.models import ScanConfig
from scanner.core.sequence_runner import load_sequence_workflows, run_sequence_workflows
from scanner.storage.repository import StorageRepository


@contextmanager
def run_app(app):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def build_sequence_app():
    app = Flask(__name__)
    items = {}

    @app.post("/login")
    def login():
        return jsonify({"token": "token-123"})

    @app.post("/items")
    def create_item():
        if request.headers.get("X-Token") != "token-123":
            return jsonify({"error": "unauthorized"}), 401
        item_id = "item-1"
        items[item_id] = {"id": item_id, "name": (request.get_json() or {}).get("name", "demo")}
        response = jsonify(items[item_id])
        response.headers["X-Item-ID"] = item_id
        return response, 201

    @app.get("/items/<item_id>")
    def read_item(item_id):
        if request.headers.get("X-Token") != "token-123":
            return jsonify({"error": "unauthorized"}), 401
        return jsonify(items.get(item_id) or {"id": item_id, "name": "missing"})

    @app.delete("/items/<item_id>")
    def delete_item(item_id):
        items.pop(item_id, None)
        return jsonify({"deleted": item_id})

    return app


class SequenceRunnerTests(unittest.TestCase):
    def test_yaml_sequence_executes_variables_assertions_and_safe_skips(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(build_sequence_app()) as base_url:
            workflow_path = Path(tmpdir) / "workflow.yaml"
            workflow_path.write_text(
                f"""
name: item lifecycle
base_url: {base_url}
steps:
  - name: login
    method: POST
    url: /login
    json:
      username: alice
    extract:
      token:
        jsonpath: $.token
    assertions:
      - status_code: 200
  - name: create item
    method: POST
    url: /items
    headers:
      X-Token: "{{{{token}}}}"
    json:
      name: demo
    extract:
      item_id:
        header: X-Item-ID
    assertions:
      - status_code: 201
      - jsonpath: $.name
        equals: demo
  - name: read item
    method: GET
    url: /items/{{{{item_id}}}}
    headers:
      X-Token: "{{{{token}}}}"
    assertions:
      - status_code: 200
      - jsonpath: $.id
        equals: "{{{{item_id}}}}"
  - name: delete item
    method: DELETE
    url: /items/{{{{item_id}}}}
""",
                encoding="utf-8",
            )

            with StorageRepository(str(Path(tmpdir) / "wraith.sqlite3")) as repo:
                scan = ScanConfig(scan_id="seq-scan", target_base_url=base_url)
                repo.create_scan(scan)

                results = run_sequence_workflows(
                    str(workflow_path),
                    base_url=base_url,
                    storage_repo=repo,
                    scan_id=scan.scan_id,
                    auth_role="user_a",
                    safety_mode="safe",
                    timeout=5,
                )

                self.assertEqual(len(results), 1)
                result = results[0]
                self.assertEqual(result.status, "succeeded")
                self.assertEqual(result.variables["token"], "token-123")
                self.assertEqual(result.variables["item_id"], "item-1")
                self.assertEqual([step.status for step in result.steps], ["executed", "executed", "executed", "skipped"])
                self.assertIn("safe mode", result.steps[-1].reason)

                saved_requests = repo.list_requests(scan.scan_id, {"source": "replay", "auth_role": "user_a"})
                self.assertEqual(len(saved_requests), 3)
                self.assertTrue(all(repo.get_response_for_request(item["request_id"]) for item in saved_requests))

    def test_failed_assertion_marks_workflow_failed(self):
        with tempfile.TemporaryDirectory() as tmpdir, run_app(build_sequence_app()) as base_url:
            workflow = {
                "name": "bad assertion",
                "steps": [
                    {
                        "name": "login",
                        "method": "POST",
                        "url": "/login",
                        "assertions": [{"status_code": 201}],
                    }
                ],
            }
            with StorageRepository(str(Path(tmpdir) / "wraith.sqlite3")) as repo:
                repo.create_scan(ScanConfig(scan_id="seq-fail", target_base_url=base_url))

                result = run_sequence_workflows(
                    workflow,
                    base_url=base_url,
                    storage_repo=repo,
                    scan_id="seq-fail",
                    safety_mode="safe",
                    timeout=5,
                )[0]

                self.assertEqual(result.status, "failed")
                self.assertEqual(result.failed_step, "login")
                self.assertIn("expected status", result.steps[0].reason)

    def test_loader_accepts_yaml_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workflow_path = Path(tmpdir) / "workflow.yaml"
            workflow_path.write_text(
                """
workflows:
  - name: smoke
    steps:
      - method: GET
        url: /health
""",
                encoding="utf-8",
            )

            workflows = load_sequence_workflows(str(workflow_path))

            self.assertEqual(len(workflows), 1)
            self.assertEqual(workflows[0]["name"], "smoke")


if __name__ == "__main__":
    unittest.main()
