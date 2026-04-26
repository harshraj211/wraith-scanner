import json
import tempfile
import unittest
from pathlib import Path

from scanner.core.models import ScanConfig
from scanner.importers.common import (
    candidates_to_scan_targets,
    load_candidates_from_imports,
    save_candidates_to_corpus,
)
from scanner.importers.graphql import import_graphql
from scanner.importers.har import import_har
from scanner.importers.openapi import import_openapi
from scanner.importers.postman import import_postman
from scanner.storage.repository import StorageRepository
from scanner.utils.redaction import MASK


class ApiImporterTests(unittest.TestCase):
    def test_openapi_importer_generates_request_candidates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_path = Path(tmpdir) / "openapi.json"
            spec_path.write_text(
                json.dumps(
                    {
                        "openapi": "3.0.3",
                        "servers": [{"url": "https://api.example.test"}],
                        "security": [{"ApiKeyAuth": []}],
                        "paths": {
                            "/users/{id}": {
                                "get": {
                                    "tags": ["users"],
                                    "parameters": [
                                        {
                                            "name": "id",
                                            "in": "path",
                                            "required": True,
                                            "schema": {"type": "integer"},
                                        },
                                        {
                                            "name": "include",
                                            "in": "query",
                                            "schema": {"type": "string", "example": "profile"},
                                        },
                                    ],
                                }
                            },
                            "/comments": {
                                "post": {
                                    "tags": ["comments"],
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "required": ["body"],
                                                    "properties": {
                                                        "body": {"type": "string", "example": "hello"},
                                                        "postId": {"type": "integer"},
                                                    },
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            candidates = import_openapi(str(spec_path))
            self.assertEqual(len(candidates), 2)
            get_candidate = next(item for item in candidates if item.method == "GET")
            self.assertEqual(get_candidate.url, "https://api.example.test/users/1")
            self.assertIn("ApiKeyAuth", get_candidate.auth_requirements)

            urls, forms = candidates_to_scan_targets(candidates)
            self.assertIn("https://api.example.test/users/1?include=profile", urls)
            self.assertEqual(forms[0]["body_format"], "json")
            self.assertEqual(forms[0]["extra_headers"]["Content-Type"], "application/json")
            self.assertIn("body", {item["name"] for item in forms[0]["inputs"]})

    def test_postman_importer_preserves_folder_tags_and_variables(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            collection_path = Path(tmpdir) / "collection.json"
            collection_path.write_text(
                json.dumps(
                    {
                        "info": {"name": "API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
                        "variable": [
                            {"key": "baseUrl", "value": "https://api.example.test"},
                            {"key": "itemId", "value": "abc"},
                        ],
                        "item": [
                            {
                                "name": "Items",
                                "item": [
                                    {
                                        "name": "Update item",
                                        "request": {
                                            "method": "PATCH",
                                            "header": [{"key": "X-Test", "value": "yes"}],
                                            "url": {
                                                "raw": "{{baseUrl}}/items/{{itemId}}",
                                                "query": [{"key": "expand", "value": "owner"}],
                                            },
                                            "body": {
                                                "mode": "raw",
                                                "raw": "{\"name\":\"demo\"}",
                                                "options": {"raw": {"language": "json"}},
                                            },
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            candidates = import_postman(str(collection_path))
            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]
            self.assertEqual(candidate.url, "https://api.example.test/items/abc")
            self.assertIn("Items", candidate.tags)
            self.assertEqual(candidate.body_format, "json")
            self.assertEqual(candidate.headers["X-Test"], "yes")

    def test_har_importer_redacts_sensitive_headers_and_preserves_response_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            har_path = Path(tmpdir) / "traffic.har"
            har_path.write_text(
                json.dumps(
                    {
                        "log": {
                            "entries": [
                                {
                                    "time": 15,
                                    "request": {
                                        "method": "POST",
                                        "url": "https://api.example.test/login",
                                        "headers": [
                                            {"name": "Authorization", "value": "Bearer secret-token-value"},
                                            {"name": "Content-Type", "value": "application/json"},
                                        ],
                                        "queryString": [],
                                        "postData": {
                                            "mimeType": "application/json",
                                            "text": "{\"username\":\"alice\",\"password\":\"secret\"}",
                                        },
                                    },
                                    "response": {
                                        "status": 200,
                                        "content": {"mimeType": "application/json"},
                                    },
                                }
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )

            candidates = import_har(str(har_path))
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].headers["Authorization"], MASK)
            self.assertEqual(candidates[0].response_metadata["status"], 200)

    def test_graphql_importer_accepts_introspection_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_path = Path(tmpdir) / "graphql.json"
            schema_path.write_text(
                json.dumps(
                    {
                        "data": {
                            "__schema": {
                                "queryType": {"name": "Query"},
                                "mutationType": {"name": "Mutation"},
                                "types": [
                                    {"name": "Query", "fields": [{"name": "viewer", "args": []}]},
                                    {"name": "Mutation", "fields": [{"name": "ping", "args": []}]},
                                ],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            candidates = import_graphql(
                str(schema_path),
                endpoint_url="https://api.example.test/graphql",
            )
            self.assertGreaterEqual(len(candidates), 3)
            self.assertTrue(all(item.body_format == "graphql" for item in candidates))

    def test_imported_candidates_can_be_saved_to_corpus(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_path = Path(tmpdir) / "openapi.json"
            db_path = Path(tmpdir) / "wraith.sqlite3"
            spec_path.write_text(
                json.dumps(
                    {
                        "openapi": "3.0.3",
                        "servers": [{"url": "https://api.example.test"}],
                        "paths": {
                            "/search": {
                                "get": {
                                    "parameters": [
                                        {"name": "q", "in": "query", "schema": {"type": "string", "example": "term"}}
                                    ]
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            repo = StorageRepository(str(db_path))
            scan = ScanConfig(scan_id="scan-import", target_base_url="https://api.example.test")
            repo.create_scan(scan)

            candidates, summary = load_candidates_from_imports({"openapi": [str(spec_path)]})
            saved = save_candidates_to_corpus(repo, scan.scan_id, candidates)

            self.assertEqual(summary["openapi"], 1)
            self.assertEqual(saved, 1)
            requests = repo.list_requests(scan.scan_id, {"source": "import", "parameter_name": "q"})
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0]["source"], "import")
            repo.close()


if __name__ == "__main__":
    unittest.main()
