import unittest
from unittest.mock import patch

from scanner.core.models import Finding
from scanner.integrations.cve_intel import CveIntelClient, enrich_findings, extract_cves_from_finding


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeSession:
    def get(self, url, **kwargs):
        if "nvd.nist.gov" in url:
            return FakeResponse({
                "vulnerabilities": [{
                    "cve": {
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-02-01T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Demo vulnerability"}],
                        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "baseSeverity": "HIGH",
                                "cvssData": {
                                    "baseScore": 8.8,
                                    "baseSeverity": "HIGH",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                },
                            }]
                        },
                    }
                }]
            })
        if "api.first.org" in url:
            return FakeResponse({
                "data": [{
                    "cve": "CVE-2024-0001",
                    "epss": "0.75",
                    "percentile": "0.98",
                }]
            })
        if "cisa.gov" in url:
            return FakeResponse({
                "vulnerabilities": [{
                    "cveID": "CVE-2024-0001",
                    "vendorProject": "DemoVendor",
                    "product": "DemoProduct",
                    "dueDate": "2024-03-01",
                    "requiredAction": "Apply updates.",
                }]
            })
        return FakeResponse({})


class CveIntelTests(unittest.TestCase):
    def test_extracts_cves_from_finding(self):
        finding = Finding.from_legacy({
            "type": "vulnerable-component",
            "title": "Exposure CVE-2024-0001",
            "url": "https://app.example.test",
            "evidence": "Matched CVE-2024-0002",
        }, target_url="https://app.example.test", scan_id="scan")
        self.assertEqual(extract_cves_from_finding(finding), ["CVE-2024-0001", "CVE-2024-0002"])

    def test_enriches_finding_with_nvd_epss_and_kev(self):
        finding = Finding.from_legacy({
            "type": "vulnerable-component",
            "title": "Exposure CVE-2024-0001",
            "url": "https://app.example.test",
            "severity": "medium",
            "evidence": "Nuclei matched CVE-2024-0001",
        }, target_url="https://app.example.test", scan_id="scan")
        summary = enrich_findings([finding], CveIntelClient(session=FakeSession()))

        self.assertEqual(summary["cve_count"], 1)
        self.assertEqual(summary["kev_count"], 1)
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.cvss_score, 8.8)
        self.assertEqual(finding.metadata["cve_intelligence"][0]["epss_score"], 0.75)
        self.assertTrue(finding.metadata["cve_intelligence"][0]["cisa_kev"])


if __name__ == "__main__":
    unittest.main()
