import xml.etree.ElementTree as ET

class JUnitExporter:
    """Generates JUnit XML reports for CI/CD pipeline integration."""
    
    def export_to_file(self, findings: list, filepath: str):
        # Root element
        testsuites = ET.Element("testsuites", name="Wraith Security Scan")
        
        # Single suite for all vulnerabilities
        testsuite = ET.SubElement(testsuites, "testsuite", 
                                  name="SecurityVulnerabilities",
                                  tests=str(len(findings)),
                                  failures=str(len(findings)),
                                  errors="0"
                                  )
                                  
        for finding in findings:
            vuln_type = finding.get("type", "Vulnerability")
            severity = finding.get("severity", "MEDIUM")
            url_or_file = finding.get("url", finding.get("file", "unknown"))
            
            # Each finding is a "test case" that failed
            testcase = ET.SubElement(testsuite, "testcase", 
                                     name=f"[{severity}] {vuln_type}",
                                     classname=url_or_file
                                     )
                                     
            # The failure details
            failure_msg = finding.get("evidence", finding.get("description", "Vulnerability found"))
            ET.SubElement(testcase, "failure", 
                          message=failure_msg,
                          type=vuln_type
                          ).text = f"Severity: {severity}\nLocation: {url_or_file}\nEvidence: {failure_msg}"

        # Write to file
        tree = ET.ElementTree(testsuites)
        with open(filepath, "wb") as f:
            tree.write(f, encoding="utf-8", xml_declaration=True)
