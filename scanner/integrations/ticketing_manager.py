from __future__ import annotations

import json
import logging
import os

import requests

logger = logging.getLogger(__name__)


class TicketingManager:
    """Formats and pushes vulnerability findings to Jira and Slack."""

    def __init__(self):
        self.jira_url = os.getenv("JIRA_URL")
        self.jira_email = os.getenv("JIRA_EMAIL")
        self.jira_api_token = os.getenv("JIRA_API_TOKEN")
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.jira_auth = (self.jira_email, self.jira_api_token) if self.jira_email else None

    def push_finding(self, finding: dict):
        severity = str(finding.get("severity", "LOW")).upper()
        if severity in ["HIGH", "CRITICAL"]:
            self.send_slack_alert(finding)
        if self.jira_url:
            self.create_jira_issue(finding)

    def send_slack_alert(self, finding: dict):
        if not self.slack_webhook:
            return

        severity_color = "#FF0000" if str(finding.get("severity")) == "CRITICAL" else "#FFA500"
        slack_payload = {
            "attachments": [
                {
                    "color": severity_color,
                    "title": f"🚨 [{finding.get('severity')}] {finding.get('title', 'Vulnerability Found')}",
                    "text": finding.get("description", "No description provided."),
                    "fields": [
                        {"title": "Target", "value": finding.get("url", finding.get("file", "N/A")), "short": True},
                        {"title": "Confidence", "value": f"{finding.get('confidence', 90)}%", "short": True},
                    ],
                    "footer": "Wraith Scanner",
                }
            ]
        }

        try:
            requests.post(self.slack_webhook, json=slack_payload, timeout=5)
            logger.info("Slack alert sent successfully.")
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")

    def create_jira_issue(self, finding: dict):
        if not self.jira_url or not self.jira_auth:
            return

        jira_api_endpoint = f"{self.jira_url}/rest/api/2/issue"
        payload = {
            "fields": {
                "project": {"key": os.getenv("JIRA_PROJECT_KEY", "SEC")},
                "summary": f"[Wraith] {finding.get('title', 'Vuln')} on {finding.get('url', finding.get('file', ''))}",
                "description": (
                    f"*h3. Vulnerability Details*\n*Severity:* {finding.get('severity')}\n"
                    f"*Confidence:* {finding.get('confidence', 90)}%\n\n"
                    f"*Description:* {finding.get('description')}\n\n"
                    f"*Evidence:* {finding.get('evidence', 'N/A')}"
                ),
                "issuetype": {"name": "Bug"},
                "labels": ["wraith-scanner", str(finding.get("severity", "LOW")).lower()],
            }
        }

        try:
            response = requests.post(
                jira_api_endpoint,
                json=payload,
                auth=self.jira_auth,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if response.status_code == 201:
                logger.info(f"Jira issue created: {response.json().get('key')}")
            else:
                logger.error(f"Failed to create Jira issue: {response.text}")
        except Exception as e:
            logger.error(f"Jira API Error: {e}")
