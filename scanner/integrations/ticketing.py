from __future__ import annotations

import os


class TicketingIntegration:
    """Pushes critical findings to Jira or Slack."""

    def __init__(self):
        self.jira_url = os.getenv("JIRA_URL")
        self.jira_token = os.getenv("JIRA_TOKEN")
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")

    def push_to_jira(self, finding):
        payload = {
            "fields": {
                "project": {"key": "SEC"},
                "summary": f"[Wraith] {finding.get('title')} on {finding.get('url')}",
                "description": finding.get("description"),
                "issuetype": {"name": "Bug"},
            }
        }
        _ = payload
        print("Mock pushed to Jira")

    def send_slack_alert(self, finding):
        if finding.get("severity") == "CRITICAL":
            payload = {
                "text": f":rotating_light: *Critical Vulnerability Found*\n*Target:* {finding.get('url')}\n*Type:* {finding.get('title')}"
            }
            _ = payload
            print("Mock sent Slack alert")
