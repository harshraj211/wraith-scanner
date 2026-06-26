from __future__ import annotations

import os

import requests


class GitHubPRIntegrator:
    """Posts SAST findings as inline comments on GitHub Pull Requests."""

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")
        self.repo = os.getenv("GITHUB_REPOSITORY")
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

    def post_finding_comment(self, pr_number: int, file_path: str, line_number: int, message: str):
        url = f"https://api.github.com/repos/{self.repo}/pulls/{pr_number}/comments"
        payload = {
            "body": f"🚨 **[Wraith SAST]** {message}",
            "path": file_path,
            "line": line_number,
            "side": "RIGHT",
        }
        try:
            requests.post(url, json=payload, headers=self.headers)
            print(f"[+] Posted PR comment to {file_path}:{line_number}")
        except Exception as e:
            print(f"[-] Failed to post PR comment: {e}")
