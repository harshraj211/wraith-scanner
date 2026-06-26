from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import sys

import requests

logger = logging.getLogger(__name__)


class DesktopUpdater:
    """Checks for updates, verifies SHA256 signatures, and applies updates."""

    def __init__(self, current_version: str):
        self.current_version = current_version
        self.update_url = "https://api.yourserver.com/api/v1/desktop/latest"

    def check_for_updates(self):
        logger.info("Checking for updates... Current version: %s", self.current_version)
        try:
            response = requests.get(self.update_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get("version")
                if latest_version and latest_version > self.current_version:
                    logger.info("Update available: %s", latest_version)
                    return data
        except Exception as e:
            logger.error("Failed to check for updates: %s", e)
        return None

    def apply_update(self, update_data: dict):
        download_url = update_data["download_url"]
        expected_sha256 = update_data["sha256"]
        logger.info("Downloading update...")
        try:
            response = requests.get(download_url, stream=True, timeout=30)
            installer_path = os.path.join(os.getcwd(), "wraith_update.exe")
            with open(installer_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            logger.info("Verifying SHA256 signature...")
            actual_sha256 = self._calculate_sha256(installer_path)
            if actual_sha256 != expected_sha256:
                logger.error("Signature verification failed! Aborting update.")
                os.remove(installer_path)
                return False

            logger.info("Signature verified. Launching installer...")
            subprocess.Popen([installer_path, "/SILENT"])
            sys.exit(0)
        except Exception as e:
            logger.error("Update failed: %s", e)
            return False

    def _calculate_sha256(self, file_path: str):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
