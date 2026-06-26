from __future__ import annotations

import json
import logging

from flask import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

SCAN_REQUESTS = Counter("wraith_scans_total", "Total number of scans initiated", ["scan_type", "status"])
SCAN_DURATION = Histogram("wraith_scan_duration_seconds", "Time spent running scans", ["scan_type"])


class JSONFormatter(logging.Formatter):
    """Outputs logs in JSON format for Datadog/Splunk/ELK ingestion."""

    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)


def setup_logging():
    """Call this in api_server.py on startup."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logger.handlers = [handler]


def metrics_endpoint():
    """Flask route returning Prometheus metrics."""
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


def health_check_endpoint():
    """Simple health endpoint."""
    return Response(
        json.dumps({"status": "healthy", "version": "4.0.0"}),
        status=200,
        mimetype="application/json",
    )
