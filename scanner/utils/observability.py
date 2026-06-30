from __future__ import annotations

import json
import logging

from flask import Response
try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
except ImportError:
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

    class _NoopMetric:
        def labels(self, *args, **kwargs):
            return self

        def inc(self, *args, **kwargs):
            return None

        def observe(self, *args, **kwargs):
            return None

        def time(self):
            return self

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def Counter(*args, **kwargs):
        return _NoopMetric()

    def Histogram(*args, **kwargs):
        return _NoopMetric()

    def generate_latest():
        return b"# prometheus_client not installed\n"

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
