"""Thin client for the Attack Flow API's job endpoints."""

import os
import time

import httpx

DEFAULT_URL = "http://localhost:8000/api/v1"
DONE = {"completed"}
FAILED = {"failed", "cancelled", "canceled"}


class JobFailed(RuntimeError):
    """The API finished the job without an ``.afb`` artifact."""

    def __init__(self, message, job_id=None, code=None):
        super().__init__(message)
        self.job_id, self.code = job_id, code


class ApiClient:
    def __init__(
        self,
        base_url=None,
        transport=None,
        timeout=60.0,
        sleep=time.sleep,
        clock=time.monotonic,
    ):
        self.base_url = (
            base_url or os.environ.get("ATTACK_FLOW_API_URL") or DEFAULT_URL
        ).rstrip("/")
        self._http = httpx.Client(transport=transport, timeout=timeout)
        self._sleep, self._clock = sleep, clock

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _get(self, path):
        response = self._http.get(f"{self.base_url}{path}")
        response.raise_for_status()
        return response

    def submit_text(self, text, metadata=None, provider_id=None, model=None):
        """POST a text job; returns the job id."""
        options = {
            k: v for k, v in {"provider_id": provider_id, "model": model}.items() if v
        }
        body = {
            "input_type": "text",
            "text": text,
            "metadata": metadata or None,
            "options": options or None,
        }
        response = self._http.post(f"{self.base_url}/jobs", json=body)
        response.raise_for_status()
        return response.json()["job_id"]

    def status(self, job_id):
        return self._get(f"/jobs/{job_id}").json()

    def wait(self, job_id, timeout=900.0, interval=5.0):
        """Poll until the job leaves the queue; returns the final status document."""
        deadline = self._clock() + timeout
        while True:
            doc = self.status(job_id)
            if doc["status"] in DONE | FAILED:
                return doc
            if self._clock() > deadline:
                raise JobFailed(
                    f"job {job_id} still {doc['status']} after {timeout:.0f}s",
                    job_id,
                    "timeout",
                )
            self._sleep(interval)

    def afb(self, job_id):
        return self._get(f"/jobs/{job_id}/artifacts/afb").content

    def audit(self, job_id):
        return self._get(f"/jobs/{job_id}/audit").json()

    def run_text_job(
        self,
        text,
        metadata=None,
        provider_id=None,
        model=None,
        timeout=900.0,
        interval=5.0,
    ):
        """
        Submit, wait, and fetch the ``.afb``.

        :return: ``(afb_bytes, job_id, audit)``; ``audit`` may be ``{}`` if it could not be read.
        :raises JobFailed: the job failed or produced no ``.afb``.
        """
        job_id = self.submit_text(text, metadata, provider_id, model)
        doc = self.wait(job_id, timeout, interval)
        if doc["status"] in FAILED or not (doc.get("artifacts") or {}).get("has_afb"):
            raise JobFailed(
                f"job {job_id}: {doc.get('error_message') or doc['status']}",
                job_id,
                doc.get("error_code"),
            )
        try:
            audit = self.audit(job_id)
        except httpx.HTTPError:
            audit = {}
        return self.afb(job_id), job_id, audit


def provider_from_audit(audit):
    """``(provider_id, model)`` the job actually used, read from its audit events."""
    for event in audit.get("events") or []:
        if event.get("event_type") == "provider_invocation_completed":
            details = event.get("details") or {}
            return details.get("provider_id"), details.get("model_used")
    job = audit.get("job") or {}
    return job.get("provider_id"), job.get("model")
