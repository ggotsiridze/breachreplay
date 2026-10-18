"""Isolated per-job analysis workspaces."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

CAPTURE_NAME = "capture.pcap"


def new_job_id() -> str:
    return uuid.uuid4().hex


class Workspace:
    """A private directory for one analysis job.

    The capture is stored under a generated name; the uploaded filename is
    never used as a path component.
    """

    def __init__(self, root: Path, job_id: str) -> None:
        if len(job_id) != 32 or not all(c in "0123456789abcdef" for c in job_id):
            raise ValueError("invalid job id")
        self.root = root
        self.path = root / job_id
        self.job_id = job_id

    def create(self) -> Workspace:
        self.root.mkdir(parents=True, exist_ok=True)
        self.path.mkdir(mode=0o770)
        # Analyzer containers run as the same unprivileged uid and need group write.
        os.chmod(self.path, 0o770)  # noqa: S103 - shared only with the analyzer uid/gid
        return self

    @property
    def capture(self) -> Path:
        return self.path / CAPTURE_NAME

    def cleanup(self) -> None:
        shutil.rmtree(self.path, ignore_errors=True)
