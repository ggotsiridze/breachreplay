"""Fan-out of analysis progress updates to WebSocket subscribers."""

from __future__ import annotations

import asyncio
import contextlib
from collections import defaultdict
from typing import Any

QUEUE_SIZE = 32


class ProgressHub:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)

    def subscribe(self, incident_id: str) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_SIZE)
        self._subscribers[incident_id].add(queue)
        return queue

    def unsubscribe(self, incident_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        subs = self._subscribers.get(incident_id)
        if subs is not None:
            subs.discard(queue)
            if not subs:
                del self._subscribers[incident_id]

    def publish(self, incident_id: str, message: dict[str, Any]) -> None:
        for queue in list(self._subscribers.get(incident_id, ())):
            if queue.full():  # bounded: drop the oldest update, keep the newest
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
            queue.put_nowait(message)

    def subscriber_count(self, incident_id: str) -> int:
        return len(self._subscribers.get(incident_id, ()))
