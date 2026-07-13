"""Network reliability helpers: bounded retries with exponential backoff.

Transient network failures (DNS blips, 5xx, timeouts) should be retried a few
times with growing, jittered delays; permanent failures (4xx, invalid input)
should fail fast. :func:`retry_request` wraps a callable that performs one HTTP
attempt and returns a :class:`requests.Response`, retrying only on transient
conditions.

Kept deliberately small and dependency-light so callers (AI client, Telegram
client, appliance connector) can opt in without inheriting a framework.
"""

from __future__ import annotations

import random
import time
from typing import Callable, Iterable, Optional

import requests

from autosoc.logging_setup import get_logger

log = get_logger("net")

# HTTP status codes worth retrying (transient server/throughput issues).
RETRYABLE_STATUS: frozenset[int] = frozenset({429, 500, 502, 503, 504})


class RetryError(Exception):
    """Raised when all retry attempts are exhausted."""


def backoff_delays(
    attempts: int,
    base: float = 0.5,
    cap: float = 8.0,
    jitter: float = 0.25,
) -> Iterable[float]:
    """Yield ``attempts - 1`` exponentially growing, jittered delays (seconds)."""
    for attempt in range(attempts - 1):
        raw = min(cap, base * (2 ** attempt))
        yield raw + random.uniform(0.0, jitter)


def retry_request(
    make_request: Callable[[], requests.Response],
    *,
    attempts: int = 3,
    retryable_status: frozenset[int] = RETRYABLE_STATUS,
    on_retry: Optional[Callable[[int, Exception | int], None]] = None,
) -> requests.Response:
    """Call ``make_request`` up to ``attempts`` times with exponential backoff.

    Retries only on connection/timeout errors and retryable HTTP statuses;
    other responses (including 4xx) are returned to the caller as-is. Raises
    :class:`RetryError` if every attempt fails with a transient error.
    """
    delays = list(backoff_delays(attempts))
    last_error: Exception | None = None

    for attempt in range(attempts):
        try:
            response = make_request()
        except (requests.Timeout, requests.ConnectionError) as exc:
            last_error = exc
            if on_retry:
                on_retry(attempt, exc)
        else:
            if response.status_code in retryable_status and attempt < attempts - 1:
                if on_retry:
                    on_retry(attempt, response.status_code)
            else:
                return response

        if attempt < attempts - 1:
            delay = delays[attempt]
            log.debug("Retry %d/%d after %.2fs", attempt + 1, attempts - 1, delay)
            time.sleep(delay)

    raise RetryError(f"All {attempts} attempts failed; last error: {last_error}")
