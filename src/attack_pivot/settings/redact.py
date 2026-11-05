"""Scrub secret values from text before it reaches a log, an error or a response."""

import logging
import re

MASK = "[redacted]"

# Key-shaped strings are masked even when the value is not one we store.
_SHAPES = re.compile(
    r"(?i)(?:x-api-key|x-subscription-token|authorization)\s*[:=]\s*\S+"
    r"|\bBearer\s+[A-Za-z0-9._\-]{12,}"
    r"|\bsk-[A-Za-z0-9_\-]{16,}"
)

_values = set()


def register(values):
    """Remember secret values so every later ``redact`` removes them."""
    _values.update(v for v in values if v and len(v) >= 6)


def forget_all():
    _values.clear()


def redact(text, extra=()):
    text = str(text)
    for value in sorted(_values.union(v for v in extra if v), key=len, reverse=True):
        text = text.replace(value, MASK)
    return _SHAPES.sub(MASK, text)


class RedactingFilter(logging.Filter):
    """Logging filter that masks registered secret values in the formatted message."""

    def filter(self, record):
        record.msg = redact(record.getMessage())
        record.args = ()
        return True


def install_log_filter():
    """Attach the filter to every root handler, which sees all propagated records (idempotent)."""
    flt = RedactingFilter()
    for handler in logging.getLogger().handlers:
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(flt)
