"""
LLM access for the corpus factory. Uses the API's own provider registry and ``config/providers.yml``,
so credentials stay where upstream keeps them (SPEC §14). Every call is logged to ``pivot.llm_call``.
"""

import json
import os
import re
import time
from pathlib import Path

DEFAULT_CONFIG = Path("config/providers.yml")
THINK_BLOCK = re.compile(r"<think>.*?(?:</think>|$)", re.S | re.I)


def _env_number(name, default, cast):
    """A positive number from the environment (slow local models need larger limits), else ``default``."""
    try:
        value = cast(os.environ[name])
    except (KeyError, ValueError):
        return default
    return value if value > 0 else default


class LlmUnavailable(RuntimeError):
    """No usable provider is configured."""


class LlmClient:
    def __init__(self, adapter, provider_id, provider_type, model):
        self.adapter = adapter
        self.provider_id = provider_id
        self.provider_type = provider_type
        self.model = model

    def complete_json(self, prompt, max_output_tokens=None, timeout=None):
        """
        ``PIVOT_LLM_TIMEOUT`` (seconds, default 60) and ``PIVOT_LLM_MAX_OUTPUT_TOKENS`` (default 400)
        raise the defaults for slow local models and models that write reasoning before the answer.

        :return: ``(parsed_object | None, usage)`` where usage is
            ``{"input_tokens", "output_tokens", "latency_ms"}``.
        """
        from attack_flow_api.providers.contracts import StructuredGenerationRequest

        max_output_tokens = max_output_tokens or _env_number(
            "PIVOT_LLM_MAX_OUTPUT_TOKENS", 400, int
        )
        timeout = timeout or _env_number("PIVOT_LLM_TIMEOUT", 60.0, float)
        started = time.monotonic()
        result = self.adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=self.model,
                prompt=prompt,
                temperature=0.0,
                max_output_tokens=max_output_tokens,
                timeout_seconds=timeout,
            )
        )
        usage = {
            "input_tokens": result.usage.input_tokens,
            "output_tokens": result.usage.output_tokens,
            "latency_ms": result.latency_ms or int((time.monotonic() - started) * 1000),
        }
        return result.output_json or parse_json_object(result.output_text), usage


def parse_json_object(text):
    """
    The first JSON object in a model reply, else ``None``. Tolerates code fences, prose around the
    object and ``<think>`` reasoning blocks (an unclosed one, from a reply cut off at the token
    limit, hides everything after it).
    """
    if not text:
        return None
    text = THINK_BLOCK.sub("", text)
    decoder = json.JSONDecoder()
    for start in (m.start() for m in re.finditer(r"\{", text)):
        try:
            value, _ = decoder.raw_decode(text, start)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


def from_config(provider_id=None, model=None, config_path=None):
    """
    Build a client from the API's provider config.

    :raises LlmUnavailable: no config file, no enabled provider, or the model is not allowed.
    """
    from attack_flow_api.config import load_providers_config
    from attack_flow_api.providers.registry import ProviderRegistry

    path = Path(
        config_path or os.environ.get("PROVIDERS_CONFIG_PATH") or DEFAULT_CONFIG
    )
    try:
        registry = ProviderRegistry(load_providers_config(path))
    except FileNotFoundError:
        raise LlmUnavailable(
            f"no provider config at {path}; copy config/providers.yml.example and enable a provider"
        ) from None
    provider_id = provider_id or registry.get_default_enabled_provider_id()
    if not provider_id:
        raise LlmUnavailable(f"no enabled provider in {path}")
    config = registry.get_provider_config(provider_id)
    model = model or config.default_model
    if not model or (config.allowed_models and model not in config.allowed_models):
        raise LlmUnavailable(
            f"model {model!r} is not allowed for provider {provider_id!r}"
        )
    return LlmClient(
        registry.resolve_adapter(provider_id), provider_id, config.provider_type, model
    )


def log_call(conn, purpose, client, usage, report_id=None, job_id=None, ok=True):
    """Record one call (tokens, latency, provider, model) in ``pivot.llm_call``."""
    conn.execute(
        "INSERT INTO pivot.llm_call (purpose, report_id, provider, model, input_tokens, "
        "output_tokens, latency_ms, job_id, ok) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            purpose,
            report_id,
            client.provider_id,
            client.model,
            usage.get("input_tokens"),
            usage.get("output_tokens"),
            usage.get("latency_ms"),
            job_id,
            ok,
        ),
    )


def cost_summary(conn, purpose=None):
    """Totals per purpose/provider/model: calls, failures, input and output tokens."""
    where, params = ("WHERE purpose = %s", (purpose,)) if purpose else ("", ())
    return conn.execute(
        "SELECT purpose, provider, model, count(*) AS calls, count(*) FILTER (WHERE NOT ok) AS failed, "
        "coalesce(sum(input_tokens), 0) AS input_tokens, coalesce(sum(output_tokens), 0) AS output_tokens "
        f"FROM pivot.llm_call {where} GROUP BY 1, 2, 3 ORDER BY 1, 2, 3",
        params,
    ).fetchall()
