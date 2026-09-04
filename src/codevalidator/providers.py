from __future__ import annotations

import sys
from functools import lru_cache
from typing import TypeVar

from pydantic import BaseModel

from .models import TokenUsage

T = TypeVar("T", bound=BaseModel)

DEFAULT_MODELS = {
    "anthropic": "claude-opus-5",
    "mistral": "mistral-large-latest",
}


class LLMUnavailable(Exception):
    """Raised when the LLM pass can't run at all (missing package, bad/missing credentials)."""


def call(
    provider: str, model: str, rubric: str, user_content: str, response_format: type[T], usage: TokenUsage
) -> T | None:
    if provider == "anthropic":
        return _call_anthropic(model, rubric, user_content, response_format, usage)
    if provider == "mistral":
        return _call_mistral(model, rubric, user_content, response_format, usage)
    raise ValueError(f"unknown LLM provider {provider!r}")


@lru_cache(maxsize=None)
def _anthropic_client():
    import anthropic
    return anthropic.Anthropic()


def _call_anthropic(model: str, rubric: str, user_content: str, response_format: type[T], usage: TokenUsage) -> T | None:
    import anthropic

    try:
        client = _anthropic_client()
        response = client.messages.parse(
            model=model,
            max_tokens=16000,
            system=[{"type": "text", "text": rubric, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": user_content}],
            output_format=response_format,
        )
    except (anthropic.AuthenticationError, TypeError) as e:
        # The SDK raises a bare TypeError (not an AuthenticationError) when it can't
        # resolve any credentials at all, before a request is even built.
        if isinstance(e, TypeError) and "authentication" not in str(e).lower():
            raise
        raise LLMUnavailable(
            f"Anthropic authentication failed ({e}). Set ANTHROPIC_API_KEY, or run `ant auth login`, "
            "or pass --no-llm to skip the LLM review pass."
        ) from e
    except anthropic.NotFoundError as e:
        raise LLMUnavailable(f"Model '{model}' not found or unavailable: {e}") from e
    except anthropic.RateLimitError as e:
        usage.failed_calls += 1
        print(f"warning: rate limited on LLM review batch, skipping it: {e}", file=sys.stderr)
        return None
    except anthropic.APIStatusError as e:
        usage.failed_calls += 1
        print(f"warning: LLM review batch failed ({e.status_code}): {e}", file=sys.stderr)
        return None
    except anthropic.APIConnectionError as e:
        usage.failed_calls += 1
        print(f"warning: network error during LLM review batch: {e}", file=sys.stderr)
        return None

    usage.calls += 1
    usage.input_tokens += response.usage.input_tokens
    usage.output_tokens += response.usage.output_tokens
    usage.cached_input_tokens += getattr(response.usage, "cache_read_input_tokens", 0) or 0
    return response.parsed_output


@lru_cache(maxsize=None)
def _mistral_client():
    import os
    try:
        from mistralai.client import Mistral
        from mistralai.client.utils.retries import BackoffStrategy, RetryConfig
    except ImportError as e:
        raise LLMUnavailable(
            "The 'mistralai' package isn't installed. Run `pip install mistralai`, or pass --no-llm."
        ) from e
    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        raise LLMUnavailable("MISTRAL_API_KEY is not set. Export it, or pass --no-llm to skip the LLM review pass.")
    # Unlike the Anthropic SDK, mistralai does NOT retry 429/5xx by default - without
    # an explicit retry_config, a single transient rate-limit hit is a silent, permanent
    # failure of that batch. Match Anthropic's default-ish behavior: a few retries with
    # exponential backoff.
    retry_config = RetryConfig(
        strategy="backoff",
        backoff=BackoffStrategy(initial_interval=1000, max_interval=20000, exponent=1.5, max_elapsed_time=120000),
        retry_connection_errors=True,
    )
    return Mistral(api_key=api_key, retry_config=retry_config)


def _call_mistral(model: str, rubric: str, user_content: str, response_format: type[T], usage: TokenUsage) -> T | None:
    from mistralai.client import errors as mistral_errors

    client = _mistral_client()
    try:
        response = client.chat.parse(
            response_format=response_format,
            model=model,
            messages=[
                {"role": "system", "content": rubric},
                {"role": "user", "content": user_content},
            ],
        )
    except mistral_errors.SDKError as e:
        status = getattr(e.raw_response, "status_code", None)
        if status in (401, 403):
            raise LLMUnavailable(f"Mistral authentication failed ({e}). Check MISTRAL_API_KEY.") from e
        if status == 404:
            raise LLMUnavailable(f"Model '{model}' not found or unavailable on Mistral: {e}") from e
        if status == 429:
            usage.failed_calls += 1
            print(f"warning: rate limited on LLM review batch, skipping it: {e}", file=sys.stderr)
            return None
        usage.failed_calls += 1
        print(f"warning: LLM review batch failed ({status}): {e}", file=sys.stderr)
        return None
    except mistral_errors.MistralError as e:
        usage.failed_calls += 1
        print(f"warning: LLM review batch failed: {e}", file=sys.stderr)
        return None

    if response.usage is not None:
        usage.calls += 1
        usage.input_tokens += response.usage.prompt_tokens
        usage.output_tokens += response.usage.completion_tokens

    if not response.choices:
        return None
    return response.choices[0].message.parsed
