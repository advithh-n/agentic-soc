"""Langfuse LLM Observability — traces, generations, and token accounting.

Wraps the Langfuse SDK to log every LLM call across triage, investigation,
and critic agents. Silently disabled if credentials are not configured.
"""

import os
import time

import structlog

logger = structlog.get_logger()

_langfuse = None
_enabled = False


def init_langfuse():
    """Initialize Langfuse client if credentials are configured."""
    global _langfuse, _enabled

    host = os.getenv("LANGFUSE_HOST", "").strip()
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY", "").strip()
    secret_key = os.getenv("LANGFUSE_SECRET_KEY", "").strip()

    if not public_key or not secret_key:
        logger.info("langfuse.disabled", reason="LANGFUSE_PUBLIC_KEY or LANGFUSE_SECRET_KEY not set")
        return

    try:
        from langfuse import Langfuse

        kwargs = {
            "public_key": public_key,
            "secret_key": secret_key,
        }
        if host:
            kwargs["host"] = host

        _langfuse = Langfuse(**kwargs)
        _enabled = True
        logger.info("langfuse.enabled", host=host or "cloud")
    except ImportError:
        logger.info("langfuse.disabled", reason="langfuse package not installed")
    except Exception as e:
        logger.warning("langfuse.init_failed", error=str(e))


def is_langfuse_enabled() -> bool:
    return _enabled


def create_trace(name: str, metadata: dict | None = None):
    """Create a new Langfuse trace for a pipeline run.

    Returns a trace object, or None if Langfuse is disabled.
    """
    if not _enabled or not _langfuse:
        return None

    try:
        return _langfuse.trace(
            name=name,
            metadata=metadata or {},
        )
    except Exception as e:
        logger.warning("langfuse.trace_failed", error=str(e))
        return None


def log_generation(
    agent: str,
    model: str,
    input_text: str,
    output_text: str,
    tokens_input: int = 0,
    tokens_output: int = 0,
    latency_ms: int = 0,
    success: bool = True,
    trace=None,
    metadata: dict | None = None,
):
    """Log an LLM generation event to Langfuse.

    Can be called standalone or with a trace object for hierarchical tracking.
    """
    if not _enabled or not _langfuse:
        return

    try:
        gen_kwargs = {
            "name": f"{agent}_generation",
            "model": model,
            "input": input_text[:2000],  # Truncate for Langfuse storage
            "output": output_text[:2000],
            "usage": {
                "input": tokens_input,
                "output": tokens_output,
                "total": tokens_input + tokens_output,
            },
            "metadata": {
                "agent": agent,
                "success": success,
                "latency_ms": latency_ms,
                **(metadata or {}),
            },
        }

        if trace:
            trace.generation(**gen_kwargs)
        else:
            # Create standalone trace + generation
            t = _langfuse.trace(name=f"{agent}_standalone")
            t.generation(**gen_kwargs)
    except Exception as e:
        logger.warning("langfuse.log_generation_failed", agent=agent, error=str(e))


def flush():
    """Flush pending events to Langfuse."""
    if _enabled and _langfuse:
        try:
            _langfuse.flush()
            logger.debug("langfuse.flushed")
        except Exception as e:
            logger.warning("langfuse.flush_failed", error=str(e))


def shutdown():
    """Shutdown Langfuse client."""
    if _enabled and _langfuse:
        try:
            _langfuse.flush()
            _langfuse.shutdown()
            logger.info("langfuse.shutdown")
        except Exception as e:
            logger.warning("langfuse.shutdown_failed", error=str(e))
