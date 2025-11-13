"""Utility for redacting sensitive data from logs."""

import re
from typing import Any


def redact_sensitive_data(data: Any) -> Any:
    """
    Recursively redact sensitive data from various data structures.

    Redacts:
    - API keys, tokens, passwords (keys containing these words)
    - Authorization headers
    - Secret matches and code snippets

    Args:
        data: Data to redact (dict, list, str, or primitive)

    Returns:
        Redacted copy of data
    """
    if isinstance(data, dict):
        return {k: redact_sensitive_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    elif isinstance(data, str):
        return _redact_string(data)
    else:
        return data


def redact_dict_keys(data: dict[str, Any]) -> dict[str, Any]:
    """
    Redact specific sensitive keys in a dictionary.

    Keys that are redacted:
    - password, passwd, pwd
    - api_key, apikey, token, secret, auth
    - authorization, bearer

    Args:
        data: Dictionary to redact

    Returns:
        Dictionary with sensitive values replaced with "***REDACTED***"
    """
    if not isinstance(data, dict):
        return data

    sensitive_keys = {
        "password", "passwd", "pwd",
        "api_key", "apikey", "token", "secret", "auth",
        "authorization", "bearer", "match", "code_snippet"
    }

    redacted = {}
    for key, value in data.items():
        key_lower = key.lower()

        # Check if key is sensitive
        if any(sensitive in key_lower for sensitive in sensitive_keys):
            redacted[key] = "***REDACTED***"
        elif isinstance(value, dict):
            redacted[key] = redact_dict_keys(value)
        elif isinstance(value, list):
            redacted[key] = [redact_dict_keys(item) if isinstance(item, dict) else item for item in value]
        else:
            redacted[key] = value

    return redacted


def _redact_string(text: str) -> str:
    """
    Redact patterns in strings that look like secrets.

    Patterns redacted:
    - Bearer tokens: "Bearer abc123..." -> "Bearer ***REDACTED***"
    - Basic auth: "Basic abc123..." -> "Basic ***REDACTED***"
    - API keys in URLs: "?api_key=xyz" -> "?api_key=***REDACTED***"
    - JSON with sensitive keys: {"password": "foo"} -> {"password": "***REDACTED***"}

    Args:
        text: String to redact

    Returns:
        Redacted string
    """
    # Redact Bearer tokens
    text = re.sub(
        r'(Bearer\s+)[A-Za-z0-9_\-\.]+',
        r'\1***REDACTED***',
        text,
        flags=re.IGNORECASE
    )

    # Redact Basic auth
    text = re.sub(
        r'(Basic\s+)[A-Za-z0-9+/=]+',
        r'\1***REDACTED***',
        text,
        flags=re.IGNORECASE
    )

    # Redact API keys in query params
    text = re.sub(
        r'([?&](api_key|token|secret|password|passwd|pwd)=)[^&\s]+',
        r'\1***REDACTED***',
        text,
        flags=re.IGNORECASE
    )

    # Redact JSON-like strings with sensitive keys
    text = re.sub(
        r'("(?:password|passwd|pwd|api_key|apikey|token|secret|auth|authorization|bearer)":\s*")[^"]*(")',
        r'\1***REDACTED***\2',
        text,
        flags=re.IGNORECASE
    )

    return text


def redact_log_message(msg: str, *args: Any, **kwargs: Any) -> tuple[str, tuple[Any, ...], dict[str, Any]]:
    """
    Redact sensitive data from log message and arguments.

    Use this before passing to logger:
    ```python
    msg, args, kwargs = redact_log_message("User %s logged in with token: %s", username, token)
    logger.info(msg, *args, **kwargs)
    ```

    Args:
        msg: Log message format string
        *args: Positional arguments for log message
        **kwargs: Keyword arguments for log message

    Returns:
        Tuple of (redacted_msg, redacted_args, redacted_kwargs)
    """
    # Redact the message itself
    redacted_msg = _redact_string(msg)

    # Redact args
    redacted_args = tuple(redact_sensitive_data(arg) for arg in args)

    # Redact kwargs
    redacted_kwargs = {k: redact_sensitive_data(v) for k, v in kwargs.items()}

    return redacted_msg, redacted_args, redacted_kwargs
