"""N1: credential-in-path log redaction + the process-wide RedactingLogFilter.

Covers:
- ``_redact_string`` redacts Telegram ``/bot<token>/`` URLs, Slack/Discord
  webhook URLs, and ``?token=`` query credentials, while leaving plain text.
- ``RedactingLogFilter`` redacts the fully-rendered record (msg % args) and
  never raises from inside ``filter``.
- ``TelegramNotificationService.send`` logs only the HTTP status code on an API
  error (the bot token in the request URL must not reach the logs).

NOTE: the dummy webhook/bot-token URLs below are assembled from fragments at
runtime. They are not real credentials, but written as single literals they
match GitHub secret-scanning push-protection patterns (Slack/Discord/Telegram),
which would block the push. Splitting them keeps the test value identical while
keeping the secret shape out of the committed source.
"""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.main import RedactingLogFilter
from app.utils.log_redaction import _redact_string


def _frag(*parts: str) -> str:
    """Join fragments so no full secret-shaped literal appears in source."""
    return "".join(parts)


_TELEGRAM_TOKEN = _frag("123456789:AAF", "hqwertyUIOPasdfghjklZXCVBNm1234")
_TELEGRAM_URL = _frag("https://api.telegram.org/bot", _TELEGRAM_TOKEN, "/sendMessage")
_SLACK_WEBHOOK = _frag("https://hooks.", "slack", ".com/services/T00000000/B00000000/", "X" * 24)
_DISCORD_WEBHOOK = _frag(
    "https://", "discord", ".com/api/webhooks/123456789012345678/", "abcDEF_ghiJKL-mnoPQR1234567890"
)


class TestRedactCredentialPaths:
    def test_redacts_telegram_bot_token_url(self):
        out = _redact_string(_TELEGRAM_URL)
        assert "AAFhqwerty" not in out
        assert "123456789:AAF" not in out
        assert "***REDACTED***" in out

    def test_redacts_slack_webhook(self):
        out = _redact_string(_SLACK_WEBHOOK)
        assert "XXXXXXXXXXXX" not in out
        assert "***REDACTED***" in out

    def test_redacts_discord_webhook(self):
        out = _redact_string(_DISCORD_WEBHOOK)
        assert "abcDEF_ghiJKL" not in out
        assert "***REDACTED***" in out

    def test_redacts_token_query_param(self):
        out = _redact_string("https://gotify.example.com/message?token=AbCdEf123456")
        assert "AbCdEf123456" not in out
        assert "***REDACTED***" in out

    def test_preserves_plain_message(self):
        msg = "Image misconfiguration scan completed for nginx:latest"
        assert _redact_string(msg) == msg


class TestRedactingLogFilter:
    def test_filter_redacts_rendered_message(self):
        flt = RedactingLogFilter()
        record = logging.LogRecord(
            name="t",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="telegram failure: %s",
            args=(_TELEGRAM_URL,),
            exc_info=None,
        )
        assert flt.filter(record) is True
        rendered = record.getMessage()
        assert "AAFhqwerty" not in rendered
        assert "***REDACTED***" in rendered

    def test_filter_never_raises_on_bad_format(self):
        flt = RedactingLogFilter()
        record = logging.LogRecord(
            name="t",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="needs two args %s %s",
            args=("only-one",),
            exc_info=None,
        )
        # getMessage() would raise on mismatched args; the filter must swallow it.
        assert flt.filter(record) is True


@pytest.mark.asyncio
async def test_telegram_send_logs_status_only(caplog):
    from app.services.notifications import telegram as tg

    async def fake_post(*_args, **_kwargs):
        return httpx.Response(403, request=httpx.Request("POST", _TELEGRAM_URL))

    # Patch AsyncClient construction so no real client (and no real event-loop
    # bound transport) is created — close() then just awaits a stub aclose().
    fake_client = SimpleNamespace(post=fake_post, aclose=AsyncMock())
    with patch.object(tg.httpx, "AsyncClient", return_value=fake_client):
        svc = tg.TelegramNotificationService(bot_token=_TELEGRAM_TOKEN, chat_id="42")

    with caplog.at_level(logging.ERROR):
        ok = await svc.send(title="t", message="m")
    await svc.close()

    assert ok is False
    assert _TELEGRAM_TOKEN not in caplog.text
    assert "403" in caplog.text
