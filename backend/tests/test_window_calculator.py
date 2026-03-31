"""
Unit tests for exposure window calculator.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from backend.window.calculator import (
    EXPOSURE_WINDOW_TIMEOUT_SECONDS,
    REVOCATION_CHECK_INTERVAL_SECONDS,
    record_exposure_start,
    is_key_revoked,
    close_exposure_window,
    monitor_exposure_window,
    start_window_monitor,
    stop_window_monitor,
    _active_monitors,
)


@pytest.fixture(autouse=True)
def clear_active_monitors():
    _active_monitors.clear()
    yield
    _active_monitors.clear()


class TestRecordExposureStart:

    def test_parse_iso_z(self):
        result = record_exposure_start("2026-03-30T12:34:56Z")
        assert result.year == 2026
        assert result.tzinfo is not None

    def test_parse_offset(self):
        result = record_exposure_start("2026-03-30T12:34:56+00:00")
        assert result.month == 3

    def test_microseconds(self):
        result = record_exposure_start("2026-03-30T12:34:56.123456Z")
        assert result.microsecond == 123456

    def test_invalid_format(self):
        with pytest.raises(ValueError):
            record_exposure_start("invalid")


class TestIsKeyRevoked:

    def _err(self, code):
        return ClientError(
            {"Error": {"Code": code, "Message": "err"}},
            "GetCallerIdentity",
        )

    @patch("backend.window.calculator.boto3.client")
    @patch("backend.window.calculator.config")
    def test_active_key(self, mock_config, mock_client):
        mock_config.AWS_ACCESS_KEY_ID = "test_key"
        mock_config.AWS_SECRET_ACCESS_KEY = "test_secret"
        mock_config.AWS_REGION = "us-east-1"
        
        mock_sts = MagicMock()
        mock_client.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {}

        assert is_key_revoked("key") is False

    @patch("backend.window.calculator.boto3.client")
    @patch("backend.window.calculator.config")
    def test_revoked_key(self, mock_config, mock_client):
        mock_config.AWS_ACCESS_KEY_ID = "test_key"
        mock_config.AWS_SECRET_ACCESS_KEY = "test_secret"
        mock_config.AWS_REGION = "us-east-1"
        
        mock_sts = MagicMock()
        mock_client.return_value = mock_sts
        mock_sts.get_caller_identity.side_effect = self._err("InvalidClientTokenId")

        assert is_key_revoked("key") is True

    @patch("backend.window.calculator.boto3.client")
    @patch("backend.window.calculator.config")
    def test_expired_token(self, mock_config, mock_client):
        mock_config.AWS_ACCESS_KEY_ID = "test_key"
        mock_config.AWS_SECRET_ACCESS_KEY = "test_secret"
        mock_config.AWS_REGION = "us-east-1"
        
        mock_sts = MagicMock()
        mock_client.return_value = mock_sts
        mock_sts.get_caller_identity.side_effect = self._err("ExpiredTokenException")

        assert is_key_revoked("key") is True

    @patch("backend.window.calculator.boto3.client")
    @patch("backend.window.calculator.config")
    def test_other_error(self, mock_config, mock_client):
        mock_config.AWS_ACCESS_KEY_ID = "test_key"
        mock_config.AWS_SECRET_ACCESS_KEY = "test_secret"
        mock_config.AWS_REGION = "us-east-1"
        
        mock_sts = MagicMock()
        mock_client.return_value = mock_sts
        mock_sts.get_caller_identity.side_effect = self._err("AccessDenied")

        assert is_key_revoked("key") is False

    @patch("backend.window.calculator.boto3.client")
    @patch("backend.window.calculator.config")
    def test_runtime_error(self, mock_config, mock_client):
        mock_config.AWS_ACCESS_KEY_ID = "test_key"
        mock_config.AWS_SECRET_ACCESS_KEY = "test_secret"
        mock_config.AWS_REGION = "us-east-1"
        
        mock_sts = MagicMock()
        mock_client.return_value = mock_sts
        mock_sts.get_caller_identity.side_effect = RuntimeError("fail")

        assert is_key_revoked("key") is False

    @patch("backend.window.calculator.boto3.client")
    @patch("backend.window.calculator.config")
    def test_custom_credentials(self, mock_config, mock_client):
        mock_config.AWS_REGION = "us-east-1"
        
        mock_sts = MagicMock()
        mock_client.return_value = mock_sts
        mock_sts.get_caller_identity.return_value = {}

        creds = {"access_key_id": "temp", "secret_access_key": "secret"}

        is_key_revoked("key", admin_credentials=creds)

        _, kwargs = mock_client.call_args
        assert kwargs["aws_access_key_id"] == "temp"
        assert kwargs["aws_secret_access_key"] == "secret"


class TestCloseExposureWindow:

    def test_close_sets_time(self):
        mock_db = MagicMock()
        mock_incident = MagicMock()
        mock_incident.exposure_end = None

        mock_db.query.return_value.filter_by.return_value.first.return_value = mock_incident

        before = datetime.now(timezone.utc)
        close_exposure_window("id", mock_db)
        after = datetime.now(timezone.utc)

        assert before <= mock_incident.exposure_end <= after
        mock_db.commit.assert_called_once()

    def test_already_closed(self):
        mock_db = MagicMock()
        mock_incident = MagicMock()
        mock_incident.exposure_end = datetime.now(timezone.utc)

        mock_db.query.return_value.filter_by.return_value.first.return_value = mock_incident

        close_exposure_window("id", mock_db)
        mock_db.commit.assert_not_called()

    def test_missing_incident(self):
        mock_db = MagicMock()
        mock_db.query.return_value.filter_by.return_value.first.return_value = None

        with pytest.raises(ValueError):
            close_exposure_window("id", mock_db)


class TestMonitorExposureWindow:

    @pytest.mark.asyncio
    async def test_revocation_stops_monitor(self):
        mock_db = MagicMock()

        with patch("backend.window.calculator.is_key_revoked", return_value=True), \
             patch("backend.window.calculator.close_exposure_window") as mock_close:

            await monitor_exposure_window("id", "key", mock_db)

            mock_close.assert_called_once()

    @pytest.mark.asyncio
    async def test_timeout_stops_monitor(self):
        mock_db = MagicMock()

        with patch("backend.window.calculator.is_key_revoked", return_value=False), \
             patch("backend.window.calculator.close_exposure_window") as mock_close, \
             patch("backend.window.calculator.asyncio.sleep", return_value=None), \
             patch("backend.window.calculator.EXPOSURE_WINDOW_TIMEOUT_SECONDS", 0):

            await monitor_exposure_window("id", "key", mock_db)

            mock_close.assert_called_once()

    @pytest.mark.asyncio
    async def test_monitor_cancel(self):
        mock_db = MagicMock()

        with patch("backend.window.calculator.is_key_revoked", return_value=False), \
             patch("backend.window.calculator.asyncio.sleep", return_value=None):

            task = asyncio.create_task(
                monitor_exposure_window("id", "key", mock_db)
            )

            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                pass
class TestMonitorManagement:

    def test_start_monitor(self):
        mock_db = MagicMock()

        with patch("backend.window.calculator.asyncio.create_task") as mock_create:
            mock_create.return_value = MagicMock()

            start_window_monitor("id", "key", mock_db)

            assert "id" in _active_monitors
            mock_create.assert_called_once()

    def test_prevent_duplicate(self):
        mock_db = MagicMock()
        mock_task = MagicMock()

        with patch("backend.window.calculator.asyncio.create_task", return_value=mock_task):
            start_window_monitor("id", "key", mock_db)
            start_window_monitor("id", "key", mock_db)

        assert len(_active_monitors) == 1

    def test_stop_monitor(self):
        mock_task = MagicMock()
        _active_monitors["id"] = mock_task

        stop_window_monitor("id")

        mock_task.cancel.assert_called_once()
        assert "id" not in _active_monitors

    def test_stop_missing(self):
        stop_window_monitor("missing")


class TestConstants:

    def test_timeout(self):
        assert EXPOSURE_WINDOW_TIMEOUT_SECONDS == 600

    def test_interval(self):
        assert REVOCATION_CHECK_INTERVAL_SECONDS == 60

    def test_ratio(self):
        assert EXPOSURE_WINDOW_TIMEOUT_SECONDS % REVOCATION_CHECK_INTERVAL_SECONDS == 0