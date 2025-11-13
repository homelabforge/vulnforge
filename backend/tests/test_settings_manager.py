"""Tests for SettingsManager service."""

import pytest
from app.models import Setting
from app.services.settings_manager import SettingsManager


@pytest.mark.asyncio
class TestSettingsRetrieval:
    """Tests for settings retrieval."""

    async def test_get_existing_setting(self, db_with_settings):
        """Test retrieving an existing setting."""
        manager = SettingsManager(db_with_settings)

        value = await manager.get("auth_enabled")
        assert value is not None
        assert isinstance(value, str)

    async def test_get_nonexistent_setting_returns_default(self, db_session):
        """Test that nonexistent setting returns default value."""
        manager = SettingsManager(db_session)

        value = await manager.get("nonexistent_key", default="default_value")
        assert value == "default_value"

    async def test_get_setting_from_defaults(self, db_session):
        """Test retrieving setting from DEFAULTS when not in database."""
        manager = SettingsManager(db_session)

        value = await manager.get("auth_enabled")
        assert value == "false"  # Default value from DEFAULTS


@pytest.mark.asyncio
class TestSettingsTypeConversion:
    """Tests for settings type conversion."""

    async def test_get_int_valid(self, db_session):
        """Test getting integer setting with valid value."""
        manager = SettingsManager(db_session)

        # Add integer setting
        setting = Setting(key="test_int", value="42")
        db_session.add(setting)
        await db_session.commit()

        value = await manager.get_int("test_int")
        assert value == 42
        assert isinstance(value, int)

    async def test_get_int_invalid_returns_default(self, db_session):
        """Test that invalid integer returns default."""
        manager = SettingsManager(db_session)

        # Add invalid integer
        setting = Setting(key="test_invalid_int", value="not_a_number")
        db_session.add(setting)
        await db_session.commit()

        value = await manager.get_int("test_invalid_int", default=0)
        assert value == 0

    async def test_get_bool_true_variations(self, db_session):
        """Test boolean conversion for various true values."""
        manager = SettingsManager(db_session)

        true_values = ["true", "True", "TRUE", "1", "yes", "Yes"]

        for i, val in enumerate(true_values):
            setting = Setting(key=f"bool_test_{i}", value=val)
            db_session.add(setting)

        await db_session.commit()

        for i, val in enumerate(true_values):
            result = await manager.get_bool(f"bool_test_{i}")
            assert result is True, f"Failed for value: {val}"

    async def test_get_bool_false_variations(self, db_session):
        """Test boolean conversion for various false values."""
        manager = SettingsManager(db_session)

        false_values = ["false", "False", "FALSE", "0", "no", "No"]

        for i, val in enumerate(false_values):
            setting = Setting(key=f"bool_false_{i}", value=val)
            db_session.add(setting)

        await db_session.commit()

        for i, val in enumerate(false_values):
            result = await manager.get_bool(f"bool_false_{i}")
            assert result is False, f"Failed for value: {val}"


@pytest.mark.asyncio
class TestSettingsUpdate:
    """Tests for settings update operations."""

    async def test_set_new_setting(self, db_session):
        """Test creating a new setting."""
        manager = SettingsManager(db_session)

        await manager.set("new_key", "new_value")

        # Verify it was saved
        value = await manager.get("new_key")
        assert value == "new_value"

    async def test_update_existing_setting(self, db_with_settings):
        """Test updating an existing setting."""
        manager = SettingsManager(db_with_settings)

        # Update existing
        await manager.set("auth_enabled", "true")

        # Verify update
        value = await manager.get("auth_enabled")
        assert value == "true"

    async def test_bulk_update_settings(self, db_session):
        """Test bulk updating multiple settings."""
        manager = SettingsManager(db_session)

        settings_dict = {
            "key1": "value1",
            "key2": "value2",
            "key3": "value3"
        }

        for key, value in settings_dict.items():
            await manager.set(key, value)

        # Verify all were updated
        for key, expected_value in settings_dict.items():
            value = await manager.get(key)
            assert value == expected_value


@pytest.mark.asyncio
class TestSettingsJSONHandling:
    """Tests for settings with JSON values."""

    async def test_get_json_list(self, db_session):
        """Test retrieving JSON list setting."""
        manager = SettingsManager(db_session)

        import json
        json_value = json.dumps(["item1", "item2", "item3"])

        setting = Setting(key="test_list", value=json_value)
        db_session.add(setting)
        await db_session.commit()

        value = await manager.get("test_list")
        parsed = json.loads(value)
        assert isinstance(parsed, list)
        assert len(parsed) == 3

    async def test_get_json_dict(self, db_session):
        """Test retrieving JSON dict setting."""
        manager = SettingsManager(db_session)

        import json
        json_value = json.dumps({"key1": "value1", "key2": "value2"})

        setting = Setting(key="test_dict", value=json_value)
        db_session.add(setting)
        await db_session.commit()

        value = await manager.get("test_dict")
        parsed = json.loads(value)
        assert isinstance(parsed, dict)
        assert parsed["key1"] == "value1"

    async def test_invalid_json_handling(self, db_session):
        """Test handling of invalid JSON in settings."""
        manager = SettingsManager(db_session)

        # Store invalid JSON
        setting = Setting(key="invalid_json", value="{invalid json[")
        db_session.add(setting)
        await db_session.commit()

        # Should return the raw value, let caller handle parsing
        value = await manager.get("invalid_json")
        assert value == "{invalid json["


@pytest.mark.asyncio
class TestSettingsDefaults:
    """Tests for default settings values."""

    async def test_all_defaults_accessible(self, db_session):
        """Test that all DEFAULTS are accessible."""
        manager = SettingsManager(db_session)

        # Test a few key defaults
        default_keys = [
            "auth_enabled",
            "auth_provider",
            "scan_schedule",
            "ntfy_enabled"
        ]

        for key in default_keys:
            value = await manager.get(key)
            assert value is not None
            assert value == SettingsManager.DEFAULTS.get(key)

    async def test_defaults_not_overwritten(self, db_session):
        """Test that DEFAULTS dict is not modified."""
        manager = SettingsManager(db_session)

        original_defaults = SettingsManager.DEFAULTS.copy()

        # Get some settings
        await manager.get("auth_enabled")
        await manager.get("scan_schedule")

        # Verify DEFAULTS unchanged
        assert SettingsManager.DEFAULTS == original_defaults


@pytest.mark.asyncio
class TestSettingsCacheInvalidation:
    """Tests for cache invalidation after updates."""

    async def test_cache_invalidated_after_set(self, db_with_settings):
        """Test that cache is invalidated after setting update."""
        manager = SettingsManager(db_with_settings)

        # Get value (may cache)
        value1 = await manager.get("auth_enabled")

        # Update value
        await manager.set("auth_enabled", "true")

        # Get again - should reflect update
        value2 = await manager.get("auth_enabled")

        assert value2 == "true"

    async def test_multiple_updates_reflected(self, db_with_settings):
        """Test that sequential updates are immediately reflected."""
        manager = SettingsManager(db_with_settings)

        updates = {
            "auth_enabled": "true",
            "auth_provider": "authentik",
        }

        for key, value in updates.items():
            await manager.set(key, value)

        # Verify both updates are visible
        for key, value in updates.items():
            assert await manager.get(key) == value
