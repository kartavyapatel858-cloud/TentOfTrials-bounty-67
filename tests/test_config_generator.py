#!/usr/bin/env python3
"""
Unit tests for tools/config_generator.py.

Validates:
- Deduplication and content of SENSITIVE_KEYS.
- Recursive configuration merging with merge_config(), ensuring unrelated
  nested keys remain intact and inputs are not mutated.
- Environment configuration generation with generate_config() for development,
  production, staging, and unknown environments, as well as custom overrides.
- Sensitive value masking with mask_sensitive(), verifying database, Redis,
  and JWT secrets are redacted while non-sensitive fields remain unchanged.
- Serializers (to_json, to_dotenv, to_k8s_configmap).
"""

import copy
import json
import os
import sys
import unittest
from pathlib import Path

# Add project root and tools directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"
sys.path.insert(0, str(TOOLS_DIR))
sys.path.insert(0, str(PROJECT_ROOT))

from config_generator import (
    DEFAULT_CONFIG,
    ENV_OVERRIDES,
    SENSITIVE_KEYS,
    generate_config,
    mask_sensitive,
    merge_config,
    to_dotenv,
    to_json,
    to_k8s_configmap,
)


class TestSensitiveKeys(unittest.TestCase):
    """Validation coverage for SENSITIVE_KEYS."""

    def test_sensitive_keys_deduplication(self):
        """Ensure SENSITIVE_KEYS contains no duplicate entries."""
        self.assertEqual(
            len(SENSITIVE_KEYS),
            len(set(SENSITIVE_KEYS)),
            f"SENSITIVE_KEYS contains duplicates: {SENSITIVE_KEYS}",
        )
        self.assertEqual(
            SENSITIVE_KEYS.count("auth.jwt_secret"),
            1,
            "auth.jwt_secret must appear exactly once",
        )

    def test_expected_sensitive_keys_present(self):
        """Ensure all required sensitive keys are present."""
        expected = {"database.password", "redis.password", "auth.jwt_secret"}
        self.assertTrue(
            expected.issubset(set(SENSITIVE_KEYS)),
            f"Missing expected keys: {expected - set(SENSITIVE_KEYS)}",
        )

    def test_sensitive_keys_type(self):
        """Ensure SENSITIVE_KEYS is a list of strings."""
        self.assertIsInstance(SENSITIVE_KEYS, list)
        for key in SENSITIVE_KEYS:
            self.assertIsInstance(key, str)


class TestMergeConfig(unittest.TestCase):
    """Validation coverage for merge_config()."""

    def test_merge_simple_keys(self):
        """Test overriding top-level scalar keys."""
        base = {"a": 1, "b": "hello"}
        override = {"b": "world", "c": True}
        result = merge_config(base, override)

        self.assertEqual(result["a"], 1)
        self.assertEqual(result["b"], "world")
        self.assertEqual(result["c"], True)

    def test_merge_nested_keys_preserves_unrelated(self):
        """Test that recursive merging does not mutate unrelated nested keys."""
        base = {
            "database": {
                "host": "localhost",
                "port": 5432,
                "credentials": {
                    "user": "admin",
                    "pool_size": 10,
                },
            },
            "server": {
                "port": 8080,
            },
        }
        override = {
            "database": {
                "port": 5433,
                "credentials": {
                    "pool_size": 25,
                },
            },
        }

        result = merge_config(base, override)

        # Overridden fields
        self.assertEqual(result["database"]["port"], 5433)
        self.assertEqual(result["database"]["credentials"]["pool_size"], 25)

        # Unrelated nested keys preserved
        self.assertEqual(result["database"]["host"], "localhost")
        self.assertEqual(result["database"]["credentials"]["user"], "admin")
        self.assertEqual(result["server"]["port"], 8080)

    def test_merge_does_not_mutate_inputs(self):
        """Ensure neither base nor override dictionaries are mutated in place."""
        base = {"nested": {"key1": "val1", "key2": "val2"}}
        override = {"nested": {"key2": "new_val"}}

        base_copy = copy.deepcopy(base)
        override_copy = copy.deepcopy(override)

        result = merge_config(base, override)

        self.assertEqual(base, base_copy, "merge_config mutated the base dict")
        self.assertEqual(override, override_copy, "merge_config mutated the override dict")
        self.assertEqual(result["nested"]["key2"], "new_val")

    def test_merge_with_empty_dictionaries(self):
        """Test merging with empty base and empty override."""
        self.assertEqual(merge_config({}, {}), {})

        base = {"k": "v"}
        self.assertEqual(merge_config(base, {}), base)
        self.assertEqual(merge_config({}, base), base)

    def test_merge_replace_scalar_with_dict_and_vice_versa(self):
        """Test overriding scalar with dict and dict with scalar."""
        base = {"section": "scalar_value"}
        override = {"section": {"nested": 123}}
        result1 = merge_config(base, override)
        self.assertEqual(result1["section"], {"nested": 123})

        base2 = {"section": {"nested": 123}}
        override2 = {"section": "scalar_value"}
        result2 = merge_config(base2, override2)
        self.assertEqual(result2["section"], "scalar_value")


class TestGenerateConfig(unittest.TestCase):
    """Validation coverage for generate_config()."""

    def test_generate_development_environment(self):
        """Verify development environment configuration overrides."""
        config = generate_config("development")

        # Overrides applied
        self.assertEqual(config["app"]["environment"], "development")
        self.assertTrue(config["app"]["debug"])
        self.assertEqual(config["app"]["log_level"], "debug")
        self.assertEqual(config["database"]["name"], "tent_dev")
        self.assertEqual(config["market"]["rate_limit_per_second"], 1000)
        self.assertEqual(config["auth"]["jwt_expiry_minutes"], 1440)

        # Defaults preserved
        self.assertEqual(config["server"]["port"], 8080)
        self.assertEqual(config["database"]["port"], 5432)
        self.assertEqual(config["redis"]["port"], 6379)
        self.assertTrue(config["features"]["web_socket"])

    def test_generate_production_environment(self):
        """Verify production environment configuration overrides."""
        config = generate_config("production")

        # Overrides applied
        self.assertEqual(config["app"]["environment"], "production")
        self.assertFalse(config["app"]["debug"])
        self.assertEqual(config["app"]["log_level"], "info")
        self.assertEqual(config["database"]["name"], "tent_production")
        self.assertEqual(config["database"]["pool_max"], 50)
        self.assertEqual(config["database"]["pool_min"], 10)
        self.assertEqual(config["market"]["rate_limit_per_second"], 10)
        self.assertEqual(config["market"]["rate_limit_burst"], 20)
        self.assertEqual(config["auth"]["jwt_expiry_minutes"], 60)
        self.assertTrue(config["auth"]["mfa_required"])
        self.assertEqual(config["monitoring"]["tracing_sample_rate"], 0.01)
        self.assertTrue(config["features"]["margin_trading"])

        # Defaults preserved
        self.assertEqual(config["server"]["port"], 8080)
        self.assertEqual(config["database"]["user"], "tent_app")

    def test_generate_staging_environment(self):
        """Verify staging environment configuration overrides."""
        config = generate_config("staging")

        self.assertEqual(config["app"]["environment"], "staging")
        self.assertEqual(config["database"]["name"], "tent_staging")
        self.assertEqual(config["database"]["pool_max"], 20)
        self.assertEqual(config["monitoring"]["tracing_sample_rate"], 0.5)

    def test_generate_unknown_environment(self):
        """Verify unknown environment falls back to default config without crash."""
        config = generate_config("unknown_environment")

        self.assertEqual(config["app"]["environment"], "development")
        self.assertEqual(config["server"]["port"], 8080)

    def test_generate_with_custom_overrides(self):
        """Verify user-provided overrides take highest precedence."""
        custom_overrides = {
            "server": {"port": 9999},
            "custom_section": {"enabled": True},
        }
        config = generate_config("production", overrides=custom_overrides)

        self.assertEqual(config["server"]["port"], 9999)
        self.assertEqual(config["server"]["host"], "0.0.0.0")  # preserved sibling
        self.assertEqual(config["custom_section"]["enabled"], True)
        self.assertEqual(config["app"]["environment"], "production")

    def test_generate_config_does_not_mutate_defaults(self):
        """Verify generate_config does not mutate DEFAULT_CONFIG or ENV_OVERRIDES."""
        default_copy = copy.deepcopy(DEFAULT_CONFIG)
        overrides_copy = copy.deepcopy(ENV_OVERRIDES)

        _ = generate_config("production", overrides={"app": {"name": "mutated"}})

        self.assertEqual(DEFAULT_CONFIG, default_copy)
        self.assertEqual(ENV_OVERRIDES, overrides_copy)


class TestMaskSensitive(unittest.TestCase):
    """Validation coverage for mask_sensitive()."""

    def test_mask_sensitive_database_redis_jwt(self):
        """Ensure database, Redis, and JWT secrets are redacted while non-sensitive fields remain visible."""
        config = generate_config("production")
        # Populate secrets
        config["database"]["password"] = "super_db_pass_123"
        config["redis"]["password"] = "super_redis_pass_456"
        config["auth"]["jwt_secret"] = "top_secret_jwt_key_789"

        masked = mask_sensitive(config)

        # Redacted sensitive values
        self.assertEqual(masked["database"]["password"], "***REDACTED***")
        self.assertEqual(masked["redis"]["password"], "***REDACTED***")
        self.assertEqual(masked["auth"]["jwt_secret"], "***REDACTED***")

        # Non-sensitive values remain visible and unaltered
        self.assertEqual(masked["database"]["host"], "localhost")
        self.assertEqual(masked["database"]["port"], 5432)
        self.assertEqual(masked["database"]["name"], "tent_production")
        self.assertEqual(masked["database"]["user"], "tent_app")
        self.assertEqual(masked["redis"]["host"], "localhost")
        self.assertEqual(masked["redis"]["port"], 6379)
        self.assertEqual(masked["redis"]["db"], 0)
        self.assertEqual(masked["auth"]["jwt_expiry_minutes"], 60)
        self.assertTrue(masked["auth"]["mfa_required"])
        self.assertEqual(masked["app"]["name"], "tent-of-trials")

    def test_mask_sensitive_input_immutability(self):
        """Ensure mask_sensitive does not mutate original input dictionary."""
        config = {
            "database": {"password": "secret", "name": "tent_dev"},
            "auth": {"jwt_secret": "myjwt"},
        }
        config_copy = copy.deepcopy(config)

        masked = mask_sensitive(config)

        self.assertEqual(config, config_copy, "mask_sensitive mutated the input dictionary")
        self.assertEqual(masked["database"]["password"], "***REDACTED***")
        self.assertEqual(config["database"]["password"], "secret")

    def test_mask_sensitive_empty_and_no_sensitive_keys(self):
        """Ensure mask_sensitive handles empty dictionaries or dicts without sensitive keys."""
        self.assertEqual(mask_sensitive({}), {})

        clean = {"app": {"name": "app", "version": "1.0"}}
        self.assertEqual(mask_sensitive(clean), clean)

    def test_mask_sensitive_custom_prefix(self):
        """Ensure prefix parameter is properly propagated in recursive calls."""
        nested = {"password": "secret_password"}
        masked = mask_sensitive(nested, prefix="database")
        self.assertEqual(masked["password"], "***REDACTED***")


class TestFormatGenerators(unittest.TestCase):
    """Validation coverage for configuration format output helpers."""

    def setUp(self):
        self.config = generate_config("development")

    def test_to_json(self):
        """Ensure to_json outputs valid JSON representing the configuration."""
        json_str = to_json(self.config, pretty=True)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["app"]["name"], "tent-of-trials")
        self.assertEqual(parsed["app"]["environment"], "development")

    def test_to_dotenv(self):
        """Ensure to_dotenv formats keys into standard environment variables."""
        dotenv_str = to_dotenv(self.config)
        self.assertIn("APP_NAME=tent-of-trials", dotenv_str)
        self.assertIn("APP_ENVIRONMENT=development", dotenv_str)
        self.assertIn("SERVER_PORT=8080", dotenv_str)

    def test_to_k8s_configmap(self):
        """Ensure to_k8s_configmap formats configuration into Kubernetes ConfigMap YAML."""
        k8s_str = to_k8s_configmap(self.config, name="test-config")
        self.assertIn("kind: ConfigMap", k8s_str)
        self.assertIn("name: test-config", k8s_str)
        self.assertIn("app: tent-of-trials", k8s_str)


if __name__ == "__main__":
    unittest.main()
