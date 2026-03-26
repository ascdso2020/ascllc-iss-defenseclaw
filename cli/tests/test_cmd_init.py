"""Tests for 'defenseclaw init' command."""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.context import AppContext


class TestInitCommand(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-test-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_help(self):
        result = self.runner.invoke(init_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Initialize DefenseClaw environment", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_skip_install_creates_dirs(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertIn("Environment:", result.output)
        self.assertIn("Directories: created", result.output)
        self.assertIn("Config:", result.output)
        self.assertIn("Audit DB:", result.output)

        # Verify config file was created
        config_file = os.path.join(self.tmp_dir, "config.yaml")
        self.assertTrue(os.path.isfile(config_file))

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_logs_action(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        # The DB should have at least one event (the init action)
        from defenseclaw.db import Store
        db_path = os.path.join(self.tmp_dir, "audit.db")
        store = Store(db_path)
        events = store.list_events(10)
        self.assertTrue(len(events) >= 1)
        init_events = [e for e in events if e.action == "init"]
        self.assertEqual(len(init_events), 1, f"expected exactly one 'init' event, got actions: {[e.action for e in events]}")
        self.assertEqual(init_events[0].action, "init")
        store.close()

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_shows_openshell_macos_message(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertIn("not available on macOS", result.output)


class TestInitPreservesExistingConfig(unittest.TestCase):
    """Regression tests for P5 fix: init must not overwrite existing config."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-preserve-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_preserves_existing_config(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        # Run init once to create config
        app1 = AppContext()
        result1 = self.runner.invoke(init_cmd, ["--skip-install"], obj=app1)
        self.assertEqual(result1.exit_code, 0, result1.output)

        # Modify the config on disk so we can detect overwrites
        config_file = os.path.join(self.tmp_dir, "config.yaml")
        self.assertTrue(os.path.isfile(config_file))

        import yaml
        with open(config_file) as f:
            cfg_data = yaml.safe_load(f)

        cfg_data["gateway"] = cfg_data.get("gateway", {})
        cfg_data["gateway"]["host"] = "10.20.30.40"
        cfg_data["gateway"]["port"] = 99999

        with open(config_file, "w") as f:
            yaml.dump(cfg_data, f)

        # Run init again — should preserve
        app2 = AppContext()
        result2 = self.runner.invoke(init_cmd, ["--skip-install"], obj=app2)
        self.assertEqual(result2.exit_code, 0, result2.output)
        self.assertIn("preserved existing", result2.output)

        # Verify the customized values survived
        with open(config_file) as f:
            reloaded = yaml.safe_load(f)

        self.assertEqual(reloaded["gateway"]["host"], "10.20.30.40")
        self.assertEqual(reloaded["gateway"]["port"], 99999)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_creates_new_defaults_when_no_config(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("created new defaults", result.output)


class TestInitDoesNotCreateExternalDirs(unittest.TestCase):
    """Regression tests for P3 fix: init must not create dirs outside data_dir."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-scope-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_does_not_create_openclaw_dirs(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)

        for root, dirs, _files in os.walk(self.tmp_dir):
            for d in dirs:
                full = os.path.join(root, d)
                real = os.path.realpath(full)
                self.assertTrue(
                    real.startswith(os.path.realpath(self.tmp_dir)),
                    f"init created directory outside data_dir: {full}"
                )

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_creates_defenseclaw_dirs(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)

        # Core DefenseClaw dirs should exist
        self.assertTrue(os.path.isdir(self.tmp_dir))
        quarantine = os.path.join(self.tmp_dir, "quarantine")
        self.assertTrue(os.path.isdir(quarantine))
        plugins = os.path.join(self.tmp_dir, "plugins")
        self.assertTrue(os.path.isdir(plugins))


class TestInstallScanners(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_init._verify_scanner_sdk")
    def test_install_scanners_verifies_sdks(self, mock_verify):
        from defenseclaw.commands.cmd_init import _install_scanners
        from defenseclaw.config import default_config

        cfg = default_config()
        logger = MagicMock()

        _install_scanners(cfg, logger, skip=False)
        self.assertEqual(mock_verify.call_count, 2)
        call_names = [c[0][0] for c in mock_verify.call_args_list]
        self.assertIn("skill-scanner", call_names)
        self.assertIn("mcp-scanner", call_names)

    def test_install_scanners_skip(self):
        from defenseclaw.commands.cmd_init import _install_scanners
        from defenseclaw.config import default_config
        cfg = default_config()
        logger = MagicMock()

        # skip=True should print skip message without calling install
        _install_scanners(cfg, logger, skip=True)
        logger.log_action.assert_not_called()


if __name__ == "__main__":
    unittest.main()
