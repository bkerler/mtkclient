#!/usr/bin/env python3
# MTK Flash Client (c) B.Kerler 2018-2025
# Licensed under GPLv3 License
"""Tests for the minimal i18n layer (mtkclient.i18n).

Covers the three contract points:
  * default language is "en" (upstream behavior unchanged),
  * MTK_LANG / --lang=ru switches user-facing surfaces to Russian,
  * unknown language codes fall back to "en".
"""
import ast
import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from mtkclient import i18n  # noqa: E402
from mtkclient.i18n import (  # noqa: E402
    DEFAULT_LANG, LANG_ENV_VAR, activate, get_lang, set_lang, t)


def _clean_env():
    env = dict(os.environ)
    env.pop(LANG_ENV_VAR, None)
    return env


class I18nActivationTest(unittest.TestCase):
    def setUp(self):
        set_lang(DEFAULT_LANG)

    def tearDown(self):
        set_lang(DEFAULT_LANG)

    def test_default_is_english(self):
        activate(argv=None, env=_clean_env())
        self.assertEqual(get_lang(), "en")
        self.assertEqual(t("Erase partition"), "Erase partition")

    def test_env_var_activates_russian(self):
        activate(argv=None, env={LANG_ENV_VAR: "ru"})
        self.assertEqual(get_lang(), "ru")
        self.assertEqual(t("Erase partition"), "Стереть раздел")

    def test_unknown_language_falls_back_to_english(self):
        activate(argv=None, env={LANG_ENV_VAR: "zz"})
        self.assertEqual(get_lang(), "en")

    def test_lang_flag_beats_environment(self):
        activate(argv=["--lang", "en"], env={LANG_ENV_VAR: "ru"})
        self.assertEqual(get_lang(), "en")

    def test_lang_flag_equals_form(self):
        activate(argv=["--lang=ru"], env=_clean_env())
        self.assertEqual(get_lang(), "ru")

    def test_missing_key_passes_through(self):
        set_lang("ru")
        self.assertEqual(t("definitely not a translated key"),
                         "definitely not a translated key")

    def test_lang_value_is_normalized(self):
        activate(argv=None, env={LANG_ENV_VAR: " RU "})
        self.assertEqual(get_lang(), "ru")


class I18nKeyCoverageTest(unittest.TestCase):
    """Ratchet: every constant t("...") key in user-facing code must have a
    Russian entry — a typo would otherwise silently fall back to English."""

    def _t_call_constants(self, path):
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        keys = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "t" and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                keys.add(node.args[0].value)
        return keys

    def test_every_used_key_is_translated(self):
        ru_table = i18n._TRANSLATIONS["ru"]
        for source in ("mtk.py", "mtk_gui.py"):
            keys = self._t_call_constants(os.path.join(REPO_ROOT, source))
            missing = keys - set(ru_table)
            self.assertEqual(missing, set(),
                             f"{source}: keys without ru translation: {sorted(missing)}")


class CliSmokeTest(unittest.TestCase):
    """End-to-end: the CLI help renders in the selected language."""

    def _run_mtk_help(self, env_overrides, *cli_args):
        env = _clean_env()
        env.update(env_overrides)
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "mtk.py"), *cli_args],
            env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    def test_russian_help_is_rendered(self):
        out = self._run_mtk_help({LANG_ENV_VAR: "ru"}, "--help")
        self.assertIn("Стереть раздел", out)
        self.assertIn("Подключение и интерфейс", out)

    def test_russian_subcommand_help_is_rendered(self):
        out = self._run_mtk_help({LANG_ENV_VAR: "ru"}, "e", "--help")
        # Note: a subcommand's own help page shows its arguments (the command
        # description itself only appears in the top-level command list).
        self.assertIn("Раздел для стирания", out)
        self.assertIn("Подключение и интерфейс", out)

    def test_default_help_stays_english(self):
        out = self._run_mtk_help({}, "--help")
        self.assertIn("Erase partition", out)
        self.assertNotIn("Стереть раздел", out)

    def test_unknown_language_help_is_english(self):
        out = self._run_mtk_help({LANG_ENV_VAR: "zz"}, "--help")
        self.assertIn("Erase partition", out)
        self.assertNotIn("Стереть раздел", out)

    def test_lang_flag_selects_russian(self):
        out = self._run_mtk_help({}, "--lang", "ru", "e", "--help")
        self.assertIn("Раздел для стирания", out)


if __name__ == "__main__":
    unittest.main()
