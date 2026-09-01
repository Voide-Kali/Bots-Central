from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import voice_vault


MASTER = "MestraForte123!"
NEW_MASTER = "NovaMestra123!"


class VoiceVaultTests(unittest.TestCase):
    def test_vault_saves_lists_finds_and_deletes_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault_file = Path(directory) / "vault.json"
            with (
                patch.object(voice_vault, "VAULT_FILE", vault_file),
                patch.object(voice_vault, "KDF_ITERATIONS", 1000),
                patch.object(voice_vault, "MIN_KDF_ITERATIONS", 1000),
            ):
                voice_vault.save_entry(MASTER, "GitHub", "voide", "senha-super-forte", "https://github.com")
                listed = voice_vault.list_entries(MASTER)
                found = voice_vault.find_entry(MASTER, "GitHub")
                deleted = voice_vault.delete_entry(MASTER, "GitHub")

        self.assertEqual(listed[0]["label"], "GitHub")
        self.assertNotIn("password", listed[0])
        self.assertIsNotNone(found)
        self.assertEqual(found["password"], "senha-super-forte")
        self.assertTrue(deleted)

    def test_vault_rejects_wrong_master_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault_file = Path(directory) / "vault.json"
            with (
                patch.object(voice_vault, "VAULT_FILE", vault_file),
                patch.object(voice_vault, "KDF_ITERATIONS", 1000),
                patch.object(voice_vault, "MIN_KDF_ITERATIONS", 1000),
            ):
                voice_vault.save_entry(MASTER, "Email", "user", "secret")
                with self.assertRaises(voice_vault.VaultError):
                    voice_vault.list_entries("errada")

    def test_vault_searches_safe_entry_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault_file = Path(directory) / "vault.json"
            with (
                patch.object(voice_vault, "VAULT_FILE", vault_file),
                patch.object(voice_vault, "KDF_ITERATIONS", 1000),
                patch.object(voice_vault, "MIN_KDF_ITERATIONS", 1000),
            ):
                voice_vault.save_entry(MASTER, "GitHub", "voide", "secret", "https://github.com")
                voice_vault.save_entry(MASTER, "Email", "conta", "secret")
                matches = voice_vault.search_entries(MASTER, "git")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["label"], "GitHub")
        self.assertNotIn("password", matches[0])

    def test_change_master_password_preserves_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault_file = Path(directory) / "vault.json"
            with (
                patch.object(voice_vault, "VAULT_FILE", vault_file),
                patch.object(voice_vault, "KDF_ITERATIONS", 1000),
                patch.object(voice_vault, "MIN_KDF_ITERATIONS", 1000),
            ):
                voice_vault.save_entry(MASTER, "Email", "voide", "secret")
                count = voice_vault.change_master_password(MASTER, NEW_MASTER)
                found = voice_vault.find_entry(NEW_MASTER, "Email")
                with self.assertRaises(voice_vault.VaultError):
                    voice_vault.list_entries(MASTER)

        self.assertEqual(count, 1)
        self.assertIsNotNone(found)
        self.assertEqual(found["password"], "secret")

    def test_new_vault_rejects_weak_master_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault_file = Path(directory) / "vault.json"
            with patch.object(voice_vault, "VAULT_FILE", vault_file):
                with self.assertRaises(voice_vault.VaultError):
                    voice_vault.save_entry("fraca", "Email", "voide", "secret")


if __name__ == "__main__":
    unittest.main()
