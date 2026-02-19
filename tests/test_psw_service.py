import json
import logging
import string
import os
import pytest
from unittest.mock import patch, MagicMock

# Set env vars before the module is imported so load_dotenv doesn't raise
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("SECRET_USER_EMAIL", "test@test.com")

from psw_manager.psw_service import PasswordManager  # noqa: E402

TEST_KEY = "test-secret-key"


@pytest.fixture
def manager():
    with patch("psw_manager.psw_service.Tk") as MockTk, \
         patch("psw_manager.psw_service.logging.FileHandler", return_value=logging.NullHandler()), \
         patch("psw_manager.psw_service.SECRET_KEY", TEST_KEY), \
         patch.object(PasswordManager, "setup_ui"):
        MockTk.return_value = MagicMock()
        m = PasswordManager(default_email="test@test.com")

    m.website_entry = MagicMock()
    m.email_entry = MagicMock()
    m.password_entry = MagicMock()
    return m


# ── Crypto ────────────────────────────────────────────────────────────────────

class TestGenerateKey:
    def test_is_deterministic(self, manager):
        assert manager.generate_key("abc") == manager.generate_key("abc")

    def test_differs_for_different_input(self, manager):
        assert manager.generate_key("abc") != manager.generate_key("xyz")

    def test_returns_bytes(self, manager):
        assert isinstance(manager.generate_key("abc"), bytes)


class TestEncryptDecrypt:
    def test_roundtrip(self, manager):
        with patch("psw_manager.psw_service.SECRET_KEY", TEST_KEY):
            encrypted = manager.encrypt_password("my-secret-password")
            # decrypt_password expects the JSON-stored shape: {"password": ...}
            stored = {"password": encrypted["encrypted"]}
            assert manager.decrypt_password(stored) == "my-secret-password"

    def test_output_is_not_plaintext(self, manager):
        with patch("psw_manager.psw_service.SECRET_KEY", TEST_KEY):
            result = manager.encrypt_password("my-secret-password")
            assert result["encrypted"] != "my-secret-password"

    def test_fernet_iv_makes_output_unique(self, manager):
        # Fernet includes a random IV, so identical inputs produce different ciphertext
        with patch("psw_manager.psw_service.SECRET_KEY", TEST_KEY):
            enc1 = manager.encrypt_password("same")["encrypted"]
            enc2 = manager.encrypt_password("same")["encrypted"]
            assert enc1 != enc2


# ── Password generation ───────────────────────────────────────────────────────

class TestGeneratePassword:
    def test_length_is_20_chars(self, manager):
        with patch("psw_manager.psw_service.pyperclip"):
            manager.generate_password()
        generated = manager.password_entry.insert.call_args[0][1]
        assert len(generated) == 20

    def test_only_valid_characters(self, manager):
        with patch("psw_manager.psw_service.pyperclip"):
            manager.generate_password()
        generated = manager.password_entry.insert.call_args[0][1]
        valid = set(string.ascii_letters + string.digits + string.punctuation)
        assert all(c in valid for c in generated)

    def test_copies_to_clipboard(self, manager):
        with patch("psw_manager.psw_service.pyperclip") as mock_clip:
            manager.generate_password()
        mock_clip.copy.assert_called_once()

    def test_two_passwords_differ(self, manager):
        with patch("psw_manager.psw_service.pyperclip"):
            manager.generate_password()
            p1 = manager.password_entry.insert.call_args[0][1]
            manager.generate_password()
            p2 = manager.password_entry.insert.call_args[0][1]
        assert p1 != p2


# ── Save ──────────────────────────────────────────────────────────────────────

class TestSave:
    def test_warns_when_fields_empty(self, manager):
        manager.website_entry.get.return_value = ""
        manager.email_entry.get.return_value = ""
        manager.password_entry.get.return_value = ""

        with patch("psw_manager.psw_service.messagebox") as mock_mb, \
             patch("psw_manager.psw_service.SECRET_KEY", TEST_KEY):
            manager.save()

        mock_mb.showwarning.assert_called_once()

    def test_saves_encrypted_entry(self, manager, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        manager.website_entry.get.return_value = "example.com"
        manager.email_entry.get.return_value = "user@example.com"
        manager.password_entry.get.return_value = "plaintext"

        with patch("psw_manager.psw_service.messagebox"), \
             patch("psw_manager.psw_service.SECRET_KEY", TEST_KEY):
            manager.save()

        data = json.loads((tmp_path / "passwords.json").read_text())
        assert "example.com" in data
        assert data["example.com"]["email"] == "user@example.com"
        assert data["example.com"]["password"] != "plaintext"

    def test_existing_entries_are_preserved(self, manager, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        existing = {"old-site.com": {"email": "a@b.com", "password": "enc", "created_at": "2024"}}
        (tmp_path / "passwords.json").write_text(json.dumps(existing))

        manager.website_entry.get.return_value = "new-site.com"
        manager.email_entry.get.return_value = "new@example.com"
        manager.password_entry.get.return_value = "newpass"

        with patch("psw_manager.psw_service.messagebox"), \
             patch("psw_manager.psw_service.SECRET_KEY", TEST_KEY):
            manager.save()

        data = json.loads((tmp_path / "passwords.json").read_text())
        assert "old-site.com" in data
        assert "new-site.com" in data


# ── Search ────────────────────────────────────────────────────────────────────

class TestSearchPassword:
    def test_shows_info_when_no_file(self, manager, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        manager.website_entry.get.return_value = "example.com"

        with patch("psw_manager.psw_service.messagebox") as mock_mb:
            manager.search_password()

        mock_mb.showinfo.assert_called_once()

    def test_shows_not_found_for_unknown_site(self, manager, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "passwords.json").write_text(json.dumps({"other.com": {}}))
        manager.website_entry.get.return_value = "missing.com"

        with patch("psw_manager.psw_service.messagebox") as mock_mb:
            manager.search_password()

        mock_mb.showinfo.assert_called_once_with("Not Found", "No details found for missing.com")

    def test_rejects_wrong_security_code(self, manager, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "passwords.json").write_text(json.dumps({"example.com": {"password": "enc", "email": "a@b.com"}}))
        manager.website_entry.get.return_value = "example.com"

        with patch("psw_manager.psw_service.messagebox") as mock_mb, \
             patch("psw_manager.psw_service.simpledialog") as mock_dlg, \
             patch("psw_manager.psw_service.SECRET_KEY", TEST_KEY):
            mock_dlg.askstring.return_value = "wrong-code"
            manager.search_password()

        mock_mb.showerror.assert_called_once()
