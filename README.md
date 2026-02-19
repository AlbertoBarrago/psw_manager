# Password Manager

A desktop password manager built with Python and Tkinter. Passwords are encrypted with [Fernet](https://cryptography.io/en/latest/fernet/) symmetric encryption (AES-128-CBC) before being stored locally in a JSON file.

## Features

- Generate strong 20-character passwords (letters, digits, punctuation) using Python's `secrets` module
- Encrypt and store credentials (website, email, password) locally in `passwords.json`
- Search stored credentials by website with security code verification before decryption
- View all stored websites and emails (password values remain hidden)
- Copy passwords to clipboard automatically on generation or on demand
- Dark-themed Tkinter GUI

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.8+ |
| GUI | Tkinter (stdlib) |
| Encryption | `cryptography` — Fernet (AES-128-CBC + HMAC-SHA256) |
| Key derivation | SHA-256 via `hashlib` |
| Env config | `python-dotenv` |
| Clipboard | `pyperclip` |
| Package manager | `uv` |

## Security Design

- The `SECRET_KEY` from `.env` is hashed with SHA-256 and base64-encoded to produce a valid Fernet key
- Passwords are encrypted before being written to disk — the JSON file never contains plaintext
- Accessing or decrypting any stored password requires re-entering the security code at runtime
- Password generation uses `secrets.choice` (cryptographically secure RNG), not `random`

## Setup

```bash
# 1. Install dependencies
uv sync

# 2. Create environment file
touch .env
```

Add to `.env`:
```
SECRET_KEY='your_secret_key'
SECRET_USER_EMAIL='your@email.com'
```

```bash
# 3. Run
python3 main.py
```

## Testing

```bash
uv run pytest tests/ -v
```

## Project Structure

```
psw_manager/
├── main.py                  # Entry point
├── psw_manager/
│   └── psw_service.py       # PasswordManager class (GUI + business logic)
├── pyproject.toml           # Project metadata and dependencies
├── .env                     # Secret key and default email (not committed)
└── passwords.json           # Encrypted credentials store (created on first save)
```

## Screenshots

![img_1.png](img_1.png)
