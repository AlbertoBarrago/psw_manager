"""
Password Manager application for securely storing and managing passwords.

This module provides a graphical user interface (GUI) to manage passwords,
generate new secure passwords, encrypt them, and securely store them. It allows
users to perform actions like saving credentials, searching stored credentials,
displaying all saved credentials, and generating random passwords.

Classes:
    PasswordManager: Provides functionalities for the password manager application.

Functions:
    _make_btn: Creates a styled button widget.
    _field_row: Creates a labeled input field row with an action button.
"""
from base64 import b64encode
from tkinter import messagebox, simpledialog, Tk, Toplevel, Text, Scrollbar, Button, Label, \
    StringVar, Entry, PhotoImage, Frame, TclError
from datetime import datetime
import os
import hashlib
import json
import secrets
import string
import logging

import pyperclip
from dotenv import load_dotenv

from cryptography.fernet import Fernet

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
SECRET_USER_EMAIL = os.getenv("SECRET_USER_EMAIL")

if not SECRET_KEY:
    raise ValueError("SECRET_KEY not set in .env file")

# ── Palette ───────────────────────────────────────────────────────────────────
BG = '#0f0f0f'
CARD = '#1a1a1a'
BORDER = '#2e2e2e'
BORDER_F = '#6366f1'
ACCENT = '#6366f1'
ACCENT_H = '#4f46e5'
TEXT = '#f1f5f9'
MUTED = '#64748b'
ENTRY_BG = '#141414'
BTN_SEC = '#262626'
BTN_SEC_H = '#323232'

# ── Typography ────────────────────────────────────────────────────────────────
FONT = ('Helvetica Neue', 13)
FONT_SM = ('Helvetica Neue', 11)
FONT_TITLE = ('Helvetica Neue', 20, 'bold')


# ── UI helpers ────────────────────────────────────────────────────────────

def _make_btn(parent, text, command, style='secondary'):
    bg, hover_bg = (ACCENT, ACCENT_H) if style == 'primary' else (BTN_SEC, BTN_SEC_H)

    frame = Frame(parent, bg=bg, cursor='hand2')
    label = Label(frame, text=text, bg=bg, fg=TEXT, font=FONT_SM, padx=16, pady=10, width=9, anchor='center')
    label.pack()

    for widget in (frame, label):
        widget.bind('<Button-1>', lambda e: command())
        widget.bind('<Enter>', lambda e: (frame.config(bg=hover_bg), label.config(bg=hover_bg)))
        widget.bind('<Leave>', lambda e: (frame.config(bg=bg), label.config(bg=bg)))

    return frame


def _field_row(parent, label, btn_text, command):
    Label(parent, text=label, bg=CARD, fg=MUTED, font=FONT_SM, anchor='w').pack(fill='x', pady=(16, 4))
    row = Frame(parent, bg=CARD)
    row.pack(fill='x')

    border = Frame(row, bg=BORDER)
    border.pack(side='left', fill='x', expand=True)

    inner = Frame(border, bg=ENTRY_BG)
    inner.pack(padx=1, pady=1, fill='x')

    entry = Entry(inner, bg=ENTRY_BG, fg=TEXT, font=FONT, bd=0,
                  highlightthickness=0, insertbackground=TEXT, relief='flat')
    entry.pack(padx=(10, 8), fill='x', ipady=8)

    entry.bind('<FocusIn>', lambda e, b=border: b.config(bg=BORDER_F))
    entry.bind('<FocusOut>', lambda e, b=border: b.config(bg=BORDER))

    _make_btn(row, btn_text, command).pack(side='left', padx=(8, 0))
    return entry


class PasswordManager:
    """
    Password Manager application for securely storing and managing passwords.
    """
    def __init__(self, default_email=SECRET_USER_EMAIL):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.default_email = default_email
        self.email_entry = None
        self.password_entry = None
        self.website_entry = None

        self.window = Tk()
        self.window.withdraw()
        self.window.title("Password Manager")
        self.window.config(bg=BG)
        self.window.resizable(False, False)

        handler = logging.FileHandler('audit.log')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        self.logo_img = None

        self.setup_ui()

        self.window.update_idletasks()
        w = self.window.winfo_reqwidth()
        h = self.window.winfo_reqheight()
        x = (self.window.winfo_screenwidth() // 2) - (w // 2)
        y = (self.window.winfo_screenheight() // 2) - (h // 2)
        self.window.geometry(f"+{x}+{y}")
        self.window.deiconify()
        self.window.lift()
        self.window.attributes("-topmost", True)
        self.window.after(200, lambda: self.window.attributes("-topmost", False))

    # ── Setup ─────────────────────────────────────────────────────────────────

    def setup_ui(self):
        # Header
        header = Frame(self.window, bg=BG)
        header.pack(fill='x', padx=30, pady=(30, 20))

        try:
            self.logo_img = PhotoImage(file="logo.png")
            logo_lbl = Label(header, image=self.logo_img, bg=BG)
            logo_lbl.image = self.logo_img
            logo_lbl.pack(side='left', padx=(0, 14))
        except TclError as e:
            self.logger.error("Error loading logo %s", e)

        title_block = Frame(header, bg=BG)
        title_block.pack(side='left', anchor='center')
        Label(title_block, text="Password Manager", bg=BG, fg=TEXT, font=FONT_TITLE).pack(anchor='w')
        Label(title_block, text="Store your credentials securely", bg=BG, fg=MUTED, font=FONT_SM).pack(anchor='w')

        # Form card
        card = Frame(self.window, bg=CARD)
        card.pack(fill='both', expand=True, padx=30, pady=(0, 30))

        form = Frame(card, bg=CARD)
        form.pack(padx=28, pady=28, fill='both', expand=True)

        self.website_entry = _field_row(form, "Website", "Search", self.search_password)
        self.email_entry = _field_row(form, "Email", "Show All", self.show_all_passwords)
        if self.default_email:
            self.email_entry.insert(0, self.default_email)
        self.password_entry = _field_row(form, "Password", "Generate", self.generate_password)

        # Action buttons
        actions = Frame(form, bg=CARD)
        actions.pack(fill='x', pady=(24, 0))
        _make_btn(actions, "Save", self.save, 'primary').pack(side='left', fill='x', expand=True, padx=(0, 8))
        _make_btn(actions, "Clear", self.clear_fields).pack(side='left', fill='x', expand=True)

    # ── Features ──────────────────────────────────────────────────────────────

    def show_all_passwords(self):
        code = simpledialog.askstring("Security", "Enter security code:", show='*')
        if code != SECRET_KEY:
            messagebox.showerror("Error", "Incorrect security code")
            return
        try:
            with open("passwords.json", "r", encoding="utf-8") as file:
                data = json.load(file)
            if not data:
                messagebox.showinfo("Info", "No passwords stored yet")
                return

            password_list = "\n\n".join(
                f"Website: {site}\nEmail: {details['email']}\nCreated: {details['created_at']}"
                for site, details in data.items()
            )

            top = Toplevel(self.window)
            top.title("Stored Passwords")
            top.config(bg=BG)
            top.geometry("460x360")

            Label(top, text="Stored Passwords", bg=BG, fg=TEXT,
                  font=FONT_TITLE).pack(padx=24, pady=(24, 12), anchor='w')

            container = Frame(top, bg=CARD)
            container.pack(fill='both', expand=True, padx=24, pady=(0, 24))

            text_widget = Text(container, wrap='word', bg=CARD, fg=TEXT, font=FONT,
                               bd=0, highlightthickness=0, padx=16, pady=16)
            text_widget.pack(side='left', fill='both', expand=True)
            text_widget.insert('1.0', password_list)
            text_widget.config(state='disabled')

            scrollbar = Scrollbar(container, command=text_widget.yview, bg=CARD, troughcolor=CARD)
            scrollbar.pack(side='right', fill='y')
            text_widget.config(yscrollcommand=scrollbar.set)

        except FileNotFoundError:
            messagebox.showinfo("Info", "No passwords stored yet")

    def generate_password(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for _ in range(20))
        self.password_entry.delete(0, 'end')
        self.password_entry.insert(0, password)
        pyperclip.copy(password)

    def generate_key(self, password):
        self.logger.info("Generating key in SHA256")
        return b64encode(hashlib.sha256(password.encode()).digest())

    def encrypt_password(self, password):
        self.logger.info("Encrypting password...")
        key = self.generate_key(SECRET_KEY)
        f = Fernet(key)
        encrypted_password = f.encrypt(password.encode())
        return {"encrypted": encrypted_password.decode()}

    def decrypt_password(self, stored_data):
        self.logger.info("Retrieving clear password")
        key = self.generate_key(SECRET_KEY)
        f = Fernet(key)
        decrypted_password = f.decrypt(stored_data["password"].encode())
        return decrypted_password.decode()

    def save(self):
        website = self.website_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        timestamp = datetime.now().isoformat()

        if not all([website, email, password]):
            messagebox.showwarning("Warning", "Please fill all fields")
            return

        psw_encrypted = self.encrypt_password(password)
        new_data = {
            website: {
                "email": email,
                "password": psw_encrypted["encrypted"],
                "created_at": timestamp
            }
        }

        try:
            with open("passwords.json", mode="r", encoding="utf-8") as file:
                existing_data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            existing_data = {}
            self.logger.info("No existing data found, creating new file")

        existing_data.update(new_data)
        with open("passwords.json", mode="w", encoding="utf-8") as file:
            json.dump(existing_data, file, indent=4)
            self.logger.info("Saved entry for %s", website)

        self.clear_fields()
        messagebox.showinfo("Success", "Password saved successfully!")

    def search_password(self):
        website = self.website_entry.get()
        if not website:
            messagebox.showinfo("Search", "Please enter a website to search")
            return

        try:
            with open("passwords.json", "r", encoding="utf-8") as file:
                data = json.load(file)

            if website not in data:
                messagebox.showinfo("Not Found", f"No details found for {website}")
                return

            code = simpledialog.askstring("Security", "Enter security code:", show='*')
            if code != SECRET_KEY:
                messagebox.showerror("Error", "Invalid security code")
                return

            entry = data[website]
            decrypted_password = self.decrypt_password(entry)

            dialog = Toplevel(self.window)
            dialog.title(f"Details for {website}")
            dialog.config(bg=BG)
            dialog.resizable(False, False)

            inner = Frame(dialog, bg=BG)
            inner.pack(padx=28, pady=28, fill='both')

            Label(inner, text=website, bg=BG, fg=TEXT, font=FONT_TITLE).pack(anchor='w')
            Label(inner, text=entry['email'], bg=BG, fg=MUTED, font=FONT).pack(anchor='w', pady=(4, 20))

            Label(inner, text="Password", bg=BG, fg=MUTED, font=FONT_SM, anchor='w').pack(fill='x', pady=(0, 4))
            border = Frame(inner, bg=BORDER)
            border.pack(fill='x', pady=(0, 20))
            password_var = StringVar(value=decrypted_password)
            Entry(border, textvariable=password_var, bg=ENTRY_BG, fg=TEXT,
                  font=FONT, bd=0, highlightthickness=0, relief='flat').pack(padx=1, pady=1, fill='x', ipady=8)

            _make_btn(inner, "Copy Password",
                      lambda: [pyperclip.copy(decrypted_password),
                               messagebox.showinfo("Copied", "Password copied to clipboard!")],
                      'primary').pack(fill='x')

        except FileNotFoundError:
            messagebox.showinfo("Error", "No password file found")

    def clear_fields(self):
        for entry in (self.website_entry, self.password_entry):
            entry.delete(0, 'end')
        self.logger.info("Cleaned entry")
