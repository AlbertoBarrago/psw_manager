from base64 import b64encode
from tkinter import messagebox, simpledialog, Tk, Toplevel, Text, Scrollbar, Y, RIGHT, WORD, END, Button, Label, \
    StringVar, Entry
from datetime import datetime
import os
import hashlib
import json
import secrets
import string
import logging
import pyperclip
from dotenv import load_dotenv

from fernet import Fernet

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")


class PasswordManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.email_entry = None
        self.password_entry = None
        self.website_entry = None
        self.window = Tk()
        self.window.title("Professional Password Manager")
        self.window.config(padx=50, pady=50)

        handler = logging.FileHandler('password_manager.log')
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)

        self.style = {
            'bg': '#f0f0f0',
            'fg': '#333333',
            'button_bg': '#4a90e2',
            'button_fg': 'white',
            'button_active_bg': '#357abd',
            'button_active_fg': 'white',
            'entry_bg': 'white'
        }

        self.window.configure(bg=self.style['bg'])
        self.setup_ui()

    def create_button(self, text, command, row, column):
        BUTTON_BG = '#007AFF'
        BUTTON_FG = '#FFFFFF'

        return Button(
            self.window,
            text=text,
            command=command,
            bg=BUTTON_FG,
            fg=BUTTON_BG,
            font=('Helvetica', 10, 'bold'),
            width=10,
            height=1,
        ).grid(row=row, column=column, pady=5, columnspan=1)

    def setup_ui(self):
        # High contrast colors that stay fixed
        WINDOW_BG = '#2B2B2B'
        TEXT_COLOR = '#FFFFFF'
        ENTRY_BG = '#3D3D3D'
        ENTRY_FG = '#FFFFFF'

        # Configure grid columns to expand properly
        self.window.grid_columnconfigure(1, weight=1)

        # Labels aligned right
        label_config = {
            'bg': WINDOW_BG,
            'fg': TEXT_COLOR,
            'font': ('Helvetica', 12, 'bold'),
            'anchor': 'e'  # Right align text
        }

        Label(self.window, text="Website:", **label_config).grid(row=0, column=0, pady=5, padx=10, sticky='e')
        Label(self.window, text="Email:", **label_config).grid(row=1, column=0, pady=5, padx=10, sticky='e')
        Label(self.window, text="Password:", **label_config).grid(row=2, column=0, pady=5, padx=10, sticky='e')

        # Entries with consistent width
        entry_config = {
            'width': 35,
            'bg': ENTRY_BG,
            'fg': ENTRY_FG,
            'insertbackground': TEXT_COLOR
        }

        self.website_entry = Entry(self.window, **entry_config)
        self.website_entry.grid(row=0, column=1, sticky='ew', padx=5)

        self.email_entry = Entry(self.window, **entry_config)
        self.email_entry.grid(row=1, column=1, sticky='ew', padx=5)

        self.password_entry = Entry(self.window, **entry_config)
        self.password_entry.grid(row=2, column=1, sticky='ew', padx=5)

        # Add search functionality
        self.create_button("Search", self.search_password, 0, 2)
        self.create_button("Generate", self.generate_password, 2, 2)
        self.create_button("Save", self.save, 3, 1)
        self.create_button("Show All", self.show_all_passwords, 3, 2)

    def show_all_passwords(self):
        try:
            with open("passwords.json", "r", encoding="utf-8") as file:
                data = json.load(file)

            if not data:
                messagebox.showinfo("Info", "No passwords stored yet")
                return

            # Create a formatted string of all entries
            password_list = "\n\n".join(
                f"Website: {site}\nEmail: {details['email']}\nCreated: {details['created_at']}"
                for site, details in data.items()
            )

            # Show in a scrolled text window
            top = Toplevel(self.window)
            top.title("Stored Passwords")
            top.geometry("400x300")

            text_widget = Text(top, wrap=WORD, bg='#2B2B2B', fg='#FFFFFF')
            text_widget.pack(expand=True, fill='both')
            text_widget.insert('1.0', password_list)
            text_widget.config(state='disabled')

            scrollbar = Scrollbar(top, command=text_widget.yview)
            scrollbar.pack(side=RIGHT, fill=Y)
            text_widget.config(yscrollcommand=scrollbar.set)

        except FileNotFoundError:
            messagebox.showinfo("Info", "No passwords stored yet")

    def generate_password(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for _ in range(20))
        self.password_entry.delete(0, END)
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
        return {
            "encrypted": encrypted_password.decode(),
        }

    def decrypt_password(self, stored_data):
        self.logger.info("Retrieving clear password")
        key = self.generate_key(SECRET_KEY)
        f = Fernet(key)
        decrypted_password = f.decrypt(stored_data["encrypted"].encode())
        return decrypted_password.decode()

    def save(self):
        website = self.website_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        timestamp = datetime.now().isoformat()

        if not all([website, email, password]):
            messagebox.showwarning("Warning", "Please fill all fields")
            return

        encrypted = self.encrypt_password(password)

        new_data = {
            website: {
                "email": email,
                "encrypted": encrypted["encrypted"],
                "created_at": timestamp
            }
        }

        try:
            with open("passwords.json", "r", encoding="utf-8") as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}

        data.update(new_data)

        with open("passwords.json", mode="w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

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
                if website in data:
                    code = simpledialog.askstring("Security", "Enter security code:", show='*')
                    if code == SECRET_KEY:
                        entry = data[website]

                        # Decrypt the stored password
                        decrypted_password = self.decrypt_password(entry)

                        dialog = Toplevel(self.window)
                        dialog.title(f"Details for {website}")
                        dialog.config(bg='#2B2B2B', padx=20, pady=20)

                        Label(dialog, text=f"Website: {website}", bg='#2B2B2B', fg='white').pack(anchor='w')
                        Label(dialog, text=f"Email: {entry['email']}", bg='#2B2B2B', fg='white').pack(anchor='w')

                        # Show decrypted password
                        password_var = StringVar(value=decrypted_password)
                        password_entry = Entry(dialog, textvariable=password_var, show='', bg='#3D3D3D', fg='white')
                        password_entry.pack(anchor='w', pady=5)

                        Button(dialog,
                               text="Copy Password",
                               command=lambda: [pyperclip.copy(decrypted_password),
                                                messagebox.showinfo("Success", "Password copied to clipboard!")]).pack(
                            pady=10)
                    else:
                        messagebox.showerror("Error", "Invalid security code")
                else:
                    messagebox.showinfo("Not Found", f"No details found for {website}")
        except FileNotFoundError:
            messagebox.showinfo("Error", "No password file found")

    def clear_fields(self):
        for entry in (self.website_entry, self.email_entry, self.password_entry):
            entry.delete(0, END)
