from base64 import b64encode
from tkinter import messagebox, simpledialog, Tk, Toplevel, Text, Scrollbar, Y, RIGHT, WORD, END, Button, Label, \
    StringVar, Entry, PhotoImage, Frame
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
WINDOW_BG = '#000000'
TEXT_COLOR = '#FFFFFF'
ENTRY_BG = '#1a1a1a'
ENTRY_FG = '#FFFFFF'


class PasswordManager:
    def __init__(self, default_email='albertobarrago@gmail.com'):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.default_email = default_email
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
            'bg': '#000000',
            'fg': '#333333',
            'font': ('Helvetica', 12),
        }

        self.window.configure(bg=self.style['bg'])
        self.setup_ui()

    def create_button(self, text, command, row, column):
        button = Button(
            self.window,
            text=text,
            command=command,
            activebackground="blue",
            activeforeground="white",
            anchor="center",
            bd=3,
            bg="lightgray",
            cursor="hand2",
            disabledforeground="gray",
            fg="black",
            font=("Arial", 12),
            height=2,
            highlightbackground="black",
            highlightcolor="green",
            highlightthickness=2,
            justify="center",
            overrelief="raised",
            padx=10,
            pady=5,
            width=15,
            wraplength=100
        )
        button.grid(row=row, column=column, padx=5, pady=5)

        return button

    def setup_ui(self):
        self.window.grid_columnconfigure(0, weight=1)
        self.window.grid_columnconfigure(1, weight=2)
        self.window.grid_columnconfigure(2, weight=1)
        self.window.grid_rowconfigure(0, weight=0)
        self.window.grid_rowconfigure(1, weight=1)

        try:
            logo_img = PhotoImage(file="logo.png")
            logo_label = Label(self.window, image=logo_img, bg=WINDOW_BG)
            logo_label.image = logo_img
            logo_label.grid(row=0, column=0, columnspan=3, pady=(20, 10))
        except FileNotFoundError as e:
            title_label = Label(self.window, text="Password Manager", font=("Helvetica", 20, "bold"),
                                bg=WINDOW_BG, fg=TEXT_COLOR)
            title_label.grid(row=0, column=0, columnspan=3, pady=(20, 10))
            self.logger.error("Error loading logo %s", e)

        content_frame = Frame(self.window, bg=WINDOW_BG)
        content_frame.grid(row=1, column=0, columnspan=3, sticky='nsew', padx=20, pady=20)
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=2)

        label_config = {'bg': WINDOW_BG, 'fg': TEXT_COLOR, 'anchor': 'e'}
        entry_config = {'width': 35, 'bg': ENTRY_BG, 'fg': ENTRY_FG, 'insertbackground': 'white'}
        tiny_config = {'width': 25, 'bg': ENTRY_BG, 'fg': ENTRY_FG, 'insertbackground': 'white'}

        Label(content_frame, text="Website:", **label_config).grid(row=0, column=0, pady=5, padx=10, sticky='e')
        self.website_entry = Entry(content_frame, **entry_config)
        self.website_entry.grid(row=0, column=1, sticky='ew', padx=5)

        Label(content_frame, text="Email:", **label_config).grid(row=1, column=0, pady=5, padx=10, sticky='e')
        self.email_entry = Entry(content_frame, **entry_config)
        self.email_entry.grid(row=1, column=1, sticky='ew', padx=5)
        self.email_entry.insert(0, self.default_email)

        Label(content_frame, text="Password:", **label_config).grid(row=2, column=0, pady=5, padx=10, sticky='e')
        password_frame = Frame(content_frame, bg=WINDOW_BG)
        password_frame.grid(row=2, column=1, sticky='ew')
        password_frame.grid_columnconfigure(0, weight=1)

        self.password_entry = Entry(password_frame, **tiny_config)
        self.password_entry.grid(row=0, column=0, sticky='ew')

        generate_button = Button(password_frame,
                                 text="Generate",
                                 command=self.generate_password,
                                 activebackground="blue",
                                 activeforeground="white",
                                 anchor="center",
                                 bd=0,
                                 bg="lightgray",
                                 cursor="hand2",
                                 fg="black",
                                 font=("Arial", 12),
                                 height=1,
                                 padx=10,
                                 pady=5,
                                 width=5)

        generate_button.grid(row=0, column=1, padx=(5, 0))

        buttons_frame_top = Frame(content_frame, bg=WINDOW_BG)
        buttons_frame_top.grid(row=3, column=0, columnspan=3, pady=(20, 10))
        self.create_button("Search", self.search_password, 0, 0).grid(in_=buttons_frame_top, row=0, column=0, padx=5)

        buttons_frame = Frame(content_frame, bg=WINDOW_BG)
        buttons_frame.grid(row=4, column=0, columnspan=3, pady=(10, 20))

        self.create_button("Save", self.save, 0, 1).grid(in_=buttons_frame, row=0, column=1, padx=5)
        self.create_button("Show All", self.show_all_passwords, 0, 2).grid(in_=buttons_frame, row=0, column=2, padx=5)
        self.create_button("Clean", self.clean_entry_field, 0, 3).grid(in_=buttons_frame, row=0, column=3, padx=5)

        self.window.grid_rowconfigure(1, weight=1)

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
            with open("passwords.json", mode="r", encoding="utf-8") as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}

        data.update(new_data)

        # Write the updated data back to the file
        with open("passwords.json", mode="w", encoding="utf-8") as file:
            json.load(file)

        self.clear_fields()
        messagebox.showinfo("Success", "Password saved successfully!")

    def clean_entry_field(self):
        self.email_entry.delete(0, END)
        self.password_entry.delete(0, END)
        self.website_entry.delete(0, END)
        self.logger.info("Cleaned entry")

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
