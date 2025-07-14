import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from PIL import Image, ImageTk
import sqlite3
import os
from cryptography.fernet import Fernet
import base64
import json
import hashlib
import pyperclip
import pyotp
import random
import string
from datetime import datetime, timedelta
import qrcode
import io
import csv
import requests
import markdown
from bs4 import BeautifulSoup
import time

class PlaceholderEntry(ttk.Entry):
    def __init__(self, master=None, placeholder="", *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.placeholder = placeholder
        self.insert("0", self.placeholder)
        self.bind("<FocusIn>", self.clear_placeholder)
        self.bind("<FocusOut>", self.set_placeholder)
    
    def clear_placeholder(self, event):
        if self.get() == self.placeholder:
            self.delete("0", "end")
    
    def set_placeholder(self, event):
        if not self.get():
            self.insert("0", self.placeholder)

# --- Constants ---
CONFIG_FILE = "config.json"
DB_FILE = "vault.db"
LOCKOUT_FILE = "lockout.json"
PASSWORD_EXPIRY_DAYS = 90
CLIPBOARD_CLEAR_TIME = 30  # seconds
SESSION_TIMEOUT = 300  # 5 minutes
MAX_PASSWORD_HISTORY = 5
HAVEIBEENPWNED_API = "https://api.pwnedpasswords.com/range/"

# --- Theme Colors ---
class Theme:
    def __init__(self):
        # Dark theme colors
        self.dark_bg = "#2d2d2d"
        self.dark_fg = "#e0e0e0"
        self.dark_entry_bg = "#444444"
        self.dark_accent = "#4e8cff"
        self.dark_card_bg = "#3a3a3a"
        
        # Light theme colors
        self.light_bg = "#f5f5f5"
        self.light_fg = "#333333"
        self.light_entry_bg = "#ffffff"
        self.light_accent = "#1a73e8"
        self.light_card_bg = "#ffffff"
        
        # Common colors
        self.success = "#4caf50"
        self.warning = "#ff9800"
        self.error = "#f44336"
        self.info = "#2196F3"
        self.favorite = "#FFD700"
        
        # Current theme
        self.current_bg = self.dark_bg
        self.current_fg = self.dark_fg
        self.current_entry_bg = self.dark_entry_bg
        self.current_accent = self.dark_accent
        self.current_card_bg = self.dark_card_bg
        self.is_dark = True

    def toggle(self):
        if self.is_dark:
            self.current_bg = self.light_bg
            self.current_fg = self.light_fg
            self.current_entry_bg = self.light_entry_bg
            self.current_accent = self.light_accent
            self.current_card_bg = self.light_card_bg
            self.is_dark = False
        else:
            self.current_bg = self.dark_bg
            self.current_fg = self.dark_fg
            self.current_entry_bg = self.dark_entry_bg
            self.current_accent = self.dark_accent
            self.current_card_bg = self.dark_card_bg
            self.is_dark = True

# Initialize theme
theme = Theme()

# --- Backend Functions ---
def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load config: {str(e)}")
        return None

def derive_key(password, salt):
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return base64.urlsafe_b64encode(key)

def init_db():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout = 3000")
            cursor = conn.cursor()
            
            # Main passwords table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site TEXT,
                    url TEXT,
                    email TEXT,
                    username TEXT,
                    password TEXT,
                    tags TEXT,
                    notes TEXT,
                    is_favorite BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Password history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_id INTEGER,
                    password TEXT,
                    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(password_id) REFERENCES passwords(id)
                )
            ''')
            
            conn.commit()
    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"Failed to initialize database: {str(e)}")

def execute_db_query(query, params=(), fetchone=False, commit=False):
    """Helper function to execute database queries safely"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("PRAGMA busy_timeout = 3000")  # Wait up to 3 seconds if locked
            cursor = conn.cursor()
            cursor.execute(query, params)
            if commit:
                conn.commit()
            if fetchone:
                return cursor.fetchone()
            return cursor.fetchall()
    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"Database error: {str(e)}")
        return None
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {str(e)}")
        return None

def encrypt(text, key):
    try:
        if not text:  # Handle empty strings
            return ""
        f = Fernet(key)
        encrypted = f.encrypt(text.encode()).decode()
        return encrypted
    except Exception as e:
        messagebox.showerror("Encryption Error", f"Failed to encrypt data: {str(e)}")
        return None

def decrypt(cipher_text, key):
    try:
        if not cipher_text:  # Handle empty strings
            return ""
        f = Fernet(key)
        decrypted = f.decrypt(cipher_text.encode()).decode()
        return decrypted
    except Exception as e:
        messagebox.showerror("Decryption Error", f"Failed to decrypt data: {str(e)}")
        return None

def check_password_strength(password):
    reasons = []
    strength = "Weak"
    if len(password) < 8:
        reasons.append("Password length < 8")
    has_digit = any(c.isdigit() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    has_alpha = any(c.isalpha() for c in password)

    if not has_digit:
        reasons.append("Missing digit")
    if not has_upper:
        reasons.append("Missing uppercase letter")
    if not has_symbol:
        reasons.append("Missing symbol")
    if not has_alpha:
        reasons.append("Missing alphabetic character")

    if len(password) >= 12:
        if has_digit and has_upper and has_symbol and has_alpha:
            strength = "Strong"
            reasons = []
        elif has_digit and has_alpha:
            strength = "Moderate"
    elif len(password) >= 8:
        if has_digit and has_upper and has_symbol and has_alpha:
            strength = "Moderate"
            reasons = ["Password length could be longer (12+ recommended)"]
        elif has_digit and has_alpha:
            strength = "Weak"
            reasons.append("Password length could be longer (12+ recommended)")

    return strength, reasons

def generate_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    characters = ''
    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        return None

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def is_locked_out():
    if not os.path.exists(LOCKOUT_FILE):
        return False
    try:
        with open(LOCKOUT_FILE, "r") as f:
            data = json.load(f)
        if data.get("locked_until"):
            unlock_time = datetime.fromisoformat(data["locked_until"])
            return datetime.now() < unlock_time
        return False
    except Exception:
        return False

def log_unauthorized_access():
    with open("access_log.txt", "a") as f:
        f.write(f"[{datetime.now()}] Unauthorized access attempt.\n")

def lock_out():
    lockout_time = datetime.now() + timedelta(minutes=1)
    with open(LOCKOUT_FILE, "w") as f:
        json.dump({"locked_until": lockout_time.isoformat()}, f)

def check_expired_passwords():
    """Check for passwords that have expired and return a list of expired entries"""
    expired_entries = []
    try:
        entries = execute_db_query('SELECT id, site, last_updated FROM passwords')
        if entries:
            for entry in entries:
                entry_id, site, updated_str = entry
                try:
                    # Handle different date formats
                    if isinstance(updated_str, str):
                        if ' ' in updated_str:  # Format: "YYYY-MM-DD HH:MM:SS"
                            updated_at = datetime.strptime(updated_str, "%Y-%m-%d %H:%M:%S")
                        else:  # Format: "YYYY-MM-DD"
                            updated_at = datetime.strptime(updated_str, "%Y-%m-%d")
                    elif isinstance(updated_str, datetime):
                        updated_at = updated_str
                    else:
                        continue
                    
                    age = (datetime.now() - updated_at).days
                    if age > PASSWORD_EXPIRY_DAYS:
                        expired_entries.append({
                            'id': entry_id,
                            'site': site,
                            'age': age,
                            'last_updated': updated_str
                        })
                except Exception as e:
                    continue
    except Exception as e:
        print(f"Error checking expired passwords: {str(e)}")
    
    return expired_entries

def check_pwned_password(password):
    """Check if password has been compromised using Have I Been Pwned API"""
    try:
        # Hash the password and send first 5 chars of hash to API
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        response = requests.get(f"{HAVEIBEENPWNED_API}{prefix}")
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.startswith(suffix):
                    count = int(line.split(':')[1])
                    return count
        return 0
    except Exception as e:
        print(f"Error checking pwned passwords: {str(e)}")
        return -1

def parse_tags(tag_string):
    """Parse comma-separated tags into a list"""
    if not tag_string:
        return []
    return [tag.strip() for tag in tag_string.split(',') if tag.strip()]

def format_tags(tag_list):
    """Format list of tags into comma-separated string"""
    return ', '.join(tag_list)

def render_markdown(markdown_text):
    """Convert markdown to HTML and then to plain text with formatting"""
    if not markdown_text:
        return ""
    html = markdown.markdown(markdown_text)
    soup = BeautifulSoup(html, 'html.parser')
    return soup.get_text()

def add_to_password_history(password_id, old_password, key):
    """Add old password to history table"""
    # Get current history count
    count = execute_db_query('SELECT COUNT(*) FROM password_history WHERE password_id = ?', 
                           (password_id,), fetchone=True)
    
    # If we're at max, delete the oldest entry
    if count and count[0] >= MAX_PASSWORD_HISTORY:
        oldest = execute_db_query('''
            SELECT id FROM password_history 
            WHERE password_id = ? 
            ORDER BY changed_at ASC 
            LIMIT 1
        ''', (password_id,), fetchone=True)
        if oldest:
            execute_db_query('DELETE FROM password_history WHERE id = ?', 
                           (oldest[0],), commit=True)
    
    # Add the new history entry
    encrypted_password = encrypt(old_password, key)
    execute_db_query('''
        INSERT INTO password_history (password_id, password)
        VALUES (?, ?)
    ''', (password_id, encrypted_password), commit=True)

def export_to_csv(filename, key, tag_filter=None, favorites_only=False):
    """Export passwords to CSV file"""
    try:
        query = 'SELECT site, url, email, username, password, tags, notes FROM passwords'
        params = []
        
        conditions = []
        if tag_filter:
            conditions.append("tags LIKE ?")
            params.append(f'%{tag_filter}%')
        if favorites_only:
            conditions.append("is_favorite = 1")
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        entries = execute_db_query(query, params)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Site', 'URL', 'Email', 'Username', 'Password', 'Tags', 'Notes'])
            
            for entry in entries:
                decrypted = [
                    entry[0],  # site
                    entry[1],  # url
                    decrypt(entry[2], key) if entry[2] else '',  # email
                    decrypt(entry[3], key) if entry[3] else '',  # username
                    decrypt(entry[4], key),  # password
                    entry[5],  # tags
                    decrypt(entry[6], key) if entry[6] else ''  # notes
                ]
                writer.writerow(decrypted)
        
        return True
    except Exception as e:
        messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
        return False

def import_from_csv(filename, key):
    """Import passwords from CSV file"""
    try:
        with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            imported = 0
            skipped = 0
            
            for row in reader:
                # Check if entry already exists
                existing = execute_db_query(
                    'SELECT id FROM passwords WHERE site = ? AND username = ?',
                    (row['Site'], row['Username']),
                    fetchone=True
                )
                
                if existing:
                    skipped += 1
                    continue
                
                # Encrypt sensitive data
                email_enc = encrypt(row['Email'], key) if row['Email'] else ''
                username_enc = encrypt(row['Username'], key) if row['Username'] else ''
                password_enc = encrypt(row['Password'], key)
                notes_enc = encrypt(row['Notes'], key) if row['Notes'] else ''
                
                if None in [email_enc, username_enc, password_enc, notes_enc]:
                    skipped += 1
                    continue
                
                # Insert new entry
                execute_db_query('''
                    INSERT INTO passwords (site, url, email, username, password, tags, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    row['Site'],
                    row['URL'],
                    email_enc,
                    username_enc,
                    password_enc,
                    row['Tags'],
                    notes_enc
                ), commit=True)
                imported += 1
            
            return imported, skipped
    except Exception as e:
        messagebox.showerror("Import Error", f"Failed to import: {str(e)}")
        return 0, 0

# --- GUI App Class ---
class SecurePassVaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecurePassVault")
        self.geometry("1000x700")
        self.resizable(True, True)
        self.config = load_config()
        self.master_password = None
        self.key = None
        self.attempts = 0
        self.password_visible = False
        self.expired_passwords = []
        self.last_activity = datetime.now()
        self.clipboard_clear_job = None
        
        # Configure styles
        self.style = ttk.Style()
        self.configure_styles()
        
        # Load icons
        self.load_icons()
        
        init_db()
        
        # Setup notification area
        self.notification_var = tk.StringVar()
        self.setup_notification_area()
        
        # Setup session timeout check
        self.session_timeout_check()
        
        # Show setup screen if no config exists
        if self.config is None:
            self.create_setup_screen()
        else:
            self.create_login_screen()

    def session_timeout_check(self):
        """Check for session timeout periodically"""
        if self.master_password and (datetime.now() - self.last_activity).seconds > SESSION_TIMEOUT:
            self.logout()
        else:
            self.after(10000, self.session_timeout_check)

    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now()

    def setup_notification_area(self):
        """Setup the persistent notification area"""
        self.notification_frame = ttk.Frame(self, padding=(10, 5))
        self.notification_btn = ttk.Button(
            self.notification_frame,
            textvariable=self.notification_var,
            command=self.show_expired_passwords_popup,
            style="Warning.TButton"
        )
        self.notification_btn.pack(side='right')
        self.notification_frame.pack_forget()  # Hide by default

    def load_icons(self):
        self.icons = {
            "login": "🔑",
            "add": "➕",
            "retrieve": "🔍",
            "update": "🔄",
            "generate": "⚙️",
            "logout": "🚪",
            "copy": "📋",
            "eye": "👁️",
            "eye_off": "👁️",
            "back": "⬅️",
            "lock": "🔒",
            "unlock": "🔓",
            "strength": "📊",
            "success": "✅",
            "error": "❌",
            "warning": "⚠️",
            "alert": "🚨",
            "star": "★",
            "unstar": "☆",
            "tag": "🏷️",
            "history": "🕒",
            "audit": "🔎",
            "export": "📤",
            "import": "📥",
            "theme": "🌓"
        }

    def configure_styles(self):
        self.style.theme_use("clam")
        self.update_theme()

    def update_theme(self):
        # Configure main styles
        self.style.configure(".", 
                           background=theme.current_bg, 
                           foreground=theme.current_fg, 
                           font=('Segoe UI', 10))
        
        self.style.configure("TFrame", background=theme.current_bg)
        self.style.configure("TLabel", background=theme.current_bg, foreground=theme.current_fg)
        self.style.configure("TButton", 
                           background=theme.current_accent, 
                           foreground=theme.current_fg, 
                           font=('Segoe UI', 10, 'bold'), 
                           padding=8,
                           borderwidth=1)
        
        self.style.map("TButton",
                      background=[('active', theme.current_accent), ('disabled', '#666666')],
                      foreground=[('disabled', '#999999')],
                      relief=[('pressed', 'sunken'), ('!pressed', 'raised')])
        
        # Entry styles
        self.style.configure("TEntry", 
                           fieldbackground=theme.current_entry_bg, 
                           foreground=theme.current_fg,
                           insertcolor=theme.current_fg,
                           bordercolor=theme.current_accent,
                           lightcolor=theme.current_accent,
                           darkcolor=theme.current_accent)
        
        # Card style
        self.style.configure("Card.TFrame",
                           background=theme.current_card_bg,
                           relief="groove",
                           borderwidth=2)
        
        # Special button styles
        self.style.configure("Accent.TButton", 
                           background=theme.current_accent,
                           foreground=theme.current_fg,
                           font=('Segoe UI', 10, 'bold'))
        
        self.style.configure("Success.TButton",
                           background=theme.success,
                           foreground=theme.current_fg)
        
        self.style.configure("Warning.TButton",
                           background=theme.warning,
                           foreground=theme.current_fg)
        
        self.style.configure("Error.TButton",
                           background=theme.error,
                           foreground=theme.current_fg)
        
        self.style.configure("Info.TButton",
                           background=theme.info,
                           foreground=theme.current_fg)
        
        self.style.configure("Favorite.TButton",
                           background=theme.favorite,
                           foreground="#000000")
        
        self.style.configure("Small.TButton",
                           padding=2,
                           font=('Segoe UI', 8))
        
        # Configure the main window background
        self.configure(background=theme.current_bg)

    def toggle_theme(self):
        theme.toggle()
        self.update_theme()
        self.update_widget_colors()

    def update_widget_colors(self):
        # Update all widgets to match current theme
        for widget in self.winfo_children():
            if isinstance(widget, ttk.Frame):
                if 'Card' in widget.winfo_class():
                    widget.configure(style="Card.TFrame")
                else:
                    widget.configure(style="TFrame")
            elif isinstance(widget, ttk.Label):
                widget.configure(style="TLabel")
            elif isinstance(widget, ttk.Entry):
                widget.configure(style="TEntry")
            elif isinstance(widget, ttk.Button):
                if 'Favorite' in widget.winfo_class():
                    widget.configure(style="Favorite.TButton")
                else:
                    widget.configure(style="TButton")

    def show_expired_password_notifications(self, show_popup=True):
        """Check and show expired password notifications"""
        self.expired_passwords = check_expired_passwords()
        
        if self.expired_passwords:
            # Update notification indicator
            self.notification_var.set(f" {self.icons['alert']} {len(self.expired_passwords)} expired passwords ")
            self.notification_frame.pack(fill='x', side='top', anchor='ne')
            
            if show_popup:
                self.show_expired_passwords_popup()
        else:
            self.notification_frame.pack_forget()

    def show_expired_passwords_popup(self):
        """Show detailed popup for expired passwords"""
        if not self.expired_passwords:
            return
            
        popup = tk.Toplevel(self)
        popup.title("Password Expiration Alert")
        popup.geometry("600x450")
        
        # Make sure popup appears on top
        popup.attributes('-topmost', True)
        popup.after(100, lambda: popup.attributes('-topmost', False))
        
        # Header
        header_frame = ttk.Frame(popup)
        header_frame.pack(fill='x', pady=10)
        
        ttk.Label(header_frame, 
                 text=f"{self.icons['alert']} Expired Passwords", 
                 font=("Segoe UI", 16, "bold")).pack()
        
        ttk.Label(header_frame, 
                 text=f"You have {len(self.expired_passwords)} password(s) older than {PASSWORD_EXPIRY_DAYS} days", 
                 font=("Segoe UI", 10)).pack(pady=5)
        
        # Scrollable content
        container = ttk.Frame(popup)
        container.pack(fill='both', expand=True, padx=10, pady=5)
        
        canvas = tk.Canvas(container)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Add expired entries
        for entry in self.expired_passwords:
            frame = ttk.Frame(scrollable_frame, relief="groove", borderwidth=1)
            frame.pack(fill='x', pady=5, padx=5, ipadx=5, ipady=5)
            
            ttk.Label(frame, 
                     text=f"🔒 {entry['site']}", 
                     font=("Segoe UI", 12, "bold")).pack(anchor='w')
            
            ttk.Label(frame, 
                     text=f"⏱️ Last updated: {entry['last_updated']} ({entry['age']} days ago)", 
                     font=("Segoe UI", 9)).pack(anchor='w')
            
            ttk.Button(frame,
                     text=f" {self.icons['update']} Update Password",
                     command=lambda e=entry: self.update_expired_password(e, popup),
                     style="Warning.TButton").pack(pady=5)
        
        # Close button
        ttk.Button(popup,
                 text=f" {self.icons['success']} Close",
                 command=popup.destroy,
                 style="Success.TButton").pack(pady=10)

    def update_expired_password(self, entry, popup=None):
        """Update an expired password"""
        site = entry['site']
        new_password = simpledialog.askstring(
            "Update Password", 
            f"Enter new password for {site}:", 
            show='*'
        )
        
        if new_password:
            strength, reasons = check_password_strength(new_password)
            if strength == "Weak":
                if not messagebox.askyesno("Weak Password", 
                                         f"Password is weak:\n" + "\n".join(reasons) + 
                                         "\n\nSave anyway?"):
                    return
            
            # Get old password for history
            old_password_row = execute_db_query(
                'SELECT password FROM passwords WHERE id = ?',
                (entry['id'],),
                fetchone=True
            )
            
            if old_password_row:
                old_password = decrypt(old_password_row[0], self.key)
                add_to_password_history(entry['id'], old_password, self.key)
            
            new_password_enc = encrypt(new_password, self.key)
            if new_password_enc is None:
                messagebox.showerror("Error", "Failed to encrypt new password")
                return
            
            execute_db_query(
                'UPDATE passwords SET password = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?', 
                (new_password_enc, entry['id']), 
                commit=True
            )
            
            pyperclip.copy(new_password)
            messagebox.showinfo("Success", f"Password for {site} updated and copied to clipboard.")
            
            # Clear clipboard after timeout
            self.schedule_clipboard_clear()
            
            # Refresh notifications
            if popup:
                popup.destroy()
            self.show_expired_password_notifications(show_popup=False)

    def schedule_clipboard_clear(self):
        """Schedule clipboard clearing after timeout"""
        if self.clipboard_clear_job:
            self.after_cancel(self.clipboard_clear_job)
        
        self.clipboard_clear_job = self.after(
            CLIPBOARD_CLEAR_TIME * 1000,
            lambda: pyperclip.copy("") or messagebox.showinfo(
                "Clipboard Cleared",
                "Password cleared from clipboard for security."
            )
        )

    def create_setup_screen(self):
        self.clear_screen()
        
        # Create main container with scrollbar
        container = ttk.Frame(self)
        container.pack(fill='both', expand=True)
        
        # Create canvas
        canvas = tk.Canvas(container)
        canvas.pack(side='left', fill='both', expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(container, orient='vertical', command=canvas.yview)
        scrollbar.pack(side='right', fill='y')
        
        # Configure canvas
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        
        # Create frame inside canvas
        content_frame = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=content_frame, anchor='nw')
        
        # Header
        header_frame = ttk.Frame(content_frame)
        header_frame.pack(fill='x', pady=(20, 10))
        
        ttk.Label(header_frame, 
                 text="🔒 SecurePassVault Setup", 
                 font=("Segoe UI", 20, "bold")).pack()
        ttk.Label(header_frame, 
                 text="Let's get your vault set up securely", 
                 font=("Segoe UI", 10)).pack(pady=5)

        # TOTP Setup Section
        ttk.Label(content_frame, 
                 text="Step 1: Set up Two-Factor Authentication", 
                 font=("Segoe UI", 12, "bold")).pack(anchor='w', pady=10)
        
        # Generate secrets
        self.setup_totp_secret = pyotp.random_base32()
        self.setup_device_secret = base64.b64encode(os.urandom(32)).decode()
        
        # Create TOTP URI for QR code
        totp_uri = pyotp.totp.TOTP(self.setup_totp_secret).provisioning_uri(
            name="SecurePassVault",
            issuer_name="SecurePassVault"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=6, border=4)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to Tkinter image
        bio = io.BytesIO()
        img.save(bio, format="PNG")
        qr_image = Image.open(bio)
        qr_photo = ImageTk.PhotoImage(qr_image)
        
        # Display QR code
        qr_frame = ttk.Frame(content_frame)
        qr_frame.pack(pady=10)
        qr_label = ttk.Label(qr_frame, image=qr_photo)
        qr_label.image = qr_photo  # Keep reference
        qr_label.pack()
        
        # Manual entry option
        ttk.Label(content_frame, 
                 text="Or enter this code manually:", 
                 font=("Segoe UI", 9)).pack(pady=5)
        
        secret_frame = ttk.Frame(content_frame)
        secret_frame.pack()
        
        ttk.Label(secret_frame, 
                 text=self.setup_totp_secret, 
                 font=("Courier", 12, "bold")).pack(side='left')
        
        ttk.Button(secret_frame, 
                 text="Copy", 
                 command=lambda: pyperclip.copy(self.setup_totp_secret),
                 style="Small.TButton").pack(side='left', padx=5)
        
        # TOTP Verification
        ttk.Label(content_frame, 
                 text="Step 2: Verify TOTP Setup", 
                 font=("Segoe UI", 12, "bold")).pack(anchor='w', pady=(20,5))
        
        ttk.Label(content_frame, 
                 text="Enter a code from your authenticator app:", 
                 font=("Segoe UI", 9)).pack(anchor='w')
        
        self.setup_test_code = ttk.Entry(content_frame, font=('Segoe UI', 11))
        self.setup_test_code.pack(fill='x', pady=5)
        
        # Master Password Setup
        ttk.Label(content_frame, 
                 text="Step 3: Set Master Password", 
                 font=("Segoe UI", 12, "bold")).pack(anchor='w', pady=(20,5))
        
        ttk.Label(content_frame, text="Master Password:").pack(anchor='w', pady=5)
        self.setup_master_pw = ttk.Entry(content_frame, show="*", font=('Segoe UI', 11))
        self.setup_master_pw.pack(fill='x', pady=5)
        
        ttk.Label(content_frame, text="Confirm Master Password:").pack(anchor='w', pady=5)
        self.setup_confirm_pw = ttk.Entry(content_frame, show="*", font=('Segoe UI', 11))
        self.setup_confirm_pw.pack(fill='x', pady=5)
        
        # Password strength indicator
        self.setup_strength_label = ttk.Label(content_frame, text="Strength: -", font=("Segoe UI", 9))
        self.setup_strength_label.pack(anchor='w', pady=5)
        
        # Bind password strength check
        self.setup_master_pw.bind("<KeyRelease>", self.check_setup_password_strength)
        
        # Complete setup button
        btn_frame = ttk.Frame(content_frame)
        btn_frame.pack(fill='x', pady=20)
        
        ttk.Button(btn_frame, 
                 text="Complete Setup", 
                 command=self.complete_setup,
                 style="Accent.TButton").pack(ipadx=20, ipady=5)
        
        # Update scroll region
        content_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

    def check_setup_password_strength(self, event):
        password = self.setup_master_pw.get()
        if password:
            strength, reasons = check_password_strength(password)
            color = theme.success if strength == "Strong" else theme.warning if strength == "Moderate" else theme.error
            self.setup_strength_label.config(
                text=f"Strength: {strength}",
                foreground=color
            )
        else:
            self.setup_strength_label.config(text="Strength: -")

    def complete_setup(self):
        # Verify TOTP code
        totp = pyotp.TOTP(self.setup_totp_secret)
        test_code = self.setup_test_code.get().strip()
        
        if not totp.verify(test_code, valid_window=1):
            messagebox.showerror("Error", "Invalid TOTP test code. Please try again.")
            return
        
        # Verify passwords match
        pw1 = self.setup_master_pw.get()
        pw2 = self.setup_confirm_pw.get()
        
        if not pw1 or pw1 != pw2:
            messagebox.showerror("Error", "Passwords don't match or are empty")
            return
        
        # Check password strength
        strength, reasons = check_password_strength(pw1)
        if strength == "Weak":
            if not messagebox.askyesno("Weak Password", 
                                     "Password is weak:\n" + "\n".join(reasons) + 
                                     "\n\nContinue anyway?"):
                return
        
        # Create config
        config = {
            "device_secret": self.setup_device_secret,
            "totp_secret": self.setup_totp_secret,
            "master_hash": base64.b64encode(
                hashlib.pbkdf2_hmac('sha256', pw1.encode(), 
                                   self.setup_device_secret.encode(), 100000)
            ).decode()
        }
        
        # Save config
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f)
            
            messagebox.showinfo("Success", "Setup completed successfully!")
            self.config = config
            self.create_login_screen()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {str(e)}")

    def create_login_screen(self):
        self.clear_screen()
        if is_locked_out():
            messagebox.showerror("Locked Out", "Too many failed attempts. Try again later.")
            self.destroy()
            return

        # Main container
        container = ttk.Frame(self)
        container.pack(expand=True, fill='both', padx=50, pady=50)

        # Header
        header_frame = ttk.Frame(container)
        header_frame.pack(pady=(0, 20))
        
        ttk.Label(header_frame, 
                 text=f"{self.icons['lock']} SecurePassVault", 
                 font=("Segoe UI", 24, "bold")).pack()
        ttk.Label(header_frame, 
                 text="Your secure password manager", 
                 font=("Segoe UI", 10)).pack(pady=5)

        # Login form
        form_frame = ttk.Frame(container)
        form_frame.pack(fill='x', pady=20)

        ttk.Label(form_frame, text="Master Password:").grid(row=0, column=0, sticky='w', pady=5)
        self.master_entry = ttk.Entry(form_frame, show="*", font=('Segoe UI', 11))
        self.master_entry.grid(row=0, column=1, pady=5, padx=10, sticky='ew')

        ttk.Label(form_frame, text="6-digit TOTP Code:").grid(row=1, column=0, sticky='w', pady=5)
        self.totp_entry = ttk.Entry(form_frame, font=('Segoe UI', 11))
        self.totp_entry.grid(row=1, column=1, pady=5, padx=10, sticky='ew')

        # Login button
        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill='x', pady=20)
        
        login_btn = ttk.Button(btn_frame, 
                             text=f" {self.icons['login']}  Login", 
                             command=self.handle_login,
                             style="Accent.TButton")
        login_btn.pack(pady=10, ipadx=20)

        # Theme toggle
        ttk.Button(btn_frame, 
                  text=f"{self.icons['theme']} Toggle Theme", 
                  command=self.toggle_theme).pack(pady=5)

        # Footer
        ttk.Label(container, 
                 text=f"🔒 SecurePassVault v2.0", 
                 font=("Segoe UI", 8)).pack(side='bottom', pady=10)

        # Focus on first entry
        self.master_entry.focus()

    def handle_login(self):
        self.update_activity()
        
        if is_locked_out():
            messagebox.showerror("Locked Out", "Too many failed attempts. Try again later.")
            self.destroy()
            return

        master_input = self.master_entry.get().strip()
        totp_input = self.totp_entry.get().strip()

        derived_hash = base64.b64encode(
            hashlib.pbkdf2_hmac('sha256', master_input.encode(), self.config['device_secret'].encode(), 100000)
        ).decode()

        if derived_hash == self.config['master_hash']:
            totp = pyotp.TOTP(self.config['totp_secret'])
            if totp.verify(totp_input):
                self.master_password = master_input
                self.key = derive_key(master_input, self.config['device_secret'])
                self.create_main_menu()
                # Show notifications after main menu is created
                self.after(100, lambda: self.show_expired_password_notifications(show_popup=True))
            else:
                self.attempts += 1
                log_unauthorized_access()
                messagebox.showerror("Error", f"{self.icons['error']} Invalid TOTP code.")
                if self.attempts >= 3:
                    lock_out()
                    messagebox.showerror("Locked Out", "Too many failed attempts. Locked out for 1 minute.")
                    self.destroy()
        else:
            self.attempts += 1
            log_unauthorized_access()
            messagebox.showerror("Error", f"{self.icons['error']} Incorrect master password.")
            if self.attempts >= 3:
                lock_out()
                messagebox.showerror("Locked Out", "Too many failed attempts. Locked out for 1 minute.")
                self.destroy()

    def create_main_menu(self):
        self.clear_screen()
        self.update_activity()
        
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill='x', pady=(20, 10))
        
        ttk.Label(header_frame, 
                 text=f"{self.icons['unlock']} SecurePassVault", 
                 font=("Segoe UI", 20, "bold")).pack()
        ttk.Label(header_frame, 
                 text="Manage your passwords securely", 
                 font=("Segoe UI", 10)).pack(pady=5)

        # Buttons container
        btn_container = ttk.Frame(self)
        btn_container.pack(expand=True, padx=100, pady=20)

        # Menu buttons
        menu_buttons = [
            ("Add New Entry", "add", self.add_entry_screen),
            ("Retrieve Entries", "retrieve", self.retrieve_entry_screen),
            ("Update Password", "update", self.update_password_screen),
            ("Password Generator", "generate", self.password_generator_screen),
            ("Password Audit", "audit", self.password_audit_screen),
            ("Import/Export", "export", self.import_export_screen),
            ("Logout", "logout", self.logout)
        ]

        for text, icon, command in menu_buttons:
            btn = ttk.Button(btn_container, 
                           text=f" {self.icons[icon]}  {text}", 
                           command=command,
                           style="Accent.TButton")
            btn.pack(fill='x', pady=8, ipady=8)

        # Footer
        ttk.Label(self, 
                 text=f"🔒 Database: {DB_FILE} | {datetime.now().strftime('%Y-%m-%d %H:%M')}", 
                 font=("Segoe UI", 8)).pack(side='bottom', pady=10)

    def add_entry_screen(self):
        self.clear_screen()
        self.update_activity()
        
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill='x', pady=(10, 20))
        
        ttk.Button(header_frame, 
                  text=f" {self.icons['back']} Back", 
                  command=self.create_main_menu).pack(side='left', padx=5)
        
        ttk.Label(header_frame, 
                 text=f"{self.icons['add']} Add New Entry", 
                 font=("Segoe UI", 16, "bold")).pack()

        # Main form
        form_frame = ttk.Frame(self)
        form_frame.pack(expand=True, padx=50, pady=10)

        # FIXED: Removed "Tags" from fields since we'll handle it separately
        fields = ["Site Name", "Site URL", "Email", "Username"]
        self.entry_vars = {}
        
        for i, field in enumerate(fields):
            ttk.Label(form_frame, text=field + ":").grid(row=i, column=0, sticky='w', pady=8)
            var = tk.StringVar()
            entry = ttk.Entry(form_frame, textvariable=var, width=40, font=('Segoe UI', 10))
            entry.grid(row=i, column=1, pady=8, padx=10, sticky='ew')
            self.entry_vars[field] = var

        # Tags section (row 4)
        ttk.Label(form_frame, text="Tags:").grid(row=4, column=0, sticky='w', pady=8)
        self.tags_entry = PlaceholderEntry(form_frame, 
                          placeholder="work, social, ...",
                          width=40, 
                          font=('Segoe UI', 10))
        self.tags_entry.grid(row=4, column=1, pady=8, padx=10, sticky='ew')
        
        # Password section (row 5)
        ttk.Label(form_frame, text="Password:").grid(row=5, column=0, sticky='w', pady=8)
        
        password_frame = ttk.Frame(form_frame)
        password_frame.grid(row=5, column=1, sticky='ew', pady=8)
        
        self.password_entry = ttk.Entry(password_frame, show="*", width=30, font=('Segoe UI', 10))
        self.password_entry.pack(side='left', fill='x', expand=True)
        
        # Password visibility toggle
        self.eye_btn = ttk.Button(password_frame, 
                                 text=self.icons['eye'], 
                                 command=self.toggle_password_visibility, 
                                 style='Small.TButton')
        self.eye_btn.pack(side='left', padx=5)

        # Password generation options (row 6)
        self.use_generated_password = tk.BooleanVar(value=False)
        gen_frame = ttk.Frame(form_frame)
        gen_frame.grid(row=6, column=1, sticky='w', pady=5)
        
        ttk.Checkbutton(gen_frame, 
                      text="Generate secure password", 
                      variable=self.use_generated_password,
                      command=self.toggle_password_input).pack(side='left')

        # Generation options (hidden initially)
        self.gen_options_frame = ttk.Frame(form_frame)
        
        # Length
        ttk.Label(self.gen_options_frame, text="Length:").grid(row=0, column=0, sticky='w', padx=5)
        self.gen_length_var = tk.IntVar(value=12)
        ttk.Spinbox(self.gen_options_frame, 
                   from_=8, to=64, 
                   width=5, 
                   textvariable=self.gen_length_var).grid(row=0, column=1, sticky='w')
        
        # Character types
        self.gen_upper_var = tk.BooleanVar(value=True)
        self.gen_lower_var = tk.BooleanVar(value=True)
        self.gen_digits_var = tk.BooleanVar(value=True)
        self.gen_symbols_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(self.gen_options_frame, 
                      text="Uppercase", 
                      variable=self.gen_upper_var).grid(row=1, column=0, sticky='w', padx=5)
        ttk.Checkbutton(self.gen_options_frame, 
                      text="Lowercase", 
                      variable=self.gen_lower_var).grid(row=1, column=1, sticky='w', padx=5)
        ttk.Checkbutton(self.gen_options_frame, 
                      text="Digits", 
                      variable=self.gen_digits_var).grid(row=2, column=0, sticky='w', padx=5)
        ttk.Checkbutton(self.gen_options_frame, 
                      text="Symbols", 
                      variable=self.gen_symbols_var).grid(row=2, column=1, sticky='w', padx=5)

        # Generate button
        ttk.Button(self.gen_options_frame,
                 text=f" {self.icons['generate']} Generate",
                 command=self.generate_password_for_entry,
                 style='Small.TButton').grid(row=3, column=0, columnspan=2, pady=5)

        # Notes section (row 7)
        ttk.Label(form_frame, text="Notes:").grid(row=7, column=0, sticky='nw', pady=8)
        self.notes_text = tk.Text(form_frame, height=5, width=40, font=('Segoe UI', 10))
        self.notes_text.grid(row=7, column=1, pady=8, padx=10, sticky='ew')

        # Favorite checkbox (row 8)
        self.is_favorite_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(form_frame,
                      text="Mark as favorite",
                      variable=self.is_favorite_var).grid(row=8, column=1, sticky='w', pady=5)

        # Submit button
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill='x', pady=20)
        
        ttk.Button(btn_frame, 
                 text=f" {self.icons['success']} Save Entry", 
                 command=self.save_entry,
                 style="Success.TButton").pack(side='left', padx=10)
        
        ttk.Button(btn_frame, 
                 text=f" {self.icons['back']} Cancel", 
                 command=self.create_main_menu).pack(side='right', padx=10)

    def toggle_password_visibility(self):
        self.password_visible = not self.password_visible
        if self.password_visible:
            self.password_entry['show'] = ''
            self.eye_btn.config(text=self.icons['eye_off'])
        else:
            self.password_entry['show'] = '*'
            self.eye_btn.config(text=self.icons['eye'])

    def toggle_password_input(self):
        if self.use_generated_password.get():
            self.password_entry.config(state='disabled')
            self.gen_options_frame.grid(row=6, column=1, sticky='w', pady=10)
        else:
            self.password_entry.config(state='normal')
            self.gen_options_frame.grid_forget()

    def generate_password_for_entry(self):
        length = self.gen_length_var.get()
        pw = generate_password(
            length,
            self.gen_upper_var.get(),
            self.gen_lower_var.get(),
            self.gen_digits_var.get(),
            self.gen_symbols_var.get()
        )
        
        if pw:
            self.password_entry.config(state='normal')
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, pw)
            messagebox.showinfo("Success", f"{self.icons['success']} Password generated and copied to clipboard.")
            pyperclip.copy(pw)
            self.schedule_clipboard_clear()
        else:
            messagebox.showerror("Error", f"{self.icons['error']} Failed to generate password. Please check options.")

    def save_entry(self):
        try:
            site = self.entry_vars["Site Name"].get().strip()
            url = self.entry_vars["Site URL"].get().strip()
            email = self.entry_vars["Email"].get().strip()
            username = self.entry_vars["Username"].get().strip()
            # FIXED: Get tags from the dedicated tags entry
            tags = self.tags_entry.get().strip()
            password = self.password_entry.get()
            notes = self.notes_text.get("1.0", tk.END).strip()
            is_favorite = self.is_favorite_var.get()

            if not (site and password):
                messagebox.showerror("Error", f"{self.icons['error']} Site Name and Password are required.")
                return

            strength, reasons = check_password_strength(password)
            if strength == "Weak":
                if not messagebox.askyesno("Weak Password", 
                                         f"{self.icons['warning']} Password is weak:\n" + "\n".join(reasons) + 
                                         "\n\nDo you still want to save it?"):
                    return

            # Check if password is compromised
            pwned_count = check_pwned_password(password)
            if pwned_count > 0:
                if not messagebox.askyesno("Compromised Password", 
                                         f"This password appears in {pwned_count} data breaches!\n"
                                         "It's highly recommended to choose a different password.\n"
                                         "Save anyway?"):
                    return

            # Encrypt and save
            email_enc = encrypt(email, self.key) if email else ''
            username_enc = encrypt(username, self.key) if username else ''
            password_enc = encrypt(password, self.key)
            notes_enc = encrypt(notes, self.key) if notes else ''

            if None in [email_enc, username_enc, password_enc, notes_enc]:
                messagebox.showerror("Error", "Failed to encrypt data")
                return

            # Use our new helper function
            success = execute_db_query('''
                INSERT INTO passwords (site, url, email, username, password, tags, notes, is_favorite)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (site, url, email_enc, username_enc, password_enc, tags, notes_enc, is_favorite), commit=True)
            
            if success is not None:
                messagebox.showinfo("Success", f"{self.icons['success']} Entry saved successfully.")
                self.create_main_menu()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save entry: {str(e)}")

    def retrieve_entry_screen(self):
        self.clear_screen()
        self.update_activity()
        
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill='x', pady=(10, 20))
        
        ttk.Button(header_frame, 
                  text=f" {self.icons['back']} Back", 
                  command=self.create_main_menu).pack(side='left', padx=5)
        
        ttk.Label(header_frame, 
                 text=f"{self.icons['retrieve']} Retrieve Entries", 
                 font=("Segoe UI", 16, "bold")).pack()

        # Search form
        form_frame = ttk.Frame(self)
        form_frame.pack(fill='x', padx=50, pady=10)

        # Search options frame
        options_frame = ttk.Frame(form_frame)
        options_frame.pack(fill='x', pady=10)
        
        # Site name search
        ttk.Label(options_frame, text="Site Name:").pack(side='left', padx=5)
        self.retrieve_site_var = tk.StringVar()
        ttk.Entry(options_frame, 
                textvariable=self.retrieve_site_var, 
                width=20,
                font=('Segoe UI', 10)).pack(side='left', padx=5)
        
        # Tag filter
        ttk.Label(options_frame, text="Tag:").pack(side='left', padx=5)
        self.retrieve_tag_var = tk.StringVar()
        ttk.Entry(options_frame, 
                textvariable=self.retrieve_tag_var, 
                width=15,
                font=('Segoe UI', 10)).pack(side='left', padx=5)
        
        # Favorites filter
        self.retrieve_favorites_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame,
                      text="Favorites only",
                      variable=self.retrieve_favorites_var).pack(side='left', padx=10)
        
        # Search button
        ttk.Button(options_frame,
                 text=f" {self.icons['retrieve']} Search",
                 command=self.retrieve_entries,
                 style="Accent.TButton").pack(side='right', padx=5)

        # Results frame (will be populated when searching)
        self.results_frame = ttk.Frame(self)
        self.results_frame.pack(fill='both', expand=True, padx=20, pady=10)

    def retrieve_entries(self):
        try:
            site = self.retrieve_site_var.get().strip()
            tag = self.retrieve_tag_var.get().strip()
            favorites_only = self.retrieve_favorites_var.get()

            # Clear previous results
            for widget in self.results_frame.winfo_children():
                widget.destroy()

            # Build query based on filters
            query = 'SELECT * FROM passwords'
            conditions = []
            params = []
            
            if site:
                conditions.append("site LIKE ?")
                params.append(f'%{site}%')
            if tag:
                conditions.append("tags LIKE ?")
                params.append(f'%{tag}%')
            if favorites_only:
                conditions.append("is_favorite = 1")
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY site ASC"
            
            # Get all matching entries
            rows = execute_db_query(query, params)
            
            if not rows:
                messagebox.showinfo("No Results", "No entries found matching your criteria.")
                return

            # Create a scrollable canvas for multiple results
            canvas = tk.Canvas(self.results_frame)
            scrollbar = ttk.Scrollbar(self.results_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
            
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            # Display each entry
            for row in rows:
                try:
                    created_at_str = row[9]
                    created_at = datetime.strptime(created_at_str, "%Y-%m-%d %H:%M:%S")
                    age = (datetime.now() - created_at).days
                except Exception:
                    age = 0

                password_to_show = None
                notes_text = decrypt(row[7], self.key) if row[7] else ''
                notes_rendered = render_markdown(notes_text)

                # Create entry card
                result_card = ttk.Frame(scrollable_frame, style="Card.TFrame")
                result_card.pack(fill='x', pady=10, ipadx=10, ipady=10)
                
                # Header with favorite star
                header_frame = ttk.Frame(result_card)
                header_frame.pack(fill='x', pady=(0, 5))
                
                # Favorite star button
                star_btn = ttk.Button(header_frame,
                                    text=self.icons['star'] if row[8] else self.icons['unstar'],
                                    command=lambda r=row: self.toggle_favorite(r),
                                    style="Favorite.TButton" if row[8] else "TButton")
                star_btn.pack(side='left', padx=5)
                
                # Site info
                ttk.Label(header_frame, 
                         text=f"🔒 {row[1]}", 
                         font=("Segoe UI", 14, "bold")).pack(side='left', padx=5)
                
                # URL
                if row[2]:
                    url_frame = ttk.Frame(result_card)
                    url_frame.pack(fill='x', pady=2)
                    ttk.Label(url_frame, 
                             text="🌐", 
                             font=("Segoe UI", 10)).pack(side='left')
                    ttk.Label(url_frame, 
                             text=row[2], 
                             font=("Segoe UI", 10)).pack(side='left', padx=5)
                
                # Email
                email = decrypt(row[3], self.key) if row[3] else ''
                if email:
                    email_frame = ttk.Frame(result_card)
                    email_frame.pack(fill='x', pady=2)
                    ttk.Label(email_frame, 
                             text="✉️", 
                             font=("Segoe UI", 10)).pack(side='left')
                    ttk.Label(email_frame, 
                             text=email, 
                             font=("Segoe UI", 10)).pack(side='left', padx=5)
                    ttk.Button(email_frame,
                             text=self.icons['copy'],
                             command=lambda e=email: self.copy_to_clipboard(e),
                             style="Small.TButton").pack(side='right')
                
                # Username
                username = decrypt(row[4], self.key) if row[4] else ''
                if username:
                    user_frame = ttk.Frame(result_card)
                    user_frame.pack(fill='x', pady=2)
                    ttk.Label(user_frame, 
                             text="👤", 
                             font=("Segoe UI", 10)).pack(side='left')
                    ttk.Label(user_frame, 
                             text=username, 
                             font=("Segoe UI", 10)).pack(side='left', padx=5)
                    ttk.Button(user_frame,
                             text=self.icons['copy'],
                             command=lambda u=username: self.copy_to_clipboard(u),
                             style="Small.TButton").pack(side='right')
                
                # Tags
                if row[6]:
                    tags_frame = ttk.Frame(result_card)
                    tags_frame.pack(fill='x', pady=5)
                    ttk.Label(tags_frame, 
                             text=f"{self.icons['tag']} Tags:", 
                             font=("Segoe UI", 9)).pack(side='left')
                    for tag in parse_tags(row[6]):
                        ttk.Label(tags_frame, 
                                 text=tag, 
                                 font=("Segoe UI", 9),
                                 background="#555555" if theme.is_dark else "#eeeeee",
                                 relief="groove",
                                 padding=2).pack(side='left', padx=2)
                
                # Password (hidden by default)
                pass_frame = ttk.Frame(result_card)
                pass_frame.pack(fill='x', pady=10)
                
                ttk.Label(pass_frame, 
                         text="🔑 Password:", 
                         font=("Segoe UI", 10)).pack(side='left')
                
                pass_var = tk.StringVar(value="••••••••")
                pass_entry = ttk.Entry(pass_frame, 
                                     textvariable=pass_var, 
                                     show="*", 
                                     font=("Segoe UI", 10),
                                     state='readonly',
                                     width=20)
                pass_entry.pack(side='left', padx=5)
                
                # Copy button
                ttk.Button(pass_frame, 
                         text=f" {self.icons['copy']} Copy", 
                         command=lambda pw=decrypt(row[5], self.key): (self.copy_to_clipboard(pw), self.schedule_clipboard_clear()),
                         style="Small.TButton").pack(side='left', padx=5)
                
                # Show button
                ttk.Button(pass_frame, 
                         text=f" {self.icons['eye']} Show", 
                         command=lambda v=pass_var, p=decrypt(row[5], self.key): self.toggle_result_password(v, p),
                         style="Small.TButton").pack(side='left', padx=5)

                # Notes (collapsible)
                if notes_text:
                    notes_frame = ttk.Frame(result_card)
                    notes_frame.pack(fill='x', pady=5)
                    
                    notes_btn = ttk.Button(notes_frame,
                                         text="📝 Notes (click to view)",
                                         command=lambda n=notes_rendered: self.show_notes_popup(n),
                                         style="Small.TButton")
                    notes_btn.pack(anchor='w')

                # Last updated and actions
                footer_frame = ttk.Frame(result_card)
                footer_frame.pack(fill='x', pady=(5, 0))
                
                ttk.Label(footer_frame, 
                         text=f"⏱️ {created_at_str} ({age} days)", 
                         font=("Segoe UI", 8)).pack(side='left')
                
                # Action buttons
                action_frame = ttk.Frame(footer_frame)
                action_frame.pack(side='right')
                
                # History button
                ttk.Button(action_frame,
                         text=f" {self.icons['history']} History",
                         command=lambda id=row[0]: self.show_password_history(id),
                         style="Small.TButton").pack(side='left', padx=2)
                
                # Edit button
                ttk.Button(action_frame,
                         text=f" {self.icons['update']} Edit",
                         command=lambda r=row: self.edit_entry(r),
                         style="Small.TButton").pack(side='left', padx=2)
                
                # Delete button
                ttk.Button(action_frame,
                         text=f" {self.icons['error']} Delete",
                         command=lambda id=row[0]: self.delete_entry(id),
                         style="Error.TButton").pack(side='left', padx=2)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while retrieving entries: {str(e)}")

    def toggle_favorite(self, row):
        """Toggle favorite status for an entry"""
        new_status = not row[8]
        execute_db_query('UPDATE passwords SET is_favorite = ? WHERE id = ?',
                       (new_status, row[0]), commit=True)
        self.retrieve_entries()  # Refresh the view

    def show_notes_popup(self, notes_text):
        """Show notes in a popup window"""
        popup = tk.Toplevel(self)
        popup.title("Entry Notes")
        popup.geometry("500x400")
        
        text_frame = ttk.Frame(popup)
        text_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        text_widget = tk.Text(text_frame, wrap='word', font=('Segoe UI', 10))
        scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side='right', fill='y')
        text_widget.pack(side='left', fill='both', expand=True)
        
        text_widget.insert('1.0', notes_text)
        text_widget.config(state='disabled')

    def show_password_history(self, password_id):
        """Show password history for an entry"""
        history = execute_db_query('''
            SELECT password, changed_at 
            FROM password_history 
            WHERE password_id = ?
            ORDER BY changed_at DESC
        ''', (password_id,))
        
        if not history:
            messagebox.showinfo("History", "No previous passwords found for this entry.")
            return
        
        popup = tk.Toplevel(self)
        popup.title("Password History")
        popup.geometry("400x300")
        
        # Header
        ttk.Label(popup, 
                 text=f"{self.icons['history']} Password History", 
                 font=("Segoe UI", 12, "bold")).pack(pady=10)
        
        # Create scrollable area
        container = ttk.Frame(popup)
        container.pack(fill='both', expand=True, padx=10, pady=5)
        
        canvas = tk.Canvas(container)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Add history entries
        for idx, (password_enc, changed_at) in enumerate(history):
            frame = ttk.Frame(scrollable_frame, style="Card.TFrame")
            frame.pack(fill='x', pady=5, padx=5, ipadx=5, ipady=5)
            
            ttk.Label(frame, 
                     text=f"Version {idx + 1} - {changed_at}", 
                     font=("Segoe UI", 9, "bold")).pack(anchor='w')
            
            pass_var = tk.StringVar(value="••••••••")
            pass_entry = ttk.Entry(frame, 
                                 textvariable=pass_var, 
                                 show="*", 
                                 font=("Segoe UI", 10),
                                 state='readonly',
                                 width=20)
            pass_entry.pack(side='left', padx=5, pady=5)
            
            # Show button
            ttk.Button(frame, 
                     text=f" {self.icons['eye']} Show", 
                     command=lambda v=pass_var, p=decrypt(password_enc, self.key): self.toggle_result_password(v, p),
                     style="Small.TButton").pack(side='left', padx=5)
            
            # Copy button
            ttk.Button(frame, 
                     text=f" {self.icons['copy']} Copy", 
                     command=lambda p=decrypt(password_enc, self.key): (self.copy_to_clipboard(p), self.schedule_clipboard_clear()),
                     style="Small.TButton").pack(side='left', padx=5)
            
            # Restore button
            if idx > 0:  # Don't show restore for current password
                ttk.Button(frame,
                         text=f" {self.icons['update']} Restore",
                         command=lambda pid=password_id, p=password_enc: self.restore_password(pid, p, popup),
                         style="Small.TButton").pack(side='right', padx=5)

    def restore_password(self, password_id, old_password_enc, popup=None):
        """Restore an old password"""
        if messagebox.askyesno("Confirm Restore", "Are you sure you want to restore this password?"):
            # Get current password for history
            current_password_row = execute_db_query(
                'SELECT password FROM passwords WHERE id = ?',
                (password_id,),
                fetchone=True
            )
            
            if current_password_row:
                current_password = decrypt(current_password_row[0], self.key)
                add_to_password_history(password_id, current_password, self.key)
            
            # Restore the old password
            execute_db_query(
                'UPDATE passwords SET password = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?', 
                (old_password_enc, password_id), 
                commit=True
            )
            
            messagebox.showinfo("Success", "Password restored successfully.")
            if popup:
                popup.destroy()
            self.retrieve_entries()  # Refresh the view

    def edit_entry(self, row):
        """Edit an existing entry"""
        self.clear_screen()
        self.update_activity()
        
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill='x', pady=(10, 20))
        
        ttk.Button(header_frame, 
                  text=f" {self.icons['back']} Back", 
                  command=self.retrieve_entries).pack(side='left', padx=5)
        
        ttk.Label(header_frame, 
                 text=f"{self.icons['update']} Edit Entry", 
                 font=("Segoe UI", 16, "bold")).pack()

        # Main form
        form_frame = ttk.Frame(self)
        form_frame.pack(expand=True, padx=50, pady=10)

        fields = ["Site Name", "Site URL", "Email", "Username", "Tags"]
        self.entry_vars = {}
        
        # Pre-populate fields
        for i, field in enumerate(fields):
            ttk.Label(form_frame, text=field + ":").grid(row=i, column=0, sticky='w', pady=8)
            var = tk.StringVar()
            
            value = ""
            if field == "Site Name":
                value = row[1]
            elif field == "Site URL":
                value = row[2] if row[2] else ""
            elif field == "Email":
                value = decrypt(row[3], self.key) if row[3] else ""
            elif field == "Username":
                value = decrypt(row[4], self.key) if row[4] else ""
            elif field == "Tags":
                value = row[6] if row[6] else ""
            
            var.set(value)
            entry = ttk.Entry(form_frame, textvariable=var, width=40, font=('Segoe UI', 10))
            entry.grid(row=i, column=1, pady=8, padx=10, sticky='ew')
            self.entry_vars[field] = var

        # Tags help text
        ttk.Label(form_frame, 
                 text="Comma-separated tags (e.g., work, social)", 
                 font=("Segoe UI", 8)).grid(row=4, column=1, sticky='w')

        # Password section
        ttk.Label(form_frame, text="Password:").grid(row=5, column=0, sticky='w', pady=8)
        
        password_frame = ttk.Frame(form_frame)
        password_frame.grid(row=5, column=1, sticky='ew', pady=8)
        
        self.password_entry = ttk.Entry(password_frame, show="*", width=30, font=('Segoe UI', 10))
        self.password_entry.insert(0, decrypt(row[5], self.key))
        self.password_entry.pack(side='left', fill='x', expand=True)
        
        # Password visibility toggle
        self.eye_btn = ttk.Button(password_frame, 
                                 text=self.icons['eye'], 
                                 command=self.toggle_password_visibility, 
                                 style='Small.TButton')
        self.eye_btn.pack(side='left', padx=5)

        # Generate new password button
        ttk.Button(password_frame,
                 text=f" {self.icons['generate']} Generate New",
                 command=self.generate_password_for_entry,
                 style='Small.TButton').pack(side='left', padx=5)

        # Notes section
        ttk.Label(form_frame, text="Notes:").grid(row=6, column=0, sticky='nw', pady=8)
        self.notes_text = tk.Text(form_frame, height=5, width=40, font=('Segoe UI', 10))
        notes = decrypt(row[7], self.key) if row[7] else ''
        self.notes_text.insert("1.0", notes)
        self.notes_text.grid(row=6, column=1, pady=8, padx=10, sticky='ew')

        # Favorite checkbox
        self.is_favorite_var = tk.BooleanVar(value=bool(row[8]))
        ttk.Checkbutton(form_frame,
                      text="Mark as favorite",
                      variable=self.is_favorite_var).grid(row=7, column=1, sticky='w', pady=5)

        # Submit button
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill='x', pady=20)
        
        ttk.Button(btn_frame, 
                 text=f" {self.icons['success']} Save Changes", 
                 command=lambda: self.update_entry(row[0]),
                 style="Success.TButton").pack(side='left', padx=10)
        
        ttk.Button(btn_frame, 
                 text=f" {self.icons['back']} Cancel", 
                 command=self.retrieve_entries).pack(side='right', padx=10)

    def update_entry(self, entry_id):
        """Update an existing entry in the database"""
        try:
            site = self.entry_vars["Site Name"].get().strip()
            url = self.entry_vars["Site URL"].get().strip()
            email = self.entry_vars["Email"].get().strip()
            username = self.entry_vars["Username"].get().strip()
            tags = self.entry_vars["Tags"].get().strip()
            password = self.password_entry.get()
            notes = self.notes_text.get("1.0", tk.END).strip()
            is_favorite = self.is_favorite_var.get()

            if not (site and password):
                messagebox.showerror("Error", f"{self.icons['error']} Site Name and Password are required.")
                return

            # Check if password was changed
            old_password_row = execute_db_query(
                'SELECT password FROM passwords WHERE id = ?',
                (entry_id,),
                fetchone=True
            )
            
            password_changed = False
            if old_password_row:
                old_password = decrypt(old_password_row[0], self.key)
                if password != old_password:
                    password_changed = True
                    strength, reasons = check_password_strength(password)
                    if strength == "Weak":
                        if not messagebox.askyesno("Weak Password", 
                                                 f"{self.icons['warning']} Password is weak:\n" + "\n".join(reasons) + 
                                                 "\n\nDo you still want to save it?"):
                            return
                    
                    # Check if password is compromised
                    pwned_count = check_pwned_password(password)
                    if pwned_count > 0:
                        if not messagebox.askyesno("Compromised Password", 
                                                 f"This password appears in {pwned_count} data breaches!\n"
                                                 "It's highly recommended to choose a different password.\n"
                                                 "Save anyway?"):
                            return
                    
                    # Add old password to history
                    add_to_password_history(entry_id, old_password, self.key)

            # Encrypt and save
            email_enc = encrypt(email, self.key) if email else ''
            username_enc = encrypt(username, self.key) if username else ''
            password_enc = encrypt(password, self.key)
            notes_enc = encrypt(notes, self.key) if notes else ''

            if None in [email_enc, username_enc, password_enc, notes_enc]:
                messagebox.showerror("Error", "Failed to encrypt data")
                return

            # Update the entry
            success = execute_db_query('''
                UPDATE passwords 
                SET site = ?, url = ?, email = ?, username = ?, password = ?, 
                    tags = ?, notes = ?, is_favorite = ?, last_updated = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (site, url, email_enc, username_enc, password_enc, tags, notes_enc, is_favorite, entry_id), commit=True)
            
            if success is not None:
                messagebox.showinfo("Success", f"{self.icons['success']} Entry updated successfully.")
                self.retrieve_entries()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update entry: {str(e)}")

    def delete_entry(self, entry_id):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            # First delete history entries
            execute_db_query('DELETE FROM password_history WHERE password_id = ?', 
                           (entry_id,), commit=True)
            # Then delete the entry
            execute_db_query('DELETE FROM passwords WHERE id = ?', 
                           (entry_id,), commit=True)
            messagebox.showinfo("Success", "Entry deleted successfully.")
            self.retrieve_entries()  # Refresh the results

    def update_password_screen(self):
        self.clear_screen()
        self.update_activity()
        
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill='x', pady=(10, 20))
        
        ttk.Button(header_frame, 
                  text=f" {self.icons['back']} Back", 
                  command=self.create_main_menu).pack(side='left', padx=5)
        
        ttk.Label(header_frame, 
                 text=f"{self.icons['update']} Update Password", 
                 font=("Segoe UI", 16, "bold")).pack()

        # Search form
        form_frame = ttk.Frame(self)
        form_frame.pack(expand=True, padx=50, pady=20)

        ttk.Label(form_frame, text="Site Name:").pack(anchor='w', pady=5)
        
        search_frame = ttk.Frame(form_frame)
        search_frame.pack(fill='x', pady=10)
        
        self.update_site_var = tk.StringVar()
        ttk.Entry(search_frame, 
                textvariable=self.update_site_var, 
                width=40,
                font=('Segoe UI', 10)).pack(side='left', fill='x', expand=True)
        
        ttk.Button(search_frame, 
                 text=f" {self.icons['retrieve']} Search", 
                 command=self.update_password_step2,
                 style="Accent.TButton").pack(side='left', padx=10)

    def update_password_step2(self):
        try:
            site = self.update_site_var.get().strip()
            if not site:
                messagebox.showerror("Error", f"{self.icons['error']} Please enter a site name.")
                return

            rows = execute_db_query('SELECT id, username FROM passwords WHERE site LIKE ?', (f'%{site}%',))
            
            if not rows:
                messagebox.showerror("Not Found", f"{self.icons['error']} No entries found for this site.")
                return

            if len(rows) > 1:
                # Multiple entries - let user choose which one to update
                selection = simpledialog.askinteger(
                    "Select Entry",
                    f"Multiple entries found matching '{site}'. Enter the ID of the one to update:",
                    minvalue=1
                )
                if not selection:
                    return
                
                # Verify the selected ID exists
                selected_row = None
                for row in rows:
                    if row[0] == selection:
                        selected_row = row
                        break
                
                if not selected_row:
                    messagebox.showerror("Error", "Invalid ID selected")
                    return
                
                entry_id = selected_row[0]
                username = selected_row[1]
            else:
                # Only one entry
                entry_id = rows[0][0]
                username = rows[0][1]

            new_password = simpledialog.askstring(
                "New Password", 
                f"Enter new password for {site}" + (f" (username: {username})" if username else ""), 
                show='*'
            )
            if not new_password:
                messagebox.showwarning("Cancelled", f"{self.icons['warning']} No password entered. Operation cancelled.")
                return

            strength, reasons = check_password_strength(new_password)
            if strength == "Weak":
                if not messagebox.askyesno("Weak Password", 
                                         f"{self.icons['warning']} Password is weak:\n" + "\n".join(reasons) + 
                                         "\n\nSave anyway?"):
                    return

            # Check if password is compromised
            pwned_count = check_pwned_password(new_password)
            if pwned_count > 0:
                if not messagebox.askyesno("Compromised Password", 
                                         f"This password appears in {pwned_count} data breaches!\n"
                                         "It's highly recommended to choose a different password.\n"
                                         "Save anyway?"):
                    return

            # Get old password for history
            old_password_row = execute_db_query(
                'SELECT password FROM passwords WHERE id = ?',
                (entry_id,),
                fetchone=True
            )
            
            if old_password_row:
                old_password = decrypt(old_password_row[0], self.key)
                add_to_password_history(entry_id, old_password, self.key)

            new_password_enc = encrypt(new_password, self.key)
            if new_password_enc is None:
                messagebox.showerror("Error", "Failed to encrypt new password")
                return

            execute_db_query('UPDATE passwords SET password = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?', 
                          (new_password_enc, entry_id), commit=True)

            pyperclip.copy(new_password)
            self.schedule_clipboard_clear()
            messagebox.showinfo("Success", f"{self.icons['success']} Password updated and copied to clipboard.")
            self.create_main_menu()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while updating password: {str(e)}")

    def password_generator_screen(self):
        self.clear_screen()
        self.update_activity()
        
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill='x', pady=(10, 20))
        
        ttk.Button(header_frame, 
                  text=f" {self.icons['back']} Back", 
                  command=self.create_main_menu).pack(side='left', padx=5)
        
        ttk.Label(header_frame, 
                 text=f"{self.icons['generate']} Password Generator", 
                 font=("Segoe UI", 16, "bold")).pack()

        # Main form
        form_frame = ttk.Frame(self)
        form_frame.pack(expand=True, padx=50, pady=20)

        # Length control
        length_frame = ttk.Frame(form_frame)
        length_frame.pack(fill='x', pady=10)
        
        ttk.Label(length_frame, text="Length:").pack(side='left')
        self.gen_length_var = tk.IntVar(value=12)
        ttk.Spinbox(length_frame, 
                   from_=8, to=64, 
                   width=5, 
                   textvariable=self.gen_length_var).pack(side='left', padx=10)

        # Character types
        options_frame = ttk.Frame(form_frame)
        options_frame.pack(fill='x', pady=10)
        
        self.gen_upper_var = tk.BooleanVar(value=True)
        self.gen_lower_var = tk.BooleanVar(value=True)
        self.gen_digits_var = tk.BooleanVar(value=True)
        self.gen_symbols_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, 
                       text="Uppercase (A-Z)", 
                       variable=self.gen_upper_var).pack(anchor='w', pady=2)
        ttk.Checkbutton(options_frame, 
                       text="Lowercase (a-z)", 
                       variable=self.gen_lower_var).pack(anchor='w', pady=2)
        ttk.Checkbutton(options_frame, 
                       text="Digits (0-9)", 
                       variable=self.gen_digits_var).pack(anchor='w', pady=8)
        ttk.Checkbutton(options_frame, 
                       text="Symbols (!@#...)", 
                       variable=self.gen_symbols_var).pack(anchor='w', pady=2)

        # Generate button
        ttk.Button(form_frame,
                 text=f" {self.icons['generate']} Generate Password",
                 command=self.generate_password_gui,
                 style="Accent.TButton").pack(pady=20)

        # Result display
        result_frame = ttk.Frame(form_frame)
        result_frame.pack(fill='x', pady=10)
        
        self.generated_password_var = tk.StringVar()
        ttk.Entry(result_frame, 
                textvariable=self.generated_password_var, 
                font=("Segoe UI", 12),
                state='readonly',
                width=30).pack(side='left', fill='x', expand=True)
        
        ttk.Button(result_frame, 
                 text=f" {self.icons['copy']} Copy", 
                 command=self.copy_generated_password,
                 style="Small.TButton").pack(side='left', padx=5)

        # Strength indicator
        self.strength_label = ttk.Label(form_frame, 
                                      text=f"{self.icons['strength']} Strength: -", 
                                      font=("Segoe UI", 10))
        self.strength_label.pack(pady=10)

    def generate_password_gui(self):
        length = self.gen_length_var.get()
        pw = generate_password(
            length,
            self.gen_upper_var.get(),
            self.gen_lower_var.get(),
            self.gen_digits_var.get(),
            self.gen_symbols_var.get()
        )
        
        if pw:
            self.generated_password_var.set(pw)
            strength, reasons = check_password_strength(pw)
            color = theme.success if strength == "Strong" else theme.warning if strength == "Moderate" else theme.error
            self.strength_label.config(
                text=f"{self.icons['strength']} Strength: {strength}",
                foreground=color
            )
            messagebox.showinfo("Success", f"{self.icons['success']} Password generated and copied to clipboard.")
            pyperclip.copy(pw)
            self.schedule_clipboard_clear()
        else:
            messagebox.showerror("Error", f"{self.icons['error']} Failed to generate password. Please check options.")

    def copy_generated_password(self):
        pw = self.generated_password_var.get()
        if pw:
            pyperclip.copy(pw)
            self.schedule_clipboard_clear()
            messagebox.showinfo("Copied", f"{self.icons['success']} Password copied to clipboard.")
        else:
            messagebox.showwarning("Empty", f"{self.icons['warning']} No password to copy.")

    def password_audit_screen(self):
        self.clear_screen()
        self.update_activity()
        
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill='x', pady=(10, 20))
        
        ttk.Button(header_frame, 
                  text=f" {self.icons['back']} Back", 
                  command=self.create_main_menu).pack(side='left', padx=5)
        
        ttk.Label(header_frame, 
                 text=f"{self.icons['audit']} Password Audit", 
                 font=("Segoe UI", 16, "bold")).pack()

        # Main content
        container = ttk.Frame(self)
        container.pack(fill='both', expand=True, padx=20, pady=10)

        # Run audit button
        ttk.Button(container,
                 text=f" {self.icons['audit']} Run Password Audit",
                 command=self.run_password_audit,
                 style="Accent.TButton").pack(pady=20)

        # Results frame
        self.audit_results_frame = ttk.Frame(container)
        self.audit_results_frame.pack(fill='both', expand=True)

    def run_password_audit(self):
        """Analyze passwords for weaknesses"""
        try:
            # Clear previous results
            for widget in self.audit_results_frame.winfo_children():
                widget.destroy()

            # Get all passwords
            entries = execute_db_query('SELECT id, site, username, password FROM passwords')
            
            if not entries:
                messagebox.showinfo("No Entries", "No password entries found to audit.")
                return

            weak_passwords = []
            reused_passwords = {}
            compromised_passwords = []
            
            # Check each password
            for entry in entries:
                entry_id, site, username, password_enc = entry
                password = decrypt(password_enc, self.key)
                
                # Check strength
                strength, reasons = check_password_strength(password)
                if strength != "Strong":
                    weak_passwords.append({
                        'id': entry_id,
                        'site': site,
                        'username': username,
                        'strength': strength,
                        'reasons': reasons
                    })
                
                # Check for reuse
                if password in reused_passwords:
                    reused_passwords[password].append({
                        'id': entry_id,
                        'site': site,
                        'username': username
                    })
                else:
                    reused_passwords[password] = [{
                        'id': entry_id,
                        'site': site,
                        'username': username
                    }]
                
                # Check if compromised (only check once per unique password)
                if password not in reused_passwords or reused_passwords[password][0]['id'] == entry_id:
                    pwned_count = check_pwned_password(password)
                    if pwned_count > 0:
                        compromised_passwords.append({
                            'id': entry_id,
                            'site': site,
                            'username': username,
                            'breach_count': pwned_count
                        })

            # Filter out passwords that aren't actually reused
            reused_passwords = {k: v for k, v in reused_passwords.items() if len(v) > 1}

            # Create scrollable results area
            canvas = tk.Canvas(self.audit_results_frame)
            scrollbar = ttk.Scrollbar(self.audit_results_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
            
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            # Display results
            if weak_passwords or reused_passwords or compromised_passwords:
                # Weak passwords section
                if weak_passwords:
                    ttk.Label(scrollable_frame, 
                             text=f"{self.icons['warning']} Weak Passwords", 
                             font=("Segoe UI", 14, "bold")).pack(anchor='w', pady=(10,5))
                    
                    for entry in weak_passwords:
                        frame = ttk.Frame(scrollable_frame, style="Card.TFrame")
                        frame.pack(fill='x', pady=5, padx=5, ipadx=5, ipady=5)
                        
                        ttk.Label(frame, 
                                 text=f"🔒 {entry['site']} ({entry['username']})", 
                                 font=("Segoe UI", 12)).pack(anchor='w')
                        
                        ttk.Label(frame, 
                                 text=f"Strength: {entry['strength']}", 
                                 font=("Segoe UI", 10)).pack(anchor='w')
                        
                        reasons_frame = ttk.Frame(frame)
                        reasons_frame.pack(anchor='w', pady=5)
                        ttk.Label(reasons_frame, 
                                 text="Issues:", 
                                 font=("Segoe UI", 9)).pack(side='left')
                        
                        for reason in entry['reasons']:
                            ttk.Label(reasons_frame, 
                                     text=reason, 
                                     font=("Segoe UI", 9),
                                     background="#555555" if theme.is_dark else "#eeeeee",
                                     relief="groove",
                                     padding=2).pack(side='left', padx=2)
                        
                        ttk.Button(frame,
                                 text=f" {self.icons['update']} Update",
                                 command=lambda e=entry: self.update_entry_from_audit(e),
                                 style="Warning.TButton").pack(pady=5)

                # Reused passwords section
                if reused_passwords:
                    ttk.Label(scrollable_frame, 
                             text=f"{self.icons['warning']} Reused Passwords", 
                             font=("Segoe UI", 14, "bold")).pack(anchor='w', pady=(20,5))
                    
                    for password, entries in reused_passwords.items():
                        frame = ttk.Frame(scrollable_frame, style="Card.TFrame")
                        frame.pack(fill='x', pady=5, padx=5, ipadx=5, ipady=5)
                        
                        ttk.Label(frame, 
                                 text=f"🔑 Password used in {len(entries)} accounts:", 
                                 font=("Segoe UI", 12)).pack(anchor='w')
                        
                        for entry in entries:
                            ttk.Label(frame, 
                                     text=f"• {entry['site']} ({entry['username']})", 
                                     font=("Segoe UI", 10)).pack(anchor='w')
                        
                        ttk.Button(frame,
                                 text=f" {self.icons['update']} Update All",
                                 command=lambda e=entries: self.update_reused_passwords(e),
                                 style="Warning.TButton").pack(pady=5)

                # Compromised passwords section
                if compromised_passwords:
                    ttk.Label(scrollable_frame, 
                             text=f"{self.icons['error']} Compromised Passwords", 
                             font=("Segoe UI", 14, "bold")).pack(anchor='w', pady=(20,5))
                    
                    for entry in compromised_passwords:
                        frame = ttk.Frame(scrollable_frame, style="Card.TFrame")
                        frame.pack(fill='x', pady=5, padx=5, ipadx=5, ipady=5)
                        
                        ttk.Label(frame, 
                                 text=f"🚨 {entry['site']} ({entry['username']})", 
                                 font=("Segoe UI", 12)).pack(anchor='w')
                        
                        ttk.Label(frame, 
                                 text=f"Found in {entry['breach_count']} data breaches!", 
                                 font=("Segoe UI", 10)).pack(anchor='w')
                        
                        ttk.Button(frame,
                                 text=f" {self.icons['update']} Update Immediately",
                                 command=lambda e=entry: self.update_entry_from_audit(e),
                                 style="Error.TButton").pack(pady=5)

                # Summary
                ttk.Label(scrollable_frame, 
                         text=f"🔍 Audit Summary", 
                         font=("Segoe UI", 14, "bold")).pack(anchor='w', pady=(20,5))
                
                summary_frame = ttk.Frame(scrollable_frame, style="Card.TFrame")
                summary_frame.pack(fill='x', pady=5, padx=5, ipadx=5, ipady=5)
                
                ttk.Label(summary_frame, 
                         text=f"• {len(weak_passwords)} weak passwords", 
                         font=("Segoe UI", 10)).pack(anchor='w')
                
                ttk.Label(summary_frame, 
                         text=f"• {len(reused_passwords)} passwords reused across accounts", 
                         font=("Segoe UI", 10)).pack(anchor='w')
                
                ttk.Label(summary_frame, 
                         text=f"• {len(compromised_passwords)} passwords found in breaches", 
                         font=("Segoe UI", 10)).pack(anchor='w')
            else:
                ttk.Label(scrollable_frame, 
                         text=f"{self.icons['success']} All passwords meet security standards!", 
                         font=("Segoe UI", 12)).pack(pady=20)

        except Exception as e:
            messagebox.showerror("Audit Error", f"Failed to run password audit: {str(e)}")

    def update_entry_from_audit(self, entry):
        """Update an entry identified in the audit"""
        self.retrieve_entries()  # Go back to retrieve screen
        self.update_site_var.set(entry['site'])  # Set the site filter
        self.retrieve_entries()  # Search for the entry
        
        # The rest will be handled by the retrieve screen's edit functionality

    def update_reused_passwords(self, entries):
        """Update all entries sharing the same password"""
        if not messagebox.askyesno("Confirm Update", 
                                 f"Update {len(entries)} entries sharing the same password?"):
            return
        
        new_password = simpledialog.askstring(
            "New Password", 
            "Enter new password for all selected entries:", 
            show='*'
        )
        
        if not new_password:
            return
        
        strength, reasons = check_password_strength(new_password)
        if strength == "Weak":
            if not messagebox.askyesno("Weak Password", 
                                     f"Password is weak:\n" + "\n".join(reasons) + 
                                     "\n\nSave anyway?"):
                return
        
        # Check if password is compromised
        pwned_count = check_pwned_password(new_password)
        if pwned_count > 0:
            if not messagebox.askyesno("Compromised Password", 
                                     f"This password appears in {pwned_count} data breaches!\n"
                                     "It's highly recommended to choose a different password.\n"
                                     "Save anyway?"):
                return

        new_password_enc = encrypt(new_password, self.key)
        if new_password_enc is None:
            messagebox.showerror("Error", "Failed to encrypt new password")
            return
        
        updated = 0
        for entry in entries:
            # Get old password for history
            old_password_row = execute_db_query(
                'SELECT password FROM passwords WHERE id = ?',
                (entry['id'],),
                fetchone=True
            )
            
            if old_password_row:
                old_password = decrypt(old_password_row[0], self.key)
                add_to_password_history(entry['id'], old_password, self.key)
            
            # Update the password
            execute_db_query(
                'UPDATE passwords SET password = ?, last_updated = CURRENT_TIMESTAMP WHERE id = ?', 
                (new_password_enc, entry['id']), 
                commit=True
            )
            updated += 1
        
        pyperclip.copy(new_password)
        self.schedule_clipboard_clear()
        messagebox.showinfo("Success", f"Updated {updated} entries with new password.")
        self.password_audit_screen()  # Refresh audit results

    def import_export_screen(self):
        self.clear_screen()
        self.update_activity()
        
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill='x', pady=(10, 20))
        
        ttk.Button(header_frame, 
                  text=f" {self.icons['back']} Back", 
                  command=self.create_main_menu).pack(side='left', padx=5)
        
        ttk.Label(header_frame, 
                 text=f"{self.icons['export']} Import/Export", 
                 font=("Segoe UI", 16, "bold")).pack()

        # Main content
        container = ttk.Frame(self)
        container.pack(fill='both', expand=True, padx=50, pady=20)

        # Export section
        export_frame = ttk.Frame(container, style="Card.TFrame")
        export_frame.pack(fill='x', pady=10, ipadx=10, ipady=10)
        
        ttk.Label(export_frame, 
                 text=f"{self.icons['export']} Export Passwords", 
                 font=("Segoe UI", 12, "bold")).pack(anchor='w', pady=5)
        
        # Export options
        self.export_tag_var = tk.StringVar()
        self.export_favorites_var = tk.BooleanVar(value=False)
        
        options_frame = ttk.Frame(export_frame)
        options_frame.pack(fill='x', pady=10)
        
        ttk.Label(options_frame, text="Filter by tag:").pack(side='left', padx=5)
        ttk.Entry(options_frame, 
                 textvariable=self.export_tag_var, 
                 width=20).pack(side='left', padx=5)
        
        ttk.Checkbutton(options_frame,
                      text="Favorites only",
                      variable=self.export_favorites_var).pack(side='left', padx=10)
        
        # Export button
        ttk.Button(export_frame,
                 text=f" {self.icons['export']} Export to CSV",
                 command=self.export_passwords,
                 style="Accent.TButton").pack(pady=5)

        # Import section
        import_frame = ttk.Frame(container, style="Card.TFrame")
        import_frame.pack(fill='x', pady=10, ipadx=10, ipady=10)
        
        ttk.Label(import_frame, 
                 text=f"{self.icons['import']} Import Passwords", 
                 font=("Segoe UI", 12, "bold")).pack(anchor='w', pady=5)
        
        ttk.Label(import_frame, 
                 text="Import passwords from a CSV file", 
                 font=("Segoe UI", 9)).pack(anchor='w', pady=5)
        
        # Import button
        ttk.Button(import_frame,
                 text=f" {self.icons['import']} Import from CSV",
                 command=self.import_passwords,
                 style="Accent.TButton").pack(pady=5)

    def export_passwords(self):
        """Export passwords to CSV file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Save Password Export"
        )
        
        if not filename:
            return
        
        tag_filter = self.export_tag_var.get().strip()
        favorites_only = self.export_favorites_var.get()
        
        if export_to_csv(filename, self.key, tag_filter if tag_filter else None, favorites_only):
            messagebox.showinfo("Success", f"Passwords exported successfully to {filename}")

    def import_passwords(self):
        """Import passwords from CSV file"""
        filename = filedialog.askopenfilename(
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Select Password CSV File"
        )
        
        if not filename:
            return
        
        imported, skipped = import_from_csv(filename, self.key)
        messagebox.showinfo("Import Complete", 
                          f"Import completed with {imported} new entries added and {skipped} duplicates skipped.")
        self.create_main_menu()

    def toggle_result_password(self, var, real_password):
        current = var.get()
        if current == "••••••••":
            var.set(real_password)
        else:
            var.set("••••••••")

    def copy_to_clipboard(self, text):
        pyperclip.copy(text)
        self.schedule_clipboard_clear()

    def logout(self):
        self.master_password = None
        self.key = None
        self.attempts = 0
        self.notification_frame.pack_forget()  # Hide notification when logging out
        if self.clipboard_clear_job:
            self.after_cancel(self.clipboard_clear_job)
        pyperclip.copy("")  # Clear clipboard on logout
        self.create_login_screen()

    def clear_screen(self):
        for widget in self.winfo_children():
            if widget != self.notification_frame:  # Keep notification frame
                widget.destroy()

if __name__ == "__main__":
    app = SecurePassVaultApp()
    app.mainloop()