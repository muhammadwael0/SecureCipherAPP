import base64
import ctypes
import hashlib
import hmac
import secrets
import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk


# ==========================================
# Cryptographic Backend Logic
# ==========================================
def generate_keystream(key: bytes, length: int, nonce: bytes) -> bytes:
    """Generates a cryptographically strong pseudo-random keystream using HMAC-SHA256."""
    keystream = bytearray()
    counter = 0

    while len(keystream) < length:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        block = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
        keystream.extend(block)
        counter += 1

    return bytes(keystream[:length])


def encode_message(plain_text: str, passphrase: str) -> str:
    """Encrypts plaintext string using PBKDF2 key derivation and SHA-256 HMAC keystream."""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, 100_000, dklen=64
    )
    encryption_key = derived_key[:32]
    mac_key = derived_key[32:]

    plain_bytes = plain_text.encode("utf-8")
    keystream = generate_keystream(encryption_key, len(plain_bytes), nonce)
    ciphertext_bytes = bytes(p ^ k for p, k in zip(plain_bytes, keystream))

    auth_tag = hmac.new(
        mac_key, salt + nonce + ciphertext_bytes, hashlib.sha256
    ).digest()
    payload = salt + nonce + auth_tag + ciphertext_bytes
    return base64.b64encode(payload).decode("utf-8")


def decode_message(cipher_text: str, passphrase: str) -> str:
    """Decrypts ciphertext payload and verifies authenticity using HMAC tag."""
    try:
        payload = base64.b64decode(cipher_text.encode("utf-8"))
        if len(payload) < 64:
            raise ValueError("Corrupted cipher payload.")

        salt = payload[:16]
        nonce = payload[16:32]
        stored_auth_tag = payload[32:64]
        ciphertext_bytes = payload[64:]

        derived_key = hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode("utf-8"), salt, 100_000, dklen=64
        )
        encryption_key = derived_key[:32]
        mac_key = derived_key[32:]

        calculated_auth_tag = hmac.new(
            mac_key, salt + nonce + ciphertext_bytes, hashlib.sha256
        ).digest()

        if not hmac.compare_digest(stored_auth_tag, calculated_auth_tag):
            raise ValueError("Incorrect secret key or payload modified.")

        keystream = generate_keystream(
            encryption_key, len(ciphertext_bytes), nonce
        )
        plain_bytes = bytes(
            c ^ k for c, k in zip(ciphertext_bytes, keystream)
        )
        return plain_bytes.decode("utf-8")
    except Exception:
        raise ValueError("Decryption failed. Verify secret key and ciphertext.")


# ==========================================
# Dynamic Scaling Windows GUI Class
# ==========================================
class WindowsCipherApp(tk.Tk):

    BASE_WIDTH = 700
    BASE_HEIGHT = 750

    TEXT_FG_COLOR = "#111827"
    TEXT_BG_COLOR = "#FFFFFF"
    SELECT_BG_COLOR = "#2563EB"

    def __init__(self):
        super().__init__()

        self._enable_windows_dpi_awareness()

        self.title("Secure Cipher Studio")
        self.geometry(f"{self.BASE_WIDTH}x{self.BASE_HEIGHT}")
        self.minsize(580, 620)

        # Initialize Dynamic Font Objects
        self.font_title = tkfont.Font(
            family="Segoe UI", size=20, weight="bold"
        )
        self.font_section = tkfont.Font(
            family="Segoe UI", size=12, weight="bold"
        )
        self.font_input = tkfont.Font(family="Segoe UI", size=13)
        self.font_mono = tkfont.Font(family="Consolas", size=12)
        self.font_button = tkfont.Font(
            family="Segoe UI", size=11, weight="bold"
        )

        # Configure TTK Theme & Styles
        self.style = ttk.Style(self)
        available_themes = self.style.theme_names()
        if "vista" in available_themes:
            self.style.theme_use("vista")

        self.style.configure("TLabelframe.Label", font=self.font_section)
        self.style.configure("TButton", font=self.font_button, padding=8)
        self.style.configure("TCheckbutton", font=self.font_input)

        self._build_ui()

        # Bind window resize event for dynamic font scaling
        self.bind("<Configure>", self._on_window_resize)

    def _enable_windows_dpi_awareness(self):
        """Configures Windows High DPI Awareness to prevent blurry UI."""
        if sys.platform == "win32":
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                try:
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass

    def _on_window_resize(self, event):
        """Dynamically scales all application fonts based on window size."""
        # Ensure resize handler applies only to root window, not child widgets
        if event.widget != self:
            return

        # Calculate scale ratio relative to base dimensions
        scale_x = event.width / self.BASE_WIDTH
        scale_y = event.height / self.BASE_HEIGHT
        scale = min(scale_x, scale_y)

        # Prevent text from becoming unreadably small
        scale = max(0.85, scale)

        # Update dynamic font sizes
        self.font_title.configure(size=int(20 * scale))
        self.font_section.configure(size=int(12 * scale))
        self.font_input.configure(size=int(13 * scale))
        self.font_mono.configure(size=int(12 * scale))
        self.font_button.configure(size=int(11 * scale))

    def _build_ui(self):
        """Constructs UI layout using dynamic font objects."""
        main_frame = ttk.Frame(self, padding=24)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header Title
        title_label = ttk.Label(
            main_frame, text="🔒 Secure Cipher Tool", font=self.font_title
        )
        title_label.pack(anchor=tk.W, pady=(0, 20))

        # 1. Secret Passphrase Section
        key_frame = ttk.LabelFrame(
            main_frame, text=" 1. Secret Passphrase ", padding=14
        )
        key_frame.pack(fill=tk.X, pady=(0, 18))

        entry_subframe = ttk.Frame(key_frame)
        entry_subframe.pack(fill=tk.X, expand=True)

        self.key_entry = ttk.Entry(
            entry_subframe, show="•", font=self.font_input
        )
        self.key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12))

        self.show_pass_var = tk.BooleanVar(value=False)
        show_pass_btn = ttk.Checkbutton(
            entry_subframe,
            text="Show Passphrase",
            variable=self.show_pass_var,
            command=self._toggle_passphrase_visibility,
        )
        show_pass_btn.pack(side=tk.RIGHT)

        # 2. Input Message Section
        input_frame = ttk.LabelFrame(
            main_frame, text=" 2. Input Message ", padding=14
        )
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 18))

        self.input_text = tk.Text(
            input_frame,
            height=5,
            font=self.font_input,
            wrap=tk.WORD,
            relief=tk.SOLID,
            borderwidth=1,
            padx=12,
            pady=10,
            spacing1=3,
            spacing3=3,
            fg=self.TEXT_FG_COLOR,
            bg=self.TEXT_BG_COLOR,
            insertbackground=self.TEXT_FG_COLOR,
            selectbackground=self.SELECT_BG_COLOR,
        )
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # Action Buttons Section
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 18))

        encrypt_btn = ttk.Button(
            btn_frame, text="Encrypt Text", command=self.handle_encrypt
        )
        encrypt_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        decrypt_btn = ttk.Button(
            btn_frame, text="Decrypt Text", command=self.handle_decrypt
        )
        decrypt_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))

        # 3. Result Output Section
        output_frame = ttk.LabelFrame(
            main_frame, text=" 3. Result Output ", padding=14
        )
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 18))

        self.output_text = tk.Text(
            output_frame,
            height=5,
            font=self.font_mono,
            wrap=tk.CHAR,
            relief=tk.SOLID,
            borderwidth=1,
            padx=12,
            pady=10,
            spacing1=2,
            spacing3=2,
            fg=self.TEXT_FG_COLOR,
            bg=self.TEXT_BG_COLOR,
            insertbackground=self.TEXT_FG_COLOR,
            selectbackground=self.SELECT_BG_COLOR,
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Bottom Utility Buttons Section
        utility_frame = ttk.Frame(main_frame)
        utility_frame.pack(fill=tk.X)

        copy_btn = ttk.Button(
            utility_frame,
            text="Copy Result",
            command=self.copy_to_clipboard,
        )
        copy_btn.pack(side=tk.LEFT, padx=(0, 10))

        clear_btn = ttk.Button(
            utility_frame, text="Clear All", command=self.clear_fields
        )
        clear_btn.pack(side=tk.LEFT)

    def _toggle_passphrase_visibility(self):
        if self.show_pass_var.get():
            self.key_entry.config(show="")
        else:
            self.key_entry.config(show="•")

    def handle_encrypt(self):
        passphrase = self.key_entry.get().strip()
        plain_text = self.input_text.get("1.0", tk.END).strip()

        if not passphrase or not plain_text:
            messagebox.showwarning(
                "Missing Input",
                "Please provide both a secret passphrase and a message.",
            )
            return

        try:
            cipher_result = encode_message(plain_text, passphrase)
            self._set_output_text(cipher_result)
        except Exception as err:
            messagebox.showerror("Encryption Error", str(err))

    def handle_decrypt(self):
        passphrase = self.key_entry.get().strip()
        cipher_text = self.input_text.get("1.0", tk.END).strip()

        if not passphrase or not cipher_text:
            messagebox.showwarning(
                "Missing Input",
                "Please provide both a secret passphrase and a ciphertext.",
            )
            return

        try:
            plain_result = decode_message(cipher_text, passphrase)
            self._set_output_text(plain_result)
        except ValueError as err:
            messagebox.showerror("Decryption Failed", str(err))

    def _set_output_text(self, text_content: str):
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text_content)

    def copy_to_clipboard(self):
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            self.clipboard_clear()
            self.clipboard_append(result)
            messagebox.showinfo(
                "Success", "Result successfully copied to clipboard!"
            )

    def clear_fields(self):
        self.key_entry.delete(0, tk.END)
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)


if __name__ == "__main__":
    app = WindowsCipherApp()
    app.mainloop()