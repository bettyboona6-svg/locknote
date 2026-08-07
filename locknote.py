import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

MAGIC = b"LNC1"

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    return kdf.derive(password.encode("utf-8"))

def encrypt_text(plaintext: str, password: str) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    return MAGIC + salt + iv + ct

def decrypt_bytes(data: bytes, password: str) -> str:
    if data[:4] != MAGIC:
        raise ValueError("Not a recognized LockNote-clone file.")
    salt = data[4:20]
    iv = data[20:32]
    ct = data[32:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(iv, ct, None)
    return pt.decode("utf-8")


class LockNoteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LockNote Clone")
        self.root.geometry("800x600")
        self.current_path = None
        self.dirty = False

        toolbar = tk.Frame(root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        tk.Button(toolbar, text="New", command=self.new_note).pack(side=tk.LEFT, padx=3)
        tk.Button(toolbar, text="Open…", command=self.open_note).pack(side=tk.LEFT, padx=3)
        tk.Button(toolbar, text="Save (Encrypted)", command=self.save_note).pack(side=tk.LEFT, padx=3)
        tk.Button(toolbar, text="Lock && Clear", command=self.lock_clear).pack(side=tk.LEFT, padx=3)
        tk.Button(toolbar, text="A-", width=3, command=self.decrease_font).pack(side=tk.LEFT, padx=(15, 2))
        tk.Button(toolbar, text="A+", width=3, command=self.increase_font).pack(side=tk.LEFT, padx=2)

        self.status_var = tk.StringVar(value="New, unsaved note")
        tk.Label(toolbar, textvariable=self.status_var, fg="gray").pack(side=tk.RIGHT, padx=6)

        self.font_size = 11
        self.text = tk.Text(root, wrap=tk.WORD, undo=True, font=("Consolas", self.font_size))
        self.text.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))
        self.text.bind("<<Modified>>", self.on_modified)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def increase_font(self):
        self.font_size = min(self.font_size + 2, 48)
        self.text.configure(font=("Consolas", self.font_size))

    def decrease_font(self):
        self.font_size = max(self.font_size - 2, 8)
        self.text.configure(font=("Consolas", self.font_size))

    def on_modified(self, event=None):
        if self.text.edit_modified():
            self.dirty = True
            self.update_status()
            self.text.edit_modified(False)

    def update_status(self, name=None):
        if name is not None:
            self.current_path = name
        label = os.path.basename(self.current_path) if self.current_path else "New, unsaved note"
        if self.dirty:
            label += "  —  unsaved changes"
        self.status_var.set(label)

    def new_note(self):
        if self.dirty and not messagebox.askyesno("Discard changes?", "Discard current note without saving?"):
            return
        self.text.delete("1.0", tk.END)
        self.current_path = None
        self.dirty = False
        self.update_status()

    def lock_clear(self):
        if not messagebox.askyesno("Lock & Clear", "Clear the editor now? Make sure you already saved."):
            return
        self.text.delete("1.0", tk.END)
        self.current_path = None
        self.dirty = False
        self.update_status()

    def save_note(self):
        pw1 = simpledialog.askstring("Set Password", "Password:", show="*")
        if pw1 is None:
            return
        pw2 = simpledialog.askstring("Confirm Password", "Confirm password:", show="*")
        if pw2 is None:
            return
        if not pw1:
            messagebox.showerror("Error", "Password cannot be empty.")
            return
        if pw1 != pw2:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        default_name = os.path.basename(self.current_path) if self.current_path else "note.lnote"
        path = filedialog.asksaveasfilename(
            defaultextension=".lnote",
            initialfile=default_name,
            filetypes=[("LockNote file", "*.lnote")],
        )
        if not path:
            return

        plaintext = self.text.get("1.0", tk.END + "-1c")
        try:
            data = encrypt_text(plaintext, pw1)
            with open(path, "wb") as f:
                f.write(data)
            self.dirty = False
            self.update_status(path)
            messagebox.showinfo("Saved", f"Encrypted note saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Encryption failed", str(e))

    def open_note(self):
        path = filedialog.askopenfilename(filetypes=[("LockNote file", "*.lnote"), ("All files", "*.*")])
        if not path:
            return
        pw = simpledialog.askstring("Enter Password", f"Unlock {os.path.basename(path)}:", show="*")
        if pw is None:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            plaintext = decrypt_bytes(data, pw)
        except Exception:
            messagebox.showerror("Error", "Wrong password, or file is corrupted / not a valid note.")
            return

        if self.dirty and not messagebox.askyesno("Discard changes?", "Discard current unsaved note and open this file?"):
            return

        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", plaintext)
        self.dirty = False
        self.update_status(path)

    def on_close(self):
        if self.dirty and not messagebox.askyesno("Quit", "You have unsaved changes. Quit anyway?"):
            return
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = LockNoteApp(root)
    root.mainloop()
