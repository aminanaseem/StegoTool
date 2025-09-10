import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import os
import subprocess
import threading
from stegano import lsb
import re
import tempfile
import shutil
import base64
import binascii

# AES (via cryptography)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets
import time

APP_TEMP_ROOT = None  # set per run, cleaned on exit
FILE_HEADER = "FILE:"  # Our custom header for identifying hidden files

def make_tempdir():
    global APP_TEMP_ROOT
    if APP_TEMP_ROOT is None:
        APP_TEMP_ROOT = tempfile.mkdtemp(prefix="stegotool_")
    return APP_TEMP_ROOT

def cleanup_temp():
    global APP_TEMP_ROOT
    if APP_TEMP_ROOT and os.path.isdir(APP_TEMP_ROOT):
        shutil.rmtree(APP_TEMP_ROOT, ignore_errors=True)
    APP_TEMP_ROOT = None

def kdf_key_from_password(password: str, salt: bytes) -> bytes:
    # 256-bit key using PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))

def aes_encrypt(plaintext: str, password: str) -> str:
    """Return armored payload with header for auto-detection."""
    salt = secrets.token_bytes(16)
    key = kdf_key_from_password(password, salt)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = b"|".join([b"STEGOTOOL_AES_v1", salt, nonce, ct])
    return base64.b64encode(blob).decode("ascii")

def aes_decrypt(armored: str, password: str) -> str:
    data = base64.b64decode(armored.encode("ascii"))
    parts = data.split(b"|", 3)
    if len(parts) != 4 or parts[0] != b"STEGOTOOL_AES_v1":
        raise ValueError("Not an AES payload")
    salt, nonce, ct = parts[1], parts[2], parts[3]
    key = kdf_key_from_password(password, salt)
    aes = AESGCM(key)
    pt = aes.decrypt(nonce, ct, None)
    return pt.decode("utf-8")

class StegoTool:
    def __init__(self, root):
        self.root = root
        self.root.title("StegoTool Professional - Complete Edition")
        self.root.geometry("1000x900")
        self.root.configure(bg="#2c3e50")

        # Ensure temp root exists and cleanup on close
        make_tempdir()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('Title.TLabel', background="#2c3e50", foreground="#ecf0f1", font=('Helvetica', 16, 'bold'))
        self.style.configure('Custom.TFrame', background="#34495e")
        self.style.configure('Custom.TButton', background="#3498db", foreground="#2c3e50", font=('Helvetica', 10, 'bold'), padding=10)
        self.style.map('Custom.TButton', background=[('active', '#2980b9')])
        self.style.configure('Detect.TButton', background="#e74c3c", foreground="#ecf0f1", font=('Helvetica', 12, 'bold'), padding=10)
        self.style.map('Detect.TButton', background=[('active', '#c0392b')])
        self.style.configure('Hide.TButton', background="#2ecc71", foreground="#ecf0f1", font=('Helvetica', 12, 'bold'), padding=10)
        self.style.map('Hide.TButton', background=[('active', '#27ae60')])
        self.style.configure('Extract.TButton', background="#f39c12", foreground="#ecf0f1", font=('Helvetica', 12, 'bold'), padding=10)
        self.style.map('Extract.TButton', background=[('active', '#e67e22')])
        self.style.configure('Result.TLabel', background="#34495e", foreground="#ecf0f1", font=('Courier', 10))

        # Tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.detect_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(self.detect_frame, text="Analysis & Detection")
        self.hide_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(self.hide_frame, text="Hide Message")
        self.extract_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(self.extract_frame, text="Extract Message")

        self.current_image = None
        self.hide_image_path = None
        self.extract_image_path = None
        self.wordlist_path = None
        self.file_to_hide_path = None

        self.setup_detection_tab()
        self.setup_hide_tab()
        self.setup_extract_tab()

    def on_close(self):
        cleanup_temp()
        self.root.destroy()

    # ------------ Detection tab ------------
    def setup_detection_tab(self):
        title_label = ttk.Label(self.detect_frame, text="STEGANOGRAPHY ANALYSIS & DETECTION", style='Title.TLabel')
        title_label.pack(pady=20)

        self.image_frame = ttk.Frame(self.detect_frame, style='Custom.TFrame')
        self.image_frame.pack(pady=10)

        self.image_label = ttk.Label(self.image_frame, text="No image selected", background="#34495e", foreground="#ecf0f1")
        self.image_label.pack(pady=10)

        self.button_frame = ttk.Frame(self.detect_frame, style='Custom.TFrame')
        self.button_frame.pack(pady=10)

        self.select_btn = ttk.Button(self.button_frame, text="Select Image", command=self.select_image, style='Custom.TButton')
        self.select_btn.pack(side=tk.LEFT, padx=5)

        self.detect_btn = ttk.Button(self.button_frame, text="Analyze & Detect", command=self.detect_steganography, style='Detect.TButton')
        self.detect_btn.pack(side=tk.LEFT, padx=5)
        self.detect_btn.state(['disabled'])

        self.extract_meta_btn = ttk.Button(self.button_frame, text="Extract Metadata", command=self.extract_metadata, style='Custom.TButton')
        self.extract_meta_btn.pack(side=tk.LEFT, padx=5)
        self.extract_meta_btn.state(['disabled'])

        self.results_frame = ttk.Frame(self.detect_frame, style='Custom.TFrame')
        self.results_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.results_label = ttk.Label(self.results_frame, text="Analysis Results:", style='Title.TLabel')
        self.results_label.pack(anchor=tk.W, pady=(0, 10))

        self.results_text = scrolledtext.ScrolledText(self.results_frame, height=15, width=80, bg="#2c3e50", fg="#ecf0f1", font=('Courier', 10))
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.insert(tk.END, "No analysis performed yet. Select an image and click 'Analyze & Detect'.")
        self.results_text.config(state=tk.DISABLED)

    # ------------ Hide tab ------------
    def setup_hide_tab(self):
        title_label = ttk.Label(self.hide_frame, text="HIDE MESSAGE IN IMAGES", style='Title.TLabel')
        title_label.pack(pady=20)

        method_frame = ttk.Frame(self.hide_frame, style='Custom.TFrame')
        method_frame.pack(pady=10)

        ttk.Label(method_frame, text="Method:", style='Result.TLabel').pack(side=tk.LEFT, padx=5)
        self.method_var = tk.StringVar(value="LSB")
        method_combo = ttk.Combobox(method_frame, textvariable=self.method_var, values=["LSB", "Steghide"], state="readonly")
        method_combo.pack(side=tk.LEFT, padx=5)

        # Add data type selection
        data_type_frame = ttk.Frame(self.hide_frame, style='Custom.TFrame')
        data_type_frame.pack(pady=5, fill=tk.X)
        
        ttk.Label(data_type_frame, text="Data Type:", style='Result.TLabel').pack(side=tk.LEFT, padx=5)
        self.data_type_var = tk.StringVar(value="Text")
        data_type_combo = ttk.Combobox(data_type_frame, textvariable=self.data_type_var, 
                                      values=["Text", "File"], state="readonly", width=10)
        data_type_combo.pack(side=tk.LEFT, padx=5)
        data_type_combo.bind("<<ComboboxSelected>>", self.toggle_data_input)
        
        # Modify the data_frame to handle both text and file input
        self.data_frame = ttk.Frame(self.hide_frame, style='Custom.TFrame')
        self.data_frame.pack(pady=10, fill=tk.X)
        
        # Text input (default)
        self.text_input_frame = ttk.Frame(self.data_frame, style='Custom.TFrame')
        self.text_input_frame.pack(fill=tk.X)
        ttk.Label(self.text_input_frame, text="Message to hide:", style='Result.TLabel').pack(anchor=tk.W)
        self.data_text = scrolledtext.ScrolledText(self.text_input_frame, height=5, bg="#2c3e50", 
                                                  fg="#ecf0f1", font=('Courier', 10))
        self.data_text.pack(fill=tk.X, pady=5)
        
        # File input (hidden initially)
        self.file_input_frame = ttk.Frame(self.data_frame, style='Custom.TFrame')
        ttk.Label(self.file_input_frame, text="File to hide:", style='Result.TLabel').pack(anchor=tk.W)
        file_select_frame = ttk.Frame(self.file_input_frame, style='Custom.TFrame')
        file_select_frame.pack(fill=tk.X, pady=5)
        self.file_select_btn = ttk.Button(file_select_frame, text="Select File", 
                                         command=self.select_file_to_hide, style='Custom.TButton')
        self.file_select_btn.pack(side=tk.LEFT, padx=5)
        self.selected_file_label = ttk.Label(file_select_frame, text="No file selected", style='Result.TLabel')
        self.selected_file_label.pack(side=tk.LEFT, padx=5)

        enc_frame = ttk.Frame(self.hide_frame, style='Custom.TFrame')
        enc_frame.pack(pady=5, fill=tk.X)
        self.encrypt_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(enc_frame, text="Encrypt (AES-256)", variable=self.encrypt_var).pack(side=tk.LEFT)
        ttk.Label(enc_frame, text="Password:", style='Result.TLabel').pack(side=tk.LEFT, padx=(10,0))
        self.enc_pass_var = tk.StringVar()
        ttk.Entry(enc_frame, textvariable=self.enc_pass_var, show="*").pack(side=tk.LEFT, padx=5)

        image_frame = ttk.Frame(self.hide_frame, style='Custom.TFrame')
        image_frame.pack(pady=10)
        self.hide_image_btn = ttk.Button(image_frame, text="Select Cover Image", command=self.select_hide_image, style='Custom.TButton')
        self.hide_image_btn.pack(side=tk.LEFT, padx=5)
        self.hide_image_label = ttk.Label(image_frame, text="No image selected", style='Result.TLabel')
        self.hide_image_label.pack(side=tk.LEFT, padx=5)

        pass_frame = ttk.Frame(self.hide_frame, style='Custom.TFrame')
        pass_frame.pack(pady=10, fill=tk.X)
        ttk.Label(pass_frame, text="Password (for Steghide):", style='Result.TLabel').pack(side=tk.LEFT)
        self.pass_var = tk.StringVar()
        ttk.Entry(pass_frame, textvariable=self.pass_var, show="*").pack(side=tk.LEFT, padx=5)

        output_frame = ttk.Frame(self.hide_frame, style='Custom.TFrame')
        output_frame.pack(pady=10, fill=tk.X)
        ttk.Label(output_frame, text="Output filename:", style='Result.TLabel').pack(side=tk.LEFT)
        self.output_var = tk.StringVar(value="hidden_image.png")
        ttk.Entry(output_frame, textvariable=self.output_var).pack(side=tk.LEFT, padx=5)

        self.hide_btn = ttk.Button(self.hide_frame, text="Hide Message", command=self.hide_data, style='Hide.TButton')
        self.hide_btn.pack(pady=10)

    # ------------ Extract tab ------------
    def setup_extract_tab(self):
        title_label = ttk.Label(self.extract_frame, text="EXTRACT HIDDEN MESSAGE", style='Title.TLabel')
        title_label.pack(pady=20)

        image_frame = ttk.Frame(self.extract_frame, style='Custom.TFrame')
        image_frame.pack(pady=10)
        self.extract_image_btn = ttk.Button(image_frame, text="Select Image", command=self.select_extract_image, style='Custom.TButton')
        self.extract_image_btn.pack(side=tk.LEFT, padx=5)
        self.extract_image_label = ttk.Label(image_frame, text="No image selected", style='Result.TLabel')
        self.extract_image_label.pack(side=tk.LEFT, padx=5)

        method_frame = ttk.Frame(self.extract_frame, style='Custom.TFrame')
        method_frame.pack(pady=10)
        ttk.Label(method_frame, text="Extraction Method:", style='Result.TLabel').pack(side=tk.LEFT, padx=5)
        self.extract_method_var = tk.StringVar(value="Auto-Detect")
        method_combo = ttk.Combobox(method_frame, textvariable=self.extract_method_var,
                                    values=["Auto-Detect", "LSB", "Steghide", "Binwalk", "Strings"], state="readonly")
        method_combo.pack(side=tk.LEFT, padx=5)

        pass_frame = ttk.Frame(self.extract_frame, style='Custom.TFrame')
        pass_frame.pack(pady=10, fill=tk.X)
        ttk.Label(pass_frame, text="Password (if known):", style='Result.TLabel').pack(side=tk.LEFT)
        self.extract_pass_var = tk.StringVar()
        ttk.Entry(pass_frame, textvariable=self.extract_pass_var).pack(side=tk.LEFT, padx=5)

        # Wordlist & brute force controls
        self.brute_force_var = tk.BooleanVar()
        ttk.Checkbutton(pass_frame, text="Brute Force (wordlist)", variable=self.brute_force_var).pack(side=tk.LEFT, padx=10)
        self.wordlist_btn = ttk.Button(pass_frame, text="Load Wordlist", command=self.load_wordlist, style='Custom.TButton')
        self.wordlist_btn.pack(side=tk.LEFT, padx=5)

        self.extract_btn = ttk.Button(self.extract_frame, text="Extract Message", command=self.extract_data, style='Extract.TButton')
        self.extract_btn.pack(pady=10)

        extract_results_frame = ttk.Frame(self.extract_frame, style='Custom.TFrame')
        extract_results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        ttk.Label(extract_results_frame, text="Extracted Message:", style='Title.TLabel').pack(anchor=tk.W, pady=(0, 10))

        self.extract_results_text = scrolledtext.ScrolledText(extract_results_frame, height=12, width=80, bg="#2c3e50", fg="#ecf0f1", font=('Courier', 10))
        self.extract_results_text.pack(fill=tk.BOTH, expand=True)
        self.extract_results_text.insert(tk.END, "No extraction performed yet.")
        self.extract_results_text.config(state=tk.DISABLED)

        # progress
        self.progress = ttk.Progressbar(self.extract_frame, mode='determinate', length=400)
        self.progress.pack(pady=5)

    # ---------- common UI helpers ----------
    def select_image(self):
        file_path = filedialog.askopenfilename(
            title="Select an image file",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff *.gif")]
        )
        if file_path:
            self.current_image = file_path
            self.display_image(file_path)
            self.detect_btn.state(['!disabled'])
            self.extract_meta_btn.state(['!disabled'])
            self.results_text.config(state=tk.NORMAL)
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Selected: {os.path.basename(file_path)}\nReady for analysis.")
            self.results_text.config(state=tk.DISABLED)

    def select_hide_image(self):
        file_path = filedialog.askopenfilename(
            title="Select a cover image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff *.gif")]
        )
        if file_path:
            self.hide_image_path = file_path
            self.hide_image_label.config(text=os.path.basename(file_path))

    def select_extract_image(self):
        file_path = filedialog.askopenfilename(
            title="Select an image with hidden data",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff *.gif")]
        )
        if file_path:
            self.extract_image_path = file_path
            self.extract_image_label.config(text=os.path.basename(file_path))

    def load_wordlist(self):
        path = filedialog.askopenfilename(title="Select wordlist (one password per line)")
        if path:
            self.wordlist_path = path
            messagebox.showinfo("Wordlist", f"Loaded: {os.path.basename(path)}")

    def display_image(self, file_path):
        try:
            image = Image.open(file_path)
            image.thumbnail((300, 300))
            photo = ImageTk.PhotoImage(image)
            self.image_label.configure(image=photo, text="")
            self.image_label.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Could not open image: {str(e)}")

    def extract_metadata(self):
        if not self.current_image:
            messagebox.showwarning("Warning", "Please select an image first.")
            return
        try:
            result = subprocess.run(['exiftool', self.current_image], capture_output=True, text=True, timeout=15)
            self.results_text.config(state=tk.NORMAL)
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "METADATA EXTRACTION RESULTS\n")
            self.results_text.insert(tk.END, "----------------------------------------\n\n")
            self.results_text.insert(tk.END, result.stdout)
            self.results_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Metadata extraction failed: {str(e)}")

    # ---------- New methods for file handling ----------
    def toggle_data_input(self, event=None):
        if self.data_type_var.get() == "Text":
            self.file_input_frame.pack_forget()
            self.text_input_frame.pack(fill=tk.X)
        else:
            self.text_input_frame.pack_forget()
            self.file_input_frame.pack(fill=tk.X)

    def select_file_to_hide(self):
        file_path = filedialog.askopenfilename(title="Select a file to hide")
        if file_path:
            self.file_to_hide_path = file_path
            self.selected_file_label.config(text=os.path.basename(file_path))

    # ---------- hide ----------
    def hide_data(self):
        if not self.hide_image_path:
            messagebox.showwarning("Warning", "Please select a cover image first.")
            return
        
        method = self.method_var.get()
        
        # Handle data based on type
        if self.data_type_var.get() == "Text":
            data = self.data_text.get(1.0, tk.END).strip()
            if not data:
                messagebox.showwarning("Warning", "Please enter data to hide.")
                return
            
            # For text, we can encrypt if requested
            if self.encrypt_var.get():
                pwd = self.enc_pass_var.get()
                if not pwd:
                    messagebox.showwarning("Warning", "Provide an encryption password.")
                    return
                try:
                    data = aes_encrypt(data, pwd)
                except Exception as e:
                    messagebox.showerror("Error", f"Encryption failed: {e}")
                    return
            
            # For text, we'll handle it as before
            data_to_hide = data
            is_binary = False
        else:
            # For files
            if not self.file_to_hide_path:
                messagebox.showwarning("Warning", "Please select a file to hide.")
                return
            
            # Read file as binary
            try:
                with open(self.file_to_hide_path, 'rb') as f:
                    data_to_hide = f.read()
                is_binary = True
                
                # Note: Encryption for binary files would need a different approach
                # For now, we'll disable encryption for files
                if self.encrypt_var.get():
                    messagebox.showwarning("Warning", "Encryption is not supported for files. Hiding without encryption.")
                    self.encrypt_var.set(False)
                    
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file: {str(e)}")
                return

        output_path = os.path.join(os.path.dirname(self.hide_image_path), self.output_var.get())
        steghide_password = self.pass_var.get()

        try:
            if method == "LSB":
                if is_binary:
                    # For binary data with LSB, we need to convert to a format that can be embedded
                    # One approach is to encode the binary data as base64
                    encoded_data = base64.b64encode(data_to_hide).decode('ascii')
                    # Add a header to identify it as a file
                    file_header = f"FILE:{os.path.basename(self.file_to_hide_path)}:"
                    full_data = file_header + encoded_data
                    secret = lsb.hide(self.hide_image_path, full_data)
                else:
                    secret = lsb.hide(self.hide_image_path, data_to_hide)
                secret.save(output_path)
                messagebox.showinfo("Success", f"Data hidden successfully using LSB!\nSaved as: {output_path}")
                
            elif method == "Steghide":
                tmpdir = make_tempdir()
                
                if is_binary:
                    # For binary data, just use the file directly
                    tmpfile = os.path.join(tmpdir, os.path.basename(self.file_to_hide_path))
                    shutil.copy2(self.file_to_hide_path, tmpfile)
                else:
                    # For text, create a text file
                    tmpfile = os.path.join(tmpdir, "hidden_data.txt")
                    with open(tmpfile, "w", encoding="utf-8") as f:
                        f.write(data_to_hide)
                
                cmd = ['steghide', 'embed', '-cf', self.hide_image_path, '-ef', tmpfile, '-sf', output_path]
                if steghide_password:
                    cmd += ['-p', steghide_password]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    messagebox.showinfo("Success", f"Data hidden successfully using Steghide!\nSaved as: {output_path}")
                else:
                    messagebox.showerror("Error", f"Steghide failed: {result.stderr}")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide data: {str(e)}")

    # ---------- extract ----------
    def extract_data(self):
        if not self.extract_image_path:
            messagebox.showwarning("Warning", "Please select an image first.")
            return
        method = self.extract_method_var.get()
        password = self.extract_pass_var.get()
        brute_force = self.brute_force_var.get()

        self.extract_results_text.config(state=tk.NORMAL)
        self.extract_results_text.delete(1.0, tk.END)
        self.extract_results_text.insert(tk.END, "Extracting data... Please wait.\n")
        self.extract_results_text.config(state=tk.DISABLED)

        thread = threading.Thread(target=self.run_extraction, args=(method, password, brute_force))
        thread.daemon = True
        thread.start()

    def run_extraction(self, method, password, brute_force):
        try:
            result_chunks = []

            if method in ("Auto-Detect", "LSB"):
                try:
                    hidden_data = lsb.reveal(self.extract_image_path)
                    if hidden_data:
                        # Check if it's a file with our custom header
                        if hidden_data.startswith(FILE_HEADER):
                            parts = hidden_data.split(":", 2)
                            if len(parts) >= 3:
                                filename = parts[1]
                                file_data = base64.b64decode(parts[2])
                                
                                # Save the extracted file
                                save_path = filedialog.asksaveasfilename(
                                    title="Save extracted file",
                                    initialfile=filename,
                                    defaultextension=os.path.splitext(filename)[1] if '.' in filename else ""
                                )
                                if save_path:
                                    with open(save_path, 'wb') as f_out:
                                        f_out.write(file_data)
                                    result_chunks.append(f"LSB (File): Extracted file '{filename}' saved to {save_path}")
                                else:
                                    result_chunks.append(f"LSB (File): Extracted file '{filename}' (user cancelled save)")
                        else:
                            # Try AES auto-decode if applicable
                            try:
                                maybe = base64.b64decode(hidden_data.encode("ascii"), validate=True)
                                if maybe.startswith(b"STEGOTOOL_AES_v1|") and password:
                                    dec = aes_decrypt(hidden_data, password)
                                    result_chunks.append("LSB (AES):\n" + dec)
                                else:
                                    result_chunks.append("LSB:\n" + hidden_data)
                            except Exception:
                                result_chunks.append("LSB:\n" + hidden_data)
                except Exception:
                    pass

            if method in ("Auto-Detect", "Steghide"):
                stego = self.extract_steghide(password, brute_force)
                if stego:
                    result_chunks.append("STEGHIDE:\n" + stego)

            if method in ("Auto-Detect", "Binwalk"):
                b = self.extract_binwalk()
                if b:
                    result_chunks.append("BINWALK:\n" + b)

            if method in ("Auto-Detect", "Strings"):
                s = self.extract_strings()
                if s:
                    result_chunks.append("STRINGS:\n" + s)

            final = "\n\n".join(result_chunks) if result_chunks else "No hidden data could be extracted using the selected methods."
            self.root.after(0, self.display_extraction_results, final)
        except Exception as e:
            self.root.after(0, self.show_extraction_error, str(e))

    def extract_steghide(self, password, brute_force):
        try:
            tmpdir = make_tempdir()
            out_file = os.path.join(tmpdir, "extracted_data")

            # Quick info probe increases detection (works even when password unknown)
            info = subprocess.run(['steghide', 'info', self.extract_image_path, '-p', password or ''],
                                  capture_output=True, text=True, timeout=15)
            info_text = (info.stdout or "") + (info.stderr or "")
            probable = ("embedded file" in info_text.lower()) or ("encryption" in info_text.lower())

            # First, try given password (including empty)
            tried_any = False
            for pwd in ([password] if password is not None else [""]):
                if pwd is None:  # should not happen
                    continue
                tried_any = True
                r = subprocess.run(['steghide', 'extract', '-sf', self.extract_image_path, '-p', pwd, '-xf', out_file],
                                   capture_output=True, text=True, timeout=20)
                if r.returncode == 0 and os.path.isfile(out_file):
                    with open(out_file, 'rb') as f:
                        data = f.read()
                    
                    # Check if this is a file with our custom header
                    try:
                        text = data.decode('utf-8', errors='ignore')
                        if text.startswith(FILE_HEADER):
                            parts = text.split(":", 2)
                            if len(parts) >= 3:
                                filename = parts[1]
                                file_data = base64.b64decode(parts[2])
                                
                                # Save the extracted file
                                save_path = filedialog.asksaveasfilename(
                                    title="Save extracted file",
                                    initialfile=filename,
                                    defaultextension=os.path.splitext(filename)[1] if '.' in filename else ""
                                )
                                if save_path:
                                    with open(save_path, 'wb') as f_out:
                                        f_out.write(file_data)
                                    return f"Password: '{pwd}'\nExtracted file: {filename} (saved to {save_path})"
                                return f"Password: '{pwd}'\nExtracted file: {filename} (user cancelled save)"
                    except UnicodeDecodeError:
                        pass
                    
                    # Not our custom file format, try to identify what it is
                    file_info = self.identify_file_type(data, out_file)
                    
                    # Ask user if they want to save the file
                    default_name = f"extracted_{int(time.time())}{file_info['extension']}"
                    save_path = filedialog.asksaveasfilename(
                        title="Save extracted file",
                        initialfile=default_name,
                        defaultextension=file_info['extension']
                    )
                    if save_path:
                        with open(save_path, 'wb') as f_out:
                            f_out.write(data)
                        return f"Password: '{pwd}'\nExtracted {file_info['type']} file (saved to {save_path})"
                    return f"Password: '{pwd}'\nExtracted {file_info['type']} file (user cancelled save)"

            # Brute force with wordlist
            if brute_force and self.wordlist_path and os.path.isfile(self.wordlist_path):
                passwords = []
                with open(self.wordlist_path, 'r', errors='ignore') as wl:
                    passwords = [line.strip() for line in wl if line.strip()]
                total = len(passwords)
                self.root.after(0, lambda: self.progress.configure(maximum=total, value=0))
                found = None
                for idx, pwd in enumerate(passwords, 1):
                    r = subprocess.run(['steghide', 'extract', '-sf', self.extract_image_path, '-p', pwd, '-xf', out_file],
                                       capture_output=True, text=True, timeout=10)
                    self.root.after(0, lambda v=idx: self.progress.configure(value=v))
                    if r.returncode == 0 and os.path.isfile(out_file):
                        with open(out_file, 'rb') as f:
                            data = f.read()
                        
                        # Check if this is a file with our custom header
                        try:
                            text = data.decode('utf-8', errors='ignore')
                            if text.startswith(FILE_HEADER):
                                parts = text.split(":", 2)
                                if len(parts) >= 3:
                                    filename = parts[1]
                                    file_data = base64.b64decode(parts[2])
                                    
                                    # Save the extracted file
                                    save_path = filedialog.asksaveasfilename(
                                        title="Save extracted file",
                                        initialfile=filename,
                                        defaultextension=os.path.splitext(filename)[1] if '.' in filename else ""
                                    )
                                    if save_path:
                                        with open(save_path, 'wb') as f_out:
                                            f_out.write(file_data)
                                        found = f"Password: '{pwd}'\nExtracted file: {filename} (saved to {save_path})"
                                    else:
                                        found = f"Password: '{pwd}'\nExtracted file: {filename} (user cancelled save)"
                                    break
                        except UnicodeDecodeError:
                            pass
                        
                        # Not our custom file format, try to decode as text
                        try:
                            text = data.decode('utf-8', errors='ignore')
                            found = f"Password: '{pwd}'\nData:\n{text}"
                            break
                        except Exception:
                            found = f"Password: '{pwd}'\n<binary data>"
                            break
                self.root.after(0, lambda: self.progress.configure(value=0))
                if found:
                    return found
                elif probable:
                    return "Steghide likely present, but wordlist brute-force did not recover the password."

            # Fallback quick check if probable steghide but no success
            if probable and not tried_any:
                return "Steghide likely present (info suggests embedding), but password required."

            return ""
        except subprocess.TimeoutExpired:
            return "Steghide extraction timed out."
        except Exception as e:
            return f"Steghide extraction error: {str(e)}"

    def identify_file_type(self, data, file_path):
        """Identify the type of file based on its signature"""
        if len(data) < 20:
            return {"type": "Unknown", "extension": ".bin"}
        
        # Check common file signatures
        signatures = [
            (b'PK\x03\x04', "ZIP Archive", ".zip"),
            (b'%PDF', "PDF Document", ".pdf"),
            (b'\x7FELF', "ELF Executable", ""),
            (b'MZ', "Windows Executable", ".exe"),
            (b'\x89PNG', "PNG Image", ".png"),
            (b'\xFF\xD8\xFF', "JPEG Image", ".jpg"),
            (b'Rar!', "RAR Archive", ".rar"),
            (b'\x1F\x8B\x08', "GZIP Archive", ".gz"),
            (b'ID3', "MP3 Audio", ".mp3"),
            (b'\x00\x00\x01\xBA', "MPEG Video", ".mpg"),
        ]
        
        for sig, file_type, extension in signatures:
            if data.startswith(sig):
                return {"type": file_type, "extension": extension}
        
        # Try using the file command
        try:
            result = subprocess.run(['file', '-b', file_path], 
                                   capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return {"type": result.stdout.strip(), "extension": ".bin"}
        except Exception:
            pass
        
        return {"type": "Unknown Binary", "extension": ".bin"}

    def extract_binwalk(self):
        try:
            outdir = os.path.join(make_tempdir(), "binwalk_extract")
            os.makedirs(outdir, exist_ok=True)
            result = subprocess.run(['binwalk', '--extract', '--directory', outdir, self.extract_image_path],
                                    capture_output=True, text=True, timeout=60)  # Increased timeout

            extracted_files = []
            for root, _, files in os.walk(outdir):
                for file in files:
                    if not file.startswith('.'):
                        full_path = os.path.join(root, file)
                        extracted_files.append(full_path)

            if extracted_files:
                result_text = f"Extracted {len(extracted_files)} files:\n"
                for fp in extracted_files[:8]:  # Show fewer files but with more info
                    try:
                        # Get file info
                        file_info = self.identify_file_type(b"", fp)
                        
                        with open(fp, 'rb') as f:
                            content = f.read(300)
                        
                        # Try to decode as text, or show hex for binary
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                            preview = text_content if text_content.strip() else "<binary data>"
                        except UnicodeDecodeError:
                            preview = "<binary data>"
                        
                        result_text += f"\nFile: {os.path.basename(fp)} ({file_info['type']})\nPreview: {preview}\n"
                    except Exception as e:
                        result_text += f"\nFile: {os.path.basename(fp)} (error reading: {str(e)})\n"
                
                if len(extracted_files) > 8:
                    result_text += f"\n...and {len(extracted_files)-8} more files."
                return result_text
            else:
                return "No embedded files found by binwalk."
        except subprocess.TimeoutExpired:
            return "Binwalk timed out."
        except Exception as e:
            return f"Binwalk error: {str(e)}"

    def extract_strings(self):
        try:
            result = subprocess.run(['strings', self.extract_image_path],
                                    capture_output=True, text=True, timeout=20)
            strings = result.stdout.splitlines()
            keywords = ['password', 'secret', 'key', 'hidden', 'encrypt', 'passphrase', 'flag', 'user', 'admin']
            interesting = [s for s in strings if len(s) > 5 and any(k in s.lower() for k in keywords)]
            if interesting:
                return "Interesting strings:\n" + "\n".join(interesting[:50])
            else:
                return "No interesting strings found."
        except Exception as e:
            return f"Strings error: {str(e)}"

    # ---------- analysis ----------
    def detect_steganography(self):
        if not self.current_image:
            messagebox.showwarning("Warning", "Please select an image first.")
            return
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Analyzing image... Please wait.\n")
        self.results_text.see(tk.END)
        self.results_text.update()
        thread = threading.Thread(target=self.run_detection)
        thread.daemon = True
        thread.start()

    def run_detection(self):
        try:
            results = self.analyze_image(self.current_image)
            self.root.after(0, self.display_results, results)
        except Exception as e:
            self.root.after(0, self.show_error, str(e))

    def analyze_image(self, image_path):
        results = {}
        results['LSB'] = self.detect_lsb(image_path)
        results['Steghide'] = self.detect_steghide(image_path)
        results['Metadata'] = self.analyze_metadata(image_path)
        results['File Structure'] = self.analyze_file_structure(image_path)
        results['Binwalk'] = self.run_binwalk_quick(image_path)
        results['Strings'] = self.analyze_strings(image_path)
        results['File Detection'] = self.detect_hidden_files(image_path)  # New analysis
        return results

    def detect_hidden_files(self, image_path):
        try:
            # Check for our custom file header in LSB
            try:
                hidden_data = lsb.reveal(image_path)
                if hidden_data and hidden_data.startswith(FILE_HEADER):
                    parts = hidden_data.split(":", 2)
                    if len(parts) >= 3:
                        filename = parts[1]
                        return f"80% (Hidden file detected: {filename})"
            except Exception:
                pass
            
            # Check with binwalk for embedded files
            outdir = os.path.join(make_tempdir(), "file_detection")
            os.makedirs(outdir, exist_ok=True)
            result = subprocess.run(['binwalk', '--extract', '--directory', outdir, image_path],
                                   capture_output=True, text=True, timeout=30)
            
            extracted_files = []
            for root, _, files in os.walk(outdir):
                for file in files:
                    if not file.startswith('.'):
                        extracted_files.append(os.path.join(root, file))
            
            if extracted_files:
                file_types = []
                for fp in extracted_files:
                    # Try to identify file type
                    try:
                        with open(fp, 'rb') as f:
                            header = f.read(20)
                        
                        # Simple file type detection
                        if header.startswith(b'PK') or header.startswith(b'\x50\x4B\x03\x04'):
                            file_types.append("ZIP")
                        elif header.startswith(b'%PDF'):
                            file_types.append("PDF")
                        elif header.startswith(b'\x7FELF'):
                            file_types.append("ELF")
                        elif header.startswith(b'MZ'):
                            file_types.append("EXE")
                        elif header.startswith(b'\x89PNG'):
                            file_types.append("PNG")
                        elif header.startswith(b'\xFF\xD8\xFF'):
                            file_types.append("JPEG")
                        else:
                            file_types.append("Unknown")
                    except Exception:
                        file_types.append("Unknown")
                
                unique_types = set(file_types)
                return f"75% ({len(extracted_files)} files detected: {', '.join(unique_types)})"
            
            # Check for common file signatures in the image data
            with open(image_path, 'rb') as f:
                data = f.read()
            
            # Look for common file signatures
            signatures = {
                b'PK\x03\x04': 'ZIP',
                b'%PDF': 'PDF',
                b'\x7FELF': 'ELF',
                b'MZ': 'EXE',
                b'\x89PNG': 'PNG',
                b'\xFF\xD8\xFF': 'JPEG',
                b'Rar!': 'RAR',
                b'\x1F\x8B\x08': 'GZIP',
            }
            
            found_files = []
            for sig, file_type in signatures.items():
                if sig in data:
                    found_files.append(file_type)
            
            if found_files:
                return f"60% (File signatures detected: {', '.join(set(found_files))})"
            
            return "0% (No hidden files detected)"
            
        except Exception as e:
            return f"0% (File detection error: {str(e)})"

    def detect_lsb(self, image_path):
        try:
            hidden_data = lsb.reveal(image_path)
            if hidden_data:
                # Check if it's a file header
                if hidden_data.startswith(FILE_HEADER):
                    parts = hidden_data.split(":", 2)
                    if len(parts) >= 3:
                        filename = parts[1]
                        return f"90% (Hidden file found: {filename})"
                
                # Regular text data
                confidence = min(80 + len(hidden_data) // 2, 95)
                return f"{confidence}% (Hidden data found: {hidden_data[:50]}...)"
            return "0% (No LSB data detected)"
        except Exception:
            return "0% (No LSB data detected)"

    def detect_steghide(self, image_path):
        try:
            # Multi-probe approach: info with blank + common passwords
            passwords = ['', 'password', 'secret', '123456', 'pass123', 'admin', 'root', 'hidden']
            probable = False
            for pwd in passwords:
                info = subprocess.run(['steghide', 'info', image_path, '-p', pwd],
                                      capture_output=True, text=True, timeout=10)
                out = (info.stdout or "") + (info.stderr or "")
                if ("embedded file" in out.lower()) or ("encryption" in out.lower()):
                    probable = True
                    # try a fast extract to temp to confirm
                    tmp_out = os.path.join(make_tempdir(), f"probe_{int(time.time())}")
                    ex = subprocess.run(['steghide', 'extract', '-sf', image_path, '-p', pwd, '-xf', tmp_out],
                                        capture_output=True, text=True, timeout=10)
                    if ex.returncode == 0 and os.path.isfile(tmp_out):
                        return "90% (Steghide embedding confirmed via quick extract)"
            if probable:
                return "70% (Steghide indicators present; password likely required)"
            # Heuristic byte scan: steghide sometimes leaves entropy/appended segments
            try:
                size = os.path.getsize(image_path)
                with open(image_path, 'rb') as f:
                    data = f.read()
                high_entropy_tail = len(data) > 2048 and (sum(b > 127 for b in data[-2048:]) / 2048.0) > 0.75
                if high_entropy_tail:
                    return "40% (High-entropy tail suggests appended container; could be steghide)"
            except Exception:
                pass
            return "0% (No steghide signals detected)"
        except subprocess.TimeoutExpired:
            return "0% (Steghide probe timed out)"
        except Exception as e:
            return f"0% (Error: {str(e)})"

    def analyze_metadata(self, image_path):
        try:
            result = subprocess.run(['exiftool', image_path], capture_output=True, text=True, timeout=15)
            metadata = result.stdout
            suspicious_keywords = ['comment', 'software', 'warning', 'copyright', 'description']
            suspicious_count = sum(1 for k in suspicious_keywords if k in metadata.lower())
            confidence = min(suspicious_count * 20, 80)
            return f"{confidence}% ({suspicious_count} suspicious metadata fields)" if confidence > 0 else "0% (No suspicious metadata)"
        except Exception:
            return "0% (Metadata analysis failed)"

    def analyze_file_structure(self, image_path):
        try:
            with open(image_path, 'rb') as f:
                content = f.read()
            ext = os.path.splitext(image_path)[1].lower()
            n = len(content)

            def has_appended(after_idx):
                return after_idx < n and content[after_idx:after_idx+4] in [b'PK\x03\x04', b'%PDF', b'\x7FELF', b'MZ']

            # Check for appended files
            for i in range(n-4):
                if has_appended(i):
                    return "60% (Appended file detected)"
            
            return "0% (No appended files detected)"
        except Exception as e:
            return f"0% (File structure analysis error: {str(e)})"

    def run_binwalk_quick(self, image_path):
        try:
            result = subprocess.run(['binwalk', image_path], capture_output=True, text=True, timeout=30)
            lines = result.stdout.splitlines()
            if len(lines) > 1:  # More than just the header
                return "70% (Binwalk found embedded data)"
            return "0% (No embedded data found by binwalk)"
        except subprocess.TimeoutExpired:
            return "0% (Binwalk timed out)"
        except Exception as e:
            return f"0% (Binwalk error: {str(e)})"

    def analyze_strings(self, image_path):
        try:
            result = subprocess.run(['strings', image_path], capture_output=True, text=True, timeout=20)
            strings = result.stdout.splitlines()
            suspicious = [s for s in strings if len(s) > 5 and any(k in s.lower() for k in ['password', 'secret', 'key', 'hidden'])]
            if suspicious:
                return f"50% ({len(suspicious)} suspicious strings found)"
            return "0% (No suspicious strings found)"
        except Exception:
            return "0% (Strings analysis failed)"

    def display_results(self, results):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "STEGANOGRAPHY ANALYSIS RESULTS\n")
        self.results_text.insert(tk.END, "========================================\n\n")
        
        for method, result in results.items():
            self.results_text.insert(tk.END, f"{method}:\n")
            self.results_text.insert(tk.END, f"  {result}\n\n")
            
        self.results_text.config(state=tk.DISABLED)

    def display_extraction_results(self, results):
        self.extract_results_text.config(state=tk.NORMAL)
        self.extract_results_text.delete(1.0, tk.END)
        self.extract_results_text.insert(tk.END, results)
        self.extract_results_text.config(state=tk.DISABLED)

    def show_error(self, error_msg):
        messagebox.showerror("Error", f"Analysis failed: {error_msg}")

    def show_extraction_error(self, error_msg):
        messagebox.showerror("Error", f"Extraction failed: {error_msg}")

if __name__ == "__main__":
    root = tk.Tk()
    app = StegoTool(root)
    root.mainloop()
    
    
    
    
