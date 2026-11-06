import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import secrets
import math
import os
def is_prime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True

def generate_prime():
    while True:
        number = secrets.randbelow(200) + 300
        if is_prime(number):
            return number

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def modular_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m

def generate_rsa_keys():
    while True:
        p = generate_prime()
        q = generate_prime()
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 17

        if math.gcd(e, phi) == 1:
            d = modular_inverse(e, phi)
            if d is not None:
                return (e, n), (d, n)

def sha256_hash(data):
    return hashlib.sha256(data).hexdigest()

public_key, private_key = generate_rsa_keys()

certificate_data = None
original_hash = ""
signature = None
file_name = ""

def set_status(kind, title, message):
    status_title.config(text=title)
    status_message.config(text=message)

    if kind == "success":
        status_box.config(bg="#DDF8E8")
        status_title.config(bg="#DDF8E8", fg="#087F5B")
        status_message.config(bg="#DDF8E8", fg="#087F5B")
        status_icon.config(bg="#DDF8E8", fg="#087F5B", text="✓")
    elif kind == "error":
        status_box.config(bg="#FFE4E8")
        status_title.config(bg="#FFE4E8", fg="#C92A4B")
        status_message.config(bg="#FFE4E8", fg="#C92A4B")
        status_icon.config(bg="#FFE4E8", fg="#C92A4B", text="✕")
    elif kind == "warning":
        status_box.config(bg="#FFF0D5")
        status_title.config(bg="#FFF0D5", fg="#9A6100")
        status_message.config(bg="#FFF0D5", fg="#9A6100")
        status_icon.config(bg="#FFF0D5", fg="#9A6100", text="!")
    else:
        status_box.config(bg="#E9EAFE")
        status_title.config(bg="#E9EAFE", fg="#4C4BA5")
        status_message.config(bg="#E9EAFE", fg="#4C4BA5")
        status_icon.config(bg="#E9EAFE", fg="#4C4BA5", text="i")


def upload_certificate():
    global certificate_data, original_hash, signature, file_name

    path = filedialog.askopenfilename(
        title="Select Certificate",
        filetypes=[
            ("Certificate files", "*.pdf *.doc *.docx *.txt *.jpg *.jpeg *.png"),
            ("All files", "*.*")
        ]
    )

    if not path:
        return

    try:
        with open(path, "rb") as file:
            data = file.read()

        if not data:
            messagebox.showwarning("Empty File", "Please select a non-empty file.")
            return

        certificate_data = data
        file_name = os.path.basename(path)
        original_hash = sha256_hash(certificate_data)

        # RSA demonstration: sign the hash reduced to the RSA modulus.
        hash_number = int(original_hash, 16) % public_key[1]
        signature = pow(hash_number, private_key[0], private_key[1])

        selected_file_label.config(text="📄  " + file_name)
        file_size_label.config(text=f"{len(certificate_data):,} bytes")
        hash_text.config(text=original_hash, fg="#4338CA")
        signature_text.config(text=str(signature), fg="#7C3AED")
        public_key_text.config(
            text=f"e = {public_key[0]}\nn = {public_key[1]}",
            fg="#0F766E"
        )
        received_hash_text.config(text="Will appear after verification", fg="#8B90A5")
        result_title.config(text="Waiting for verification", fg="#4C4BA5")
        result_message.config(text="Click Verify Certificate to check the file.")
        verify_button.config(state=tk.NORMAL)
        tamper_button.config(state=tk.NORMAL)
        set_status("info", "Certificate uploaded", "SHA-256 hash and RSA signature are ready.")

    except Exception as error:
        messagebox.showerror("Upload Error", str(error))


def verify_certificate():
    if certificate_data is None:
        messagebox.showwarning("Upload Required", "Please upload a certificate first.")
        return

    try:
        received_hash = sha256_hash(certificate_data)
        hash_number = int(received_hash, 16) % public_key[1]
        recovered_number = pow(signature, public_key[0], public_key[1])

        received_hash_text.config(text=received_hash, fg="#4338CA")

        if received_hash == original_hash and hash_number == recovered_number:
            result_title.config(text="✓ CERTIFICATE VALID", fg="#087F5B")
            result_message.config(
                text="The hash matches. The digital signature is valid."
            )
            set_status("success", "Verification successful",
                       "No changes were detected in the uploaded file.")
        else:
            result_title.config(text="✕ CERTIFICATE INVALID", fg="#C92A4B")
            result_message.config(
                text="The file was changed or the signature does not match."
            )
            set_status("error", "Verification failed",
                       "The file content or its signature did not match.")

    except Exception as error:
        messagebox.showerror("Verification Error", str(error))


def test_tampering():
    global certificate_data, file_name
    if certificate_data is None:
        messagebox.showwarning("Upload Required", "Please upload a certificate first.")
        return
       
    messagebox.showinfo("Tampering Test", "Please select a modified or different file to test verification failure.")
   
    path = filedialog.askopenfilename(
        title="Select Modified/Tampered Certificate",
        filetypes=[
            ("Certificate files", "*.pdf *.doc *.docx *.txt *.jpg *.jpeg *.png"),
            ("All files", "*.*")
        ]
    )
    if not path:
        return

    try:
        with open(path, "rb") as file:
            data = file.read()
        if not data:
            messagebox.showwarning("Empty File", "Please select a non-empty file.")
            return
           
        certificate_data = data
        file_name = os.path.basename(path)
       
        selected_file_label.config(text="📄 " + file_name + " (Modified Test)")
        file_size_label.config(text=f"{len(certificate_data):,} bytes")
       
        set_status("warning", "Modified file loaded", "A different file is loaded. Click Verify Certificate to check it.")
        received_hash_text.config(text="Click Verify Certificate again", fg="#9A6100")
        result_title.config(text="Ready to test modified file", fg="#9A6100")
        result_message.config(text="Verify the certificate to see the result.")
       
    except Exception as error:
        messagebox.showerror("Tampering Test Error", str(error))
def reset_application():
    global certificate_data, original_hash, signature, file_name
    certificate_data = None
    original_hash = ""
    signature = None
    file_name = ""
    selected_file_label.config(text="No certificate selected")
    file_size_label.config(text="")
    hash_text.config(text="Hash will appear here", fg="#9298AE")
    signature_text.config(text="Signature will appear here", fg="#9298AE")
    public_key_text.config(text="Public key will appear here", fg="#9298AE")
    received_hash_text.config(text="Hash will appear after verification", fg="#9298AE")
    result_title.config(text="Waiting for verification", fg="#4C4BA5")
    result_message.config(text="Upload a certificate to begin.")
    verify_button.config(state=tk.DISABLED)
    tamper_button.config(state=tk.DISABLED)
    set_status("info", "Ready to verify",
               "Upload a certificate to calculate its hash and sign it.")
root = tk.Tk()
root.title("Digital Certificate Verification")
root.state("zoomed")
root.configure(bg="#11152F")
root.resizable(True, True)
header = tk.Frame(root, bg="#11152F")
header.pack(fill="x", pady=(22, 15))

tk.Label(
    header, text="🔐", font=("Arial", 28),
    bg="#11152F", fg="white"
).pack()
tk.Label(
    header, text="Digital Certificate Verification",
    font=("Arial", 23, "bold"), bg="#11152F", fg="white"
).pack(pady=(5, 6))
tk.Label(
    header, text="SHA-256 Hashing  •  RSA Digital Signature",
    font=("Arial", 11), bg="#11152F", fg="#C8CCF0"
).pack()
container = tk.Frame(root, bg="#11152F")
container.pack(fill="both", expand=True, padx=35, pady=(0, 24))
canvas = tk.Canvas(
    container,
    bg="white",
    highlightthickness=0
)
scrollbar = tk.Scrollbar(
    container,
    orient="vertical",
    command=canvas.yview
)
card = tk.Frame(
    canvas,
    bg="white",
    highlightthickness=1,
    highlightbackground="#E4E6F4"
)
card_window = canvas.create_window(
    (0, 0),
    window=card,
    anchor="nw"
)

canvas.configure(yscrollcommand=scrollbar.set)
def update_scroll_region(event=None):
    canvas.configure(scrollregion=canvas.bbox("all"))
def update_card_width(event):
    canvas.itemconfigure(card_window, width=event.width)
card.bind("<Configure>", update_scroll_region)
canvas.bind("<Configure>", update_card_width)
canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")
def mouse_scroll(event):
    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
canvas.bind_all("<MouseWheel>", mouse_scroll)
upload_area = tk.Frame(card, bg="#F5F3FF", highlightbackground="#B9B2FA",
                       highlightthickness=2)
upload_area.pack(fill="x", padx=22, pady=(22, 12))
tk.Label(
    upload_area, text="📁  Upload your certificate",
    font=("Arial", 13, "bold"), bg="#F5F3FF", fg="#4C3EC8"
).pack(pady=(13, 4))
tk.Label(
    upload_area, text="Choose a PDF, DOCX, TXT or image file",
    font=("Arial", 9), bg="#F5F3FF", fg="#737896"
).pack(pady=(0, 12))
upload_button = tk.Button(
    upload_area, text="Browse Files", command=upload_certificate,
    font=("Arial", 10, "bold"), bg="#6D5AE6", fg="white",
    activebackground="#5542CC", activeforeground="white",
    relief="flat", padx=18, pady=7, cursor="hand2"
)
upload_button.pack(pady=(0, 14))
selected_file_label = tk.Label(
    card, text="No certificate selected", font=("Arial", 10, "bold"),
    bg="white", fg="#343957", wraplength=730
)
selected_file_label.pack(pady=(3, 0))
file_size_label = tk.Label(card, text="", font=("Arial", 9), bg="white", fg="#858BA3")
file_size_label.pack(pady=(2, 8))
def section_title(number, title, color):
    frame = tk.Frame(card, bg="white")
    frame.pack(fill="x", padx=24, pady=(8, 5))
    tk.Label(
        frame, text=str(number), font=("Arial", 10, "bold"),
        bg=color, fg="white", width=3, pady=4
    ).pack(side="left", padx=(0, 9))
    tk.Label(
        frame, text=title, font=("Arial", 12, "bold"),
        bg="white", fg="#252B4A"
    ).pack(side="left")

def value_panel(parent, text, color="#9298AE", height=2):
    frame = tk.Frame(parent, bg="#F8F9FD", highlightthickness=1,
                     highlightbackground="#E6E8F2")
    frame.pack(fill="x", padx=24, pady=(0, 7))
    label = tk.Label(
        frame, text=text, font=("Consolas", 9), bg="#F8F9FD",
        fg=color, wraplength=730, justify="left", anchor="w"
    )
    label.pack(fill="x", padx=12, pady=9)
    return label
section_title(1, "SHA-256 Certificate Hash", "#6554D9")
hash_text = value_panel(card, "Hash will appear here")
section_title(2, "RSA Digital Signature", "#8B5CF6")
signature_text = value_panel(card, "Signature will appear here")
section_title(3, "University Public Key", "#0D9488")
public_key_text = value_panel(card, "Public key will appear here")
button_row = tk.Frame(card, bg="white")
button_row.pack(pady=(8, 10))

verify_button = tk.Button(
    button_row, text="✓  Verify Certificate", command=verify_certificate,
    font=("Arial", 10, "bold"), bg="#6554D9", fg="white",
    activebackground="#5140C2", activeforeground="white",
    relief="flat", padx=15, pady=9, state=tk.DISABLED, cursor="hand2"
)
verify_button.pack(side="left", padx=5)
tamper_button = tk.Button(
    button_row, text="⚡  Test Tampering", command=test_tampering,
    font=("Arial", 10, "bold"), bg="#FFF0D6", fg="#9A6100",
    activebackground="#FFE4AE", relief="flat", padx=15, pady=9,
    state=tk.DISABLED, cursor="hand2"
)
tamper_button.pack(side="left", padx=5)
reset_button = tk.Button(
    button_row, text="↻ Reset", command=reset_application,
    font=("Arial", 10, "bold"), bg="#E9EAFE", fg="#4C4BA5",
    activebackground="#DADCFB", relief="flat", padx=15, pady=9,
    cursor="hand2"
)
reset_button.pack(side="left", padx=5)
section_title(4, "Received Certificate Hash", "#D97706")
received_hash_text = value_panel(card, "Hash will appear after verification")
result_frame = tk.Frame(card, bg="#E9EAFE")
result_frame.pack(fill="x", padx=24, pady=(4, 8))
result_title = tk.Label(
    result_frame, text="Waiting for verification",
    font=("Arial", 14, "bold"), bg="#E9EAFE", fg="#4C4BA5"
)
result_title.pack(pady=(10, 3))
result_message = tk.Label(
    result_frame, text="Upload a certificate to begin.",
    font=("Arial", 9), bg="#E9EAFE", fg="#454B6B", wraplength=700
)
result_message.pack(pady=(0, 10))
status_box = tk.Frame(card, bg="#E9EAFE")
status_box.pack(fill="x", padx=24, pady=(0, 18))
status_icon = tk.Label(
    status_box, text="i", font=("Arial", 16, "bold"),
    bg="#E9EAFE", fg="#4C4BA5", width=3
)
status_icon.pack(side="left", padx=(8, 0), pady=8)
status_words = tk.Frame(status_box, bg="#E9EAFE")
status_words.pack(side="left", fill="x", expand=True, padx=5, pady=8)
status_title = tk.Label(
    status_words, text="Ready to verify", font=("Arial", 10, "bold"),
    bg="#E9EAFE", fg="#4C4BA5", anchor="w"
)
status_title.pack(fill="x")
status_message = tk.Label(
    status_words, text="Upload a certificate to calculate its hash and sign it.",
    font=("Arial", 9), bg="#E9EAFE", fg="#4C4BA5",
    anchor="w", justify="left", wraplength=680
)
status_message.pack(fill="x")
root.mainloop()