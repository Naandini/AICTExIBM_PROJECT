import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import base64

# Function to generate encryption key from passcode
def generate_key(passcode):
    salt = b'secure_salt'  # You can use a randomly generated salt for better security
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passcode.encode()))

def encrypt_message(message, key):
    aes = Fernet(key)
    return aes.encrypt(message.encode()).decode()

def encode_message():
    passcode = simpledialog.askstring("Passcode", "Enter a passcode:", show='*')
    if not passcode:
        messagebox.showerror("Error", "Passcode is required.")
        return

    key = generate_key(passcode)

    file_path = filedialog.askopenfilename(title="Select Image for Encoding")
    if not file_path:
        return

    img = cv2.imread(file_path)
    if img is None:
        messagebox.showerror("Error", "Invalid image file")
        return

    message = text_input.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Error", "Enter a message to encode")
        return

    encrypted_msg = encrypt_message(message, key)
    binary_msg = ''.join(format(ord(c), '08b') for c in encrypted_msg) + '11111111'  # End delimiter

    data_len = len(binary_msg)
    idx = 0
    for row in img:
        for pixel in row:
            for channel in range(3):
                if idx < data_len:
                    pixel[channel] = (pixel[channel] & 254) | int(binary_msg[idx])
                    idx += 1
                else:
                    break

    save_path = "stego_image.png"
    cv2.imwrite(save_path, img)
    messagebox.showinfo("Success", f"Message encoded and saved as {save_path}")

# GUI Setup
root = tk.Tk()
root.title("Image Steganography - Encryption with Passcode")
root.geometry("400x300")

tk.Label(root, text="Enter Secret Message:").pack()
text_input = tk.Text(root, height=5, width=40)
text_input.pack()

tk.Button(root, text="Encode Message", command=encode_message).pack()

root.mainloop()


