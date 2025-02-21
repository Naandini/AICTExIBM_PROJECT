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

def decrypt_message(encrypted_msg, key):
    try:
        aes = Fernet(key)
        return aes.decrypt(encrypted_msg.encode()).decode()
    except:
        return None

def decode_message():
    passcode = simpledialog.askstring("Passcode", "Enter the passcode:", show="*")
    if not passcode:
        messagebox.showerror("Error", "Passcode is required.")
        return

    key = generate_key(passcode)

    file_path = filedialog.askopenfilename(title="Select Stego Image for Decoding")
    if not file_path:
        return

    img = cv2.imread(file_path)
    if img is None:
        messagebox.showerror("Error", "Invalid image file")
        return

    binary_msg = ""
    stop_marker = "11111111"  # Marks the end of the hidden message

    for row in img:
        for pixel in row:
            for channel in range(3):
                binary_msg += str(pixel[channel] & 1)

                if binary_msg.endswith(stop_marker):  # Stop reading when marker is found
                    break

    # Convert binary to characters
    extracted_text = ""
    for i in range(0, len(binary_msg) - 8, 8):  # Ignore stop marker
        char = chr(int(binary_msg[i:i+8], 2))
        extracted_text += char

    decrypted_msg = decrypt_message(extracted_text.strip(), key)

    if decrypted_msg:
        messagebox.showinfo("Decoded Message", f"Hidden Message: {decrypted_msg}")
    else:
        messagebox.showerror("Error", "Failed to decode message. Incorrect passcode or corrupted data.")

# GUI Setup
root = tk.Tk()
root.title("Image Steganography - Decryption with Passcode")
root.geometry("400x200")

tk.Button(root, text="Decode Message", command=decode_message).pack()

root.mainloop()
