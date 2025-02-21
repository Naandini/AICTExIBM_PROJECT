Overview
This project implements Image Steganography with AES encryption using Python. It allows users to securely hide and retrieve text messages inside images using a passcode-protected GUI.

Features
✅ Passcode Protection – Encrypts hidden messages with a user-provided passcode.
✅ Graphical User Interface (GUI) – Easy-to-use Tkinter-based interface.
✅ AES Encryption (Fernet) – Ensures message security before embedding.
✅ LSB Steganography – Hides messages inside image pixels with minimal distortion.
✅ Cross-Platform Support – Works on Windows, macOS, and Linux.

Required Libraries and Installation Commands:
OpenCV (For image processing)
pip install opencv-python

NumPy (For handling image arrays)
pip install numpy

Cryptography (For AES encryption and key derivation)
pip install cryptography

Tkinter (For GUI - Usually pre-installed with Python)
If Tkinter is missing on Linux, install it using:
sudo apt-get install python3-tk
On Windows & macOS, Tkinter comes pre-installed with Python.
