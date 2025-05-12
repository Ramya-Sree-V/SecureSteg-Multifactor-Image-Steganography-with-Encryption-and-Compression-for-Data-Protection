# 🔐 SecureSteg — PNG Steganography with Compression & AES Encryption

**SecureSteg** is a Python GUI application that securely **embeds**, **compresses**, and **encrypts** secret text messages into **PNG images** using:

- 🧬 **LSB (Least Significant Bit) steganography**
- 🗜️ **zlib compression**
- 🔐 **AES encryption (CFB8 mode)**

It also allows you to **decrypt** and **extract** messages from previously encrypted stego images. Built with an intuitive interface using Tkinter.

---

## ✨ Features

- 💬 **Text Embedding**: Hide plaintext messages in `.png` images using LSB steganography.
- 🗜️ **Compression**: Messages are compressed using `zlib` before embedding for size optimization and added obfuscation.
- 🔐 **AES Encryption**: Encrypt the stego image using AES-CFB8 for added protection.
- 🕵️ **Decryption & Reveal**: Load encrypted images, decrypt them using key/IV, and extract the original hidden message.
- 🖼️ **GUI**: Clean, user-friendly interface built with Tkinter for a smooth user experience.

> 🔒 **Important**: Encryption keys and IVs are not stored. Please save them safely — they are essential for decrypting the hidden message.


## Technologies Used
- **Programming Language:** Python
- **Libraries:**
  - Tkinter: For creating the GUI
  - Pillow: For image processing
  - Cryptography: For AES encryption and decryption
  - zlib: For compressing and decompressing
 
## Installation
To install the required dependencies, run:
```bash
pip install -r requirements.txt
```

## How to Use
- **Run the application:**
  ```bash
  python app.py
  ```
- **Hide a Message:**
  - Click "Open Image" to select a .png image.
  - Type your secret message into the text box.
  - Click "Hide Data" to embed the message using LSB.
  - Click "Hide & Encrypt" to encrypt the image.
  - Save the Key and IV shown after encryption — you'll need them to decrypt the image later.

- **Compress:**
  - Click "Compress" to reduce the image size post-embedding/encryption (optional but enhances security).
- **Reveal a Message:**
  - Click "Open Image" to load the encrypted image.
  - Enter the correct Key and IV, then click "Decrypt & Show".
  - Or, click "Show Data" for non-encrypted hidden messages.
  


## File Structure
```bash
.
├── app.py             # Main application script
├── requirements.txt   # List of dependencies
├── images/            # Example images and assets
│   ├── fairy.jpg
│   └── circle.png
└── README.md          # Documentation
```



## Example
- Encode a message into a PNG image.
- Encrypt the steganographed image and save the resulting secure image.
- Share the encrypted .png securely over a network or storage medium.
- The recipient uses the shared Key and IV to decrypt the image and retrieve the original hidden message.

## Contribution
Contributions are welcome! Feel free to open issues or submit pull requests.

## License
This project is licensed under the MIT License.













