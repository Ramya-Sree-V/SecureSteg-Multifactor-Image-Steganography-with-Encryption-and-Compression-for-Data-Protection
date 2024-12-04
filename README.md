# Secure Steganography and Image Encryption Application

A Python-based GUI application that allows users to hide, encrypt, and compress text messages within images securely. The project uses steganography techniques combined with AES encryption and file compression for enhanced security and efficient storage.

## Features
- **Message Encoding:** Hide secret text messages in images using Least Significant Bit (LSB) steganography.
- **Message Decoding:** Extract hidden messages from steganographed images.
- **Encryption:** Secure the steganographed image using AES encryption (CFB mode) with randomly generated keys and IVs.
- **Decryption:** Decrypt encrypted images using the provided keys and IVs.
- **Compression:** Compress encrypted images using zlib to reduce file size.
- **Decompression:** Decompress compressed image files for further processing.
- **User-Friendly Interface:** Intuitive GUI built with Tkinter for easy usage.

## Technologies Used
- **Programming Language:** Python
- **Libraries:**
  - Tkinter: For creating the GUI
  - Pillow: For image processing
  - Cryptography: For AES encryption and decryption
  - zlib: For compressing and decompressing

## How to Use
- **Run the application:**
  ```bash
  python app.py
  ```
- **Select an image:**
  - Click on "Open Image" to choose an image file for encoding or decoding.
- **Hide a message:**
  - Enter the message in the provided text area.
  - Click "Hide Data" to embed the message into the selected image.
- **Encrypt and Compress:**
   - Click "Compress" to encrypt and compress or click on "Hide & Encrypt" to only hide and encrypt.
  - The encryption key and IV will be displayed. Save them for decryption
- **Decrypt and Decompress:**
  - Use the "Decompress" option to extract the message from the secured image.
- **View results:**
  - The hidden message and any decoded content will appear in the text area.


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
- Encode a message into an image.
- Encrypt and compress the steganographed image.
- Share the compressed file securely.
- Use the decryption key and IV to retrieve the original message.

## Contribution
Contributions are welcome! Feel free to open issues or submit pull requests.

## License
This project is licensed under the MIT License.













