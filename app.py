from tkinter import *
from tkinter import filedialog
from tkinter import simpledialog
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

root = Tk()
root.title("SecureSteg - Secure Steganography with Encryption and Compression")
root.geometry("730x600")
root.resizable(False, False)
root.configure(bg="#2c041d")

# Converts a text message to its binary representation.
def text_to_binary(text):
    binary_text = ''.join(format(ord(char), '08b') for char in text)
    return binary_text

# Converts binary data back to its corresponding text.
def binary_to_text(binary):
    chars = [chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)]
    return ''.join(chars)

# Hides a given message within an image using Least Significant Bit (LSB) steganography.
def encode_image(input_image_path, message):
    image = Image.open(input_image_path)
    image = image.convert('RGB')  # Ensure image is in RGB mode for consistent pixel handling
    width, height = image.size
    message += "1111111111111110"  # Delimiter to mark the end of the message
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    
    binary_message_index = 0
    
    for y in range(height):
        for x in range(width):
            pixel = list(image.getpixel((x, y)))
            
            for i in range(3):  # Only modify RGB channels (ignore alpha if present)
                if binary_message_index < len(binary_message):
                    pixel[i] = (pixel[i] & ~1) | int(binary_message[binary_message_index])
                    binary_message_index += 1
            
            image.putpixel((x, y), tuple(pixel))
            
            if binary_message_index >= len(binary_message):
                break
        if binary_message_index >= len(binary_message):
            break
    
    return image

# Extracts the hidden message from an image by reading the least significant bits of each pixel.
def decode_image(input_image_path):
    image = Image.open(input_image_path)
    image = image.convert('RGB')  # Ensure consistent mode for decoding
    binary_message = ''
    width, height = image.size
    
    for y in range(height):
        for x in range(width):
            pixel = list(image.getpixel((x, y)))
            
            for i in range(3):  # Only decode RGB channels
                binary_message += str(pixel[i] & 1)
    
    byte_chunks = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    decoded_message = ''.join([chr(int(byte, 2)) for byte in byte_chunks])
    
    decoded_message = decoded_message.split("1111111111111110")[0]  # Remove delimiter
    return decoded_message

# Opens a file dialog for selecting an image.
def showimage():
    global filename
    filename = filedialog.askopenfilename(initialdir=os.getcwd(),
                                          title="Select Image File",
                                          filetype=(("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.tiff"),
                                                    ("PNG File", "*.png"),
                                                    ("JPG File", "*.jpg;*.jpeg"),
                                                    ("BMP File", "*.bmp"),
                                                    ("TIFF File", "*.tiff"),
                                                    ("All Files", "*.*")))
    img = Image.open(filename)
    img.thumbnail((250, 250))  # Resize image for display
    img = ImageTk.PhotoImage(img)
    lb1.configure(image=img, width=250, height=250)
    lb1.image = img

# Prompts the user to choose the file format for saving the hidden image.
def save_file_as():
    filetypes = [("PNG File", "*.png"),
                 ("JPG File", "*.jpg;*.jpeg"),
                 ("BMP File", "*.bmp"),
                 ("TIFF File", "*.tiff"),
                 ("All Files", "*.*")]
    
    save_filename = filedialog.asksaveasfilename(defaultextension=".png",
                                                 filetypes=filetypes,
                                                 title="Save Image As")
    return save_filename

# This function retrieves the message from the text box and hides it in the image.
def Hide():
    global secret
    message = text1.get(1.0, END).strip()  # Ensure there are no extra newlines
    
    output_image_path = save_file_as()
    if output_image_path:
        hidden_image = encode_image(filename, message)
        hidden_image.save(output_image_path)
        print(f"Message encoded and saved to {output_image_path}")

def Show():
    decoded_message = decode_image(filename)
    text1.delete(1.0, END)
    text1.insert(END, decoded_message)

def save():
    pass

    

# Generates a random key and IV for encryption.
def generate_key_iv():
    key = os.urandom(32)
    iv = os.urandom(16)
    return key, iv

# Encrypts the image using AES encryption in CFB mode.
def encrypt_image(image_path, key, iv):
    with open(image_path, 'rb') as file:
        image_data = file.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(image_data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(image_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    print(f"Image encrypted and saved to {image_path}")

# This function hides the message, encrypts the image, and saves it under the user-chosen filename.
def HideAndEncrypt():
    global secret
    message = text1.get(1.0, END).strip()
    
    output_image_path = save_file_as()
    if output_image_path:
        # Hide the message in the image
        hidden_image = encode_image(filename, message)
        hidden_image.save(output_image_path)

        # Encrypt the image after hiding the message
        key, iv = generate_key_iv()
        encrypt_image(output_image_path, key, iv)

        print(f"Encryption Key: {key.hex()}")
        print(f"Encryption IV: {iv.hex()}")

# Decrypts the image and checks for valid formats.
def decrypt_image(encrypted_image_path, output_decrypted_path, key, iv):
    try:
        with open(encrypted_image_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        # Check image signature
        if decrypted_data[:8] == b'\x89PNG\r\n\x1a\n':  # PNG signature
            print("Decrypted data is a valid PNG image.")
        elif decrypted_data[:2] == b'\xFF\xD8':  # JPG signature
            print("Decrypted data is a valid JPG image.")
        else:
            print("Decrypted data is not a valid image format.")
            return

        with open(output_decrypted_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"Image decrypted and saved to {output_decrypted_path}")

    except ValueError as e:
        print("Decryption failed: ", str(e))

# Decrypts and shows the image and hidden message.
def DecryptAndShow():
    decrypted_image_path = "decrypted_hidden.png"
    
    key_hex = simpledialog.askstring("Input", "Enter the encryption key (hex format):", parent=root)
    iv_hex = simpledialog.askstring("Input", "Enter the IV (hex format):", parent=root)
    
    if key_hex and iv_hex:
        try:
            key = bytes.fromhex(key_hex)
            iv = bytes.fromhex(iv_hex)
            
            decrypt_image(filename, decrypted_image_path, key, iv)
            
            try:
                img = Image.open(decrypted_image_path)
                img.show()  # Show the image to verify it's correct
            except Exception as e:
                print(f"Failed to open the decrypted image: {e}")
            
            decoded_message = decode_image(decrypted_image_path)
            text1.delete(1.0, END)
            text1.insert(END, decoded_message)
        except ValueError as e:
            print("Invalid input or decryption error:", e)
    else:
        print("Key or IV not provided.")

import zlib

# Function to compress the encrypted image using zlib.
def compress_image(input_image_path, compressed_output_path):
    try:
        with open(input_image_path, 'rb') as file:
            image_data = file.read()

        compressed_data = zlib.compress(image_data)

        with open(compressed_output_path, 'wb') as compressed_file:
            compressed_file.write(compressed_data)

        print(f"Image compressed and saved to {compressed_output_path}")
    except Exception as e:
        print(f"Compression failed: {e}")

# This function hides, encrypts, compresses the image, and saves it.
def HideEncryptAndCompress():
    global secret
    message = text1.get(1.0, END).strip()

    output_image_path = save_file_as()
    compressed_output_path = output_image_path.replace(".png", "_compressed.zlib")

    if output_image_path:
        # Hide the message in the image
        hidden_image = encode_image(filename, message)
        hidden_image.save(output_image_path)

        # Encrypt the image after hiding the message
        key, iv = generate_key_iv()
        encrypt_image(output_image_path, key, iv)

        # Compress the encrypted image
        compress_image(output_image_path, compressed_output_path)

        print(f"Encryption Key: {key.hex()}")
        print(f"Encryption IV: {iv.hex()}")
        print(f"Compressed file saved at: {compressed_output_path}")

# Decompress the image for decoding.
def decompress_image(compressed_image_path, decompressed_output_path):
    try:
        with open(compressed_image_path, 'rb') as compressed_file:
            compressed_data = compressed_file.read()

        decompressed_data = zlib.decompress(compressed_data)

        with open(decompressed_output_path, 'wb') as decompressed_file:
            decompressed_file.write(decompressed_data)

        print(f"Image decompressed and saved to {decompressed_output_path}")
    except Exception as e:
        print(f"Decompression failed: {e}")

# Decompress, decrypt, and show the image and hidden message.
def DecompressDecryptAndShow():
    decompressed_image_path = "decompressed_hidden.png"

    compressed_image_path = filedialog.askopenfilename(
        title="Select Compressed File",
        filetype=(("ZLIB Compressed Files", "*.zlib"), ("All Files", "*.*"))
    )

    if not compressed_image_path:
        print("No compressed file selected.")
        return

    decompress_image(compressed_image_path, decompressed_image_path)

    key_hex = simpledialog.askstring("Input", "Enter the encryption key (hex format):", parent=root)
    iv_hex = simpledialog.askstring("Input", "Enter the IV (hex format):", parent=root)

    if key_hex and iv_hex:
        try:
            key = bytes.fromhex(key_hex)
            iv = bytes.fromhex(iv_hex)

            decrypt_image(decompressed_image_path, "decrypted_image.png", key, iv)

            try:
                img = Image.open("decrypted_image.png")
                img.show()  # Show the image to verify it's correct
            except Exception as e:
                print(f"Failed to open the decrypted image: {e}")

            decoded_message = decode_image("decrypted_image.png")
            text1.delete(1.0, END)
            text1.insert(END, decoded_message)
        except ValueError as e:
            print("Invalid input or decryption error:", e)
    else:
        print("Key or IV not provided.")


# ICON
image_icon = PhotoImage(file="fairy.jpg")
root.iconphoto(False, image_icon)

# LOGO
logo = PhotoImage(file="circle.png")
Label(root, image=logo, bg="#2c041d").place(x=10, y=0)

Label(root, text="CYBER SCIENCE", bg="#2c041d", fg="white", font="arial 25 bold").place(x=100, y=20)


# FIRST FRAME
f = Frame(root, bd=3, bg="black", width=340, height=280, relief=GROOVE)
f.place(x=10, y=80)

lb1 = Label(f, bg="black")
lb1.place(x=40, y=10)

# SECOND FRAME
frame2 = Frame(root, bd=3, width=340, height=280, bg="#c8a2c9", relief=GROOVE)
frame2.place(x=350, y=80)

text1 = Text(frame2, font="Roboto 20", bg="#c8a2c9", fg="black", relief=GROOVE, wrap=WORD)
text1.place(x=0, y=0, width=320, height=295)

scrollbar1 = Scrollbar(frame2)
scrollbar1.place(x=320, y=0, height=300)

scrollbar1.configure(command=text1.yview)
text1.configure(yscrollcommand=scrollbar1.set)

# THIRD FRAME
frame3 = Frame(root, bd=3, bg="#601a3e", width=330, height=100, relief=GROOVE)
frame3.place(x=10, y=370)

Button(frame3, text="Open Image", width=12, height=2, font="arial 12 bold", command=showimage).place(x=10, y=30)
Button(frame3, text="Save Image", width=12, height=2, font="arial 12 bold", command=save).place(x=180, y=30)
Label(frame3, text="Picture, Image, Photo File", bg="#601a3e", fg="white").place(x=20, y=5)

# FOURTH FRAME
frame4 = Frame(root, bd=3, bg="#601a3e", width=340, height=100, relief=GROOVE)
frame4.place(x=350, y=370)

Button(frame4, text="Hide Data", width=12, height=2, font="arial 12 bold", command=Hide).place(x=10, y=30)
Button(frame4, text="Show Data", width=12, height=2, font="arial 12 bold", command=Show).place(x=180, y=30)
Label(frame4, text="Text only", bg="#601a3e", fg="white").place(x=20, y=5)

# FIFTH FRAME - Encryption and Decryption
frame5 = Frame(root, bd=3, bg="#601a3e", width=348, height=100, relief=GROOVE)
frame5.place(x=10, y=480)

Button(frame5, text="Hide & Encrypt", width=14, height=2, font="arial 12 bold", command=HideAndEncrypt).place(x=10, y=30)
Button(frame5, text="Decrypt & Show", width=14, height=2, font="arial 12 bold", command=DecryptAndShow).place(x=180, y=30)
Label(frame5, text="Picture, Image, Photo File", bg="#601a3e", fg="white").place(x=20, y=5)

# Adding the new frame and buttons for compression-related actions
frame6 = Frame(root, bd=3, bg="#601a3e", width=340, height=100, relief=GROOVE)
frame6.place(x=370, y=480)

Button(frame6, text="Compress", width=14, height=2, font="arial 12 bold", command=HideEncryptAndCompress).place(x=10, y=30)
Button(frame6, text="Decompress", width=14, height=2, font="arial 12 bold", command=DecompressDecryptAndShow).place(x=180, y=30)
Label(frame6, text="Compressed File Operations", bg="#601a3e", fg="white").place(x=20, y=5)


root.mainloop()

