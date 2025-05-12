from tkinter import *
from tkinter import filedialog, simpledialog, messagebox
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import zlib

root = Tk()
root.title("SecureSteg - PNG Steganography with Encryption")
root.geometry("730x600")
root.resizable(False, False)
root.configure(bg="#2c041d")

base_path = os.path.dirname(__file__)
image_path = os.path.join(base_path, "fairy.jpg")
image_path_2 = os.path.join(base_path, "circle.png")

# --------------------- CORE FUNCTIONS ---------------------
def compress_text(text):
    return zlib.compress(text.encode('utf-8'), level=9)

def decompress_text(compressed_data):
    try:
        return zlib.decompress(compressed_data).decode('utf-8')
    except zlib.error:
        return "Decompression Error: Invalid or corrupted data"

def text_to_binary(text):
    return ''.join(f"{byte:08b}" for byte in text)

def binary_to_text(binary):
    byte_array = bytearray()
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        byte_array.append(int(byte, 2))
    return bytes(byte_array)

def encode_image(input_image_path, message):
    """Embed message in PNG using LSB steganography"""
    image = Image.open(input_image_path)
    if image.format != 'PNG':
        raise ValueError("Only PNG images are supported")
    
    if image.mode not in ['RGB', 'RGBA']:
        image = image.convert('RGBA' if image.mode == 'P' else 'RGB')
    
    width, height = image.size
    compressed_data = compress_text(message)
    binary_message = text_to_binary(compressed_data) + "1111111111111110"
    
    max_bits = width * height * (4 if image.mode == 'RGBA' else 3)
    if len(binary_message) > max_bits:
        raise ValueError(f"Message too large! Needs {len(binary_message)} bits, has {max_bits}")
    
    pixels = image.load()
    bit_index = 0
    
    for y in range(height):
        for x in range(width):
            pixel = list(pixels[x, y])
            channels = len(pixel)
            
            for i in range(channels):
                if image.mode == 'RGBA' and i == 3:  # Preserve alpha
                    continue
                if bit_index < len(binary_message):
                    pixel[i] = (pixel[i] & ~1) | int(binary_message[bit_index])
                    bit_index += 1
            
            pixels[x, y] = tuple(pixel)
            if bit_index >= len(binary_message):
                break
        if bit_index >= len(binary_message):
            break
    
    return image

def decode_image(input_image_path):
    """Extract hidden message from PNG"""
    image = Image.open(input_image_path)
    if image.format != 'PNG':
        raise ValueError("Only PNG images are supported")
    
    image = image.convert('RGBA')
    width, height = image.size
    pixels = image.load()
    binary_message = []
    delimiter = "1111111111111110"
    
    for y in range(height):
        for x in range(width):
            r, g, b, *a = pixels[x, y]
            for channel in [r, g, b]:
                binary_message.append(str(channel & 1))
    
    compressed_data = binary_to_text(''.join(binary_message).split(delimiter)[0])
    return decompress_text(compressed_data)

def encrypt_image(image_path, key, iv):
    with open(image_path, 'rb') as f:
        data = f.read()
    
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    
    encrypted_path = image_path.replace('.png', '_encrypted.png')
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted)
    return encrypted_path

def decrypt_image(encrypted_path, output_path, key, iv):
    with open(encrypted_path, 'rb') as f:
        encrypted = f.read()
    
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    
    with open(output_path, 'wb') as f:
        f.write(decrypted)

# --------------------- GUI FUNCTIONS ---------------------

current_file = ""  # Global variable to track current working file

def showimage():
    global filename, current_file
    filename = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
    if filename:
        current_file = filename  # Initialize current_file when opening
        img = Image.open(filename)
        img.thumbnail((250, 250))
        tkimg = ImageTk.PhotoImage(img)
        lb1.config(image=tkimg)
        lb1.image = tkimg

def save_file_as():
    return filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG Image", "*.png")]
    )

def Hide():
    global current_file
    message = text1.get("1.0", END).strip()
    if not message:
        messagebox.showwarning("Warning", "Please enter a message to hide")
        return
    
    output_path = save_file_as()
    if not output_path:
        return
    
    try:
        img = encode_image(current_file, message)  # Use current_file instead of filename
        img.save(output_path, compress_level=0)
        current_file = output_path  # Update current_file to new hidden file
        messagebox.showinfo("Success", f"Message hidden in {output_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def Show():
    try:
        decoded = decode_image(filename)
        text1.delete("1.0", END)
        text1.insert(END, decoded)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def Compress():
    global current_file
    if not current_file:
        messagebox.showwarning("Warning", "No file to compress")
        return
    
    try:
        img = Image.open(current_file)
        compressed_path = current_file.replace('.png', '_compressed.png')
        img.save(compressed_path, optimize=True, compress_level=9)
        current_file = compressed_path  # Update current_file to compressed version
        messagebox.showinfo("Success", f"Compressed to: {compressed_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))





def Encrypt():
    global current_file
    if not current_file:
        messagebox.showwarning("Warning", "No file to encrypt")
        return
    
    try:
        key, iv = os.urandom(32), os.urandom(16)
        encrypted_path = encrypt_image(current_file, key, iv)
        current_file = encrypted_path  # Update current_file to encrypted version
        print("Encryption Details", 
                          f"Encrypted file saved as: {encrypted_path}\n\n"
                          f"Key: {key.hex()}\nIV: {iv.hex()}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def DecryptShow():
    input_path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
    if not input_path:
        return
    
    key_hex = simpledialog.askstring("Input", "Enter encryption key (hex):")
    iv_hex = simpledialog.askstring("Input", "Enter IV (hex):")
    
    if not key_hex or not iv_hex:
        return
    
    try:
        # Ask user where to save the decrypted image
        output_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png")]
        )
        if not output_path:
            return
        
        # Decrypt directly to user-specified path
        decrypt_image(input_path, output_path, bytes.fromhex(key_hex), bytes.fromhex(iv_hex))
        
        
        
        # Show decrypted image
        img = Image.open(output_path)
        img.show()
        decoded = decode_image(output_path)
        #text1.delete("1.0", END)
        text1.insert(END, decoded)
        #os.remove(output_path)  # Clean up temp file
        messagebox.showinfo("Success", f"Decrypted image saved as: {output_path}")
        print("Decrypted image saved as:", output_path)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# --------------------- UI SETUP ---------------------
# ICON
image_icon = PhotoImage(file=image_path)
root.iconphoto(False, image_icon)

# LOGO
logo = PhotoImage(file=image_path_2)
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
Button(frame3, text="Save Image", width=12, height=2, font="arial 12 bold", command=save_file_as).place(x=180, y=30)
Label(frame3, text="PNG Images Only", bg="#601a3e", fg="white").place(x=20, y=5)

# FOURTH FRAME
frame4 = Frame(root, bd=3, bg="#601a3e", width=340, height=100, relief=GROOVE)
frame4.place(x=350, y=370)
Button(frame4, text="Hide Data", width=12, height=2, font="arial 12 bold", command=Hide).place(x=10, y=30)
Button(frame4, text="Show Data", width=12, height=2, font="arial 12 bold", command=Show).place(x=180, y=30)
Label(frame4, text="Text Operations", bg="#601a3e", fg="white").place(x=20, y=5)

# FIFTH FRAME
frame5 = Frame(root, bd=3, bg="#601a3e", width=348, height=100, relief=GROOVE)
frame5.place(x=10, y=480)
Button(frame5, text="Encrypt", width=14, height=2, font="arial 12 bold", command=Encrypt).place(x=10, y=30)
Button(frame5, text="Decrypt & Show", width=14, height=2, font="arial 12 bold", command=DecryptShow).place(x=180, y=30)
Label(frame5, text="Encryption Operations", bg="#601a3e", fg="white").place(x=20, y=5)

# SIXTH FRAME
frame6 = Frame(root, bd=3, bg="#601a3e", width=340, height=100, relief=GROOVE)
frame6.place(x=370, y=480)
Button(frame6, text="Compress", width=14, height=2, font="arial 12 bold", command=Compress).place(x=10, y=30)
Label(frame6, text="PNG Compression", bg="#601a3e", fg="white").place(x=20, y=5)

current_file = ""
root.mainloop()


root.mainloop()

