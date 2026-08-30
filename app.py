import tkinter as tk
from tkinter import filedialog, messagebox
import os
from crypto_utils import encrypt_file, decrypt_file
from cryptography.fernet import InvalidToken

# ===============
# ENCRYPT FILE
# ===============
def choose_file_encrypt():

    filename = filedialog.askopenfilename()
    if filename:
        encrypt_file_path.set(filename)

def encrypt_selected_file():
    input_file = encrypt_file_path.get()
    password = encrypt_password.get()
    confirm_password = confirm_encrypt_password.get()
    if not input_file:
        messagebox.showerror(
            'Error',
            'Please select a file.'
        )
        return
    if not password:
        messagebox.showerror(
            'Error',
            'Please enter a password.'
        )
        return
    
    if password != confirm_password:
        messagebox.showerror(
            'Error',
            'Passwords do not match.'
        )
        return
    output_file = input_file + '.enc'
    try:
        encrypt_file(
            input_file,
            output_file,
            password
        )
        messagebox.showinfo(
            'Success',
            f'File encrypted successfully!\n\nSaved as:\n{output_file}'
        )
    except Exception as e:
        messagebox.showerror(
            'Encryption Error',
            str(e)
        )

# ===============
# DECRYPT FILE
# ===============
def choose_file_decrypt():
    filename = filedialog.askopenfilename(
        filetypes = [
            ('Encrypted Files', '*.enc'),
            ('All Files', '*.*')
        ]
    )
    if filename:
        decrypt_file_path.set(filename)

def decrypt_selected_file():
    input_file = decrypt_file_path.get()
    password = decrypt_password.get()
    if not input_file:
        messagebox.showerror(
            'Error',
            'Please select an encrypted file.'
        )
        return
    if not password:
        messagebox.showerror(
            'Error',
            'Please enter a password.'
        )
        return
    
    if input_file.endswith('.enc'):
        output_file = input_file[:-4]
    else:
        output_file = input_file + '.decrypted'
    try:
        decrypt_file(
            input_file,
            output_file,
            password
        )
        messagebox.showinfo(
            'Success',
            f'File decrypted successfully!\n\nSaved as:\n{output_file}'
        )
    except InvalidToken:
        messagebox.showerror(
            'Decryption Failed',
            'Incorrect password or corrupted file.'
        )
    except Exception as e:
        messagebox.showerror(
            'Error',
            str(e)
        )

# ===============
# MAIN WINDOW
# ===============
root = tk.Tk()
root.title('Secure File Encryptor')
root.geometry('600x500')

# ===============
# VARIABLES
# ===============
encrypt_file_path = tk.StringVar()
decrypt_file_path = tk.StringVar()

# ===============
# ENCRIPTION SECTION
# ===============
encrypt_label = tk.Label(
    root,
    text = 'Encrypt File',
    font = ('Arial', 28, 'bold')
)
encrypt_label.pack(pady = 10)

tk.Button(
    root,
    text = 'Choose File',
    command = choose_file_encrypt
).pack()

encrypt_password = tk.Entry(
    root,
    show = '*',
    width = 40
)
encrypt_password.pack()
tk.Label(
    root,
    text = 'Confirm Password'
).pack()
confirm_encrypt_password = tk.Entry(
    root,
    show = '*',
    width = 40
)
confirm_encrypt_password.pack()

tk.Button(
    root,
    text = 'Encrypt File',
    command = encrypt_selected_file
).pack(pady = 10)


# ===============
# VISUAL DIVIDER
# ===============
tk.Label(
    root,
    text = '_________________________'
).pack(pady = 10)

# ===============
# DECRYPTION SECTION
# ===============
decrypt_label = tk.Label(
    root,
    text = 'Decrypt File',
    font = ('Arial', 28, 'bold')
)
decrypt_label.pack(pady = 10)

tk.Button(
    root,
    text = 'Choose Encrypted File',
    command = choose_file_decrypt
).pack()

tk.Label(
    root, 
    textvariable = decrypt_file_path,
    wraplength = 500
).pack(pady = 5)

tk.Label(
    root,
    text = 'Password'
).pack()

decrypt_password = tk.Entry(
    root,
    show = '*',
    width = 40
)
decrypt_password.pack()

tk.Button(
    root,
    text = 'Decrypt File',
    command = decrypt_selected_file
).pack(pady = 10)


# ===============
# START APPLICATION
# ===============
root.mainloop()