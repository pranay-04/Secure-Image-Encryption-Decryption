import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.font import Font
from encryption import encrypt_image
from decryption import decrypt_image
from key_utils import check_pin_strength
from dotenv import load_dotenv
import os
import csv

# Load credentials from .env file
load_dotenv()

# Global file paths
image_path = ""
encrypted_file_path = ""

def update_strength_label(event):
    pin = entry_pin_encrypt.get()
    strength = check_pin_strength(pin)
    label_strength.config(text=f"PIN Strength: {strength}", fg=("green" if strength == "Strong" else "orange" if strength == "Medium" else "red"))

def browse_image():
    global image_path
    filetypes = (("Image files", "*.jpg *.jpeg *.png"), ("All files", "*.*"))
    filename = filedialog.askopenfilename(title="Select Image", filetypes=filetypes)
    if filename:
        image_path = filename
        label_file.config(text=filename.split('/')[-1])

def browse_encrypted_file():
    global encrypted_file_path
    filetypes = (("Encrypted files", "*.enc"), ("All files", "*.*"))
    filename = filedialog.askopenfilename(title="Select Encrypted File", filetypes=filetypes)
    if filename:
        encrypted_file_path = filename
        label_encrypted_file.config(text=filename.split('/')[-1])

def authenticate_and_open_log():
    auth_window = tk.Toplevel(main)
    auth_window.title("Log Access Authentication")
    auth_window.geometry("300x150")
    auth_window.resizable(False, False)
    auth_window.configure(background="#f0f0f0")

    tk.Label(auth_window, text="Username:", bg="#f0f0f0").pack(pady=5)
    entry_user = tk.Entry(auth_window)
    entry_user.pack()

    tk.Label(auth_window, text="Password:", bg="#f0f0f0").pack(pady=5)
    entry_pass = tk.Entry(auth_window, show="*")
    entry_pass.pack()

    def check_credentials():
        username = entry_user.get()
        password = entry_pass.get()

        if username == os.getenv("LOG_USERNAME") and password == os.getenv("LOG_PASSWORD"):
            auth_window.destroy()
            show_log_csv()
        else:
            messagebox.showerror("Access Denied", "Invalid credentials.")

    tk.Button(auth_window, text="Login", bg="gray", command=check_credentials).pack(pady=10)

def show_log_csv():
    log_path = os.path.join("logs", "activity_log.csv")
    if not os.path.exists(log_path):
        messagebox.showinfo("Log Viewer", "Log file is empty or missing.")
        return

    log_window = tk.Toplevel(main)
    log_window.title("Activity Log")
    log_window.geometry("600x400")

    text_widget = tk.Text(log_window, wrap="none")
    text_widget.pack(expand=True, fill='both')

    with open(log_path, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            text_widget.insert(tk.END, ', '.join(row) + "\n")



    log_window = tk.Toplevel(main)
    log_window.title("Activity Log")
    log_window.geometry("600x400")

    text_widget = tk.Text(log_window, wrap="none")
    text_widget.pack(expand=True, fill='both')

    log_path = os.path.join("logs", "activity_log.csv")
    with open(log_path, "r") as f:

        reader = csv.reader(f)
        for row in reader:
            text_widget.insert(tk.END, ', '.join(row) + "\n")

# GUI Setup
main = tk.Tk()
main.title("Image Encrypt Decrypt")
main.geometry("450x550")
main.configure(background='#dfdddd')
main.bold_font = Font(family="Helvetica", size=14, weight="bold")

label_title = tk.Label(main, text="Image Encryption & Decryption", font=main.bold_font, bg='#dfdddd')
label_title.pack(pady=10)

label_file = tk.Label(main, text="No original image selected", bg='#dfdddd')
label_file.pack()

btn_browse = tk.Button(main, text="Browse Original Image", command=browse_image, bg='#e28743')
btn_browse.pack(pady=5)

label_pin = tk.Label(main, text="Enter Encryption PIN:", bg='#dfdddd')
label_pin.pack()

entry_pin_encrypt = tk.Entry(main, show='*')
entry_pin_encrypt.pack(pady=5)
entry_pin_encrypt.bind("<KeyRelease>", update_strength_label)

label_strength = tk.Label(main, text="PIN Strength: ", bg='#dfdddd')
label_strength.pack()

btn_encrypt = tk.Button(main, text="Encrypt Image", bg='#e28743', command=lambda: encrypt_image(image_path, entry_pin_encrypt.get()))
btn_encrypt.pack(pady=5)

label_encrypted_file = tk.Label(main, text="No encrypted file selected", bg='#dfdddd')
label_encrypted_file.pack()

btn_browse_enc = tk.Button(main, text="Browse Encrypted File", command=browse_encrypted_file, bg='#e28743')
btn_browse_enc.pack(pady=5)

label_pin_decrypt = tk.Label(main, text="Enter Decryption PIN:", bg='#dfdddd')
label_pin_decrypt.pack()

entry_pin_decrypt = tk.Entry(main, show='*')
entry_pin_decrypt.pack(pady=5)

btn_decrypt = tk.Button(main, text="Decrypt Image", bg='#e28743', command=lambda: decrypt_image(encrypted_file_path, entry_pin_decrypt.get()))
btn_decrypt.pack(pady=5)

btn_log = tk.Button(main, text="View Activity Log", bg='gray', command=authenticate_and_open_log)
btn_log.pack(pady=15)

main.mainloop()
