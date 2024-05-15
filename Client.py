import tkinter as tk
from tkinter import messagebox
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random
from base64 import b64encode, b64decode

# Global variables
user_id, user_pass, is_valid, public_key_rsa, client_sock, exchange_method = None, None, None, None, None, None

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(encrypted_bytes).decode('utf-8')
    return iv + ciphertext

def perform_dh(server_sock):
    params = server_sock.recv(20000).decode().split(',')
    prime, generator, server_public = map(int, params)

    private = random.randint(2, prime - 2)
    public = pow(generator, private, prime)

    server_sock.send(str(public).encode())

    shared_secret = pow(server_public, private, prime)
    shared_secret_bytes = long_to_bytes(shared_secret)

    aes_key = shared_secret_bytes[:16]
    return aes_key

def decrypt_data(ciphertext, key):
    iv = b64decode(ciphertext[:24])
    ciphertext_bytes = b64decode(ciphertext[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
    return decrypted_text.decode('utf-8')

def authenticate():
    global user_id, user_pass, is_valid, client_sock

    user_id = username_entry_login.get()
    user_pass = password_entry_login.get()
    message = f"90,login,{user_id},{user_pass},,,,,,"
    message = encrypt_data(message, aes_key)
    client_sock.send(message.encode())

    response = client_sock.recv(100000)
    response = decrypt_data(response, aes_key)

    if response == "login success":
        login_status.config(text="Login successful", fg="green")
    else:
        login_status.config(text="Login failed. Please try again.", fg="red")

def register():
    global user_id, user_pass, email, client_sock

    user_id = username_entry_sign_up.get()
    user_pass = password_entry_sign_up.get()
    confirm_pass = confirm_password_entry_sign_up.get()
    email = email_entry_sign_up.get()

    if user_pass == confirm_pass:
        message = "90," + "signup," + user_id + "," + user_pass + "," + email
        message = encrypt_data(message, aes_key)
        client_sock.send(message.encode())

        response = client_sock.recv(100000)
        response = decrypt_data(response, aes_key)

        if "newsignup" == response:
            sign_up_status.config(text="Sign up successful", fg="green")
        else:
            sign_up_status.config(text="Already signed in or other problem.", fg="red")
    else:
        sign_up_status.config(text="Passwords do not match.", fg="red")

def reset_password_request():
    global email
    email = email_entry.get()

    message = f"90,"+"email,"+email
    message = encrypt_data(message, aes_key)
    client_sock.send(message.encode())

    response = client_sock.recv(100000)
    response = decrypt_data(response, aes_key)

    if response == "emailsent":
        forgotpasword_status.config(text="Code sent to email", fg="green")
    else:
        forgotpasword_status.config(text="Something failed", fg="red")

def submit_email():
    print("Email submitted:", email_entry.get())

def submit_code():
    code = code_entry.get()
    print("Code submitted:", code_entry.get())

def show_forgot_password_page():
    login_frame.pack_forget()
    forgot_password_frame.pack()

def show_login_page():
    forgot_password_frame.pack_forget()
    sign_up_frame.pack_forget()
    login_frame.pack()

def show_sign_up_page():
    login_frame.pack_forget()
    sign_up_frame.pack()

def show_login_page_from_sign_up():
    sign_up_frame.pack_forget()
    login_frame.pack()

def generate_aes_key(key_size):
    return get_random_bytes(key_size)

def initiate_key_exchange():
    global aes_key, exchange_method

    if var.get() == 1:
        messagebox.showinfo("Selected Key Exchange Method", "RSA selected.")
        exchange_method = "rsa"
        initiate_rsa_key_exchange()
        client_sock.send(f"3,{exchange_method}".encode())
        public_key_rsa = client_sock.recv(100000)

        if public_key_rsa:
            send_encrypted_aes_rsa(client_sock)
            print(f"AES key is: {aes_key.hex()}")

    elif var.get() == 2:
        messagebox.showinfo("Selected Key Exchange Method", "Diffie-Hellman selected.")
        exchange_method = "dph"
        initiate_diffie_hellman_key_exchange()
    else:
        messagebox.showerror("Error", "Please select a key exchange method.")

    window.destroy()

def initiate_rsa_key_exchange():
    print("Initiating RSA key exchange...")

def initiate_diffie_hellman_key_exchange():
    global aes_key
    client_sock.send(f"3,{exchange_method}".encode())
    aes_key = perform_dh(client_sock)
    print(f"Diffie-Hellman key exchange completed. AES key: {aes_key.hex()}")

def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    rsa_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    rsa_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return decrypted_aes_key

def send_encrypted_aes_rsa(client):
    encrypted_key = encrypt_aes_key_with_rsa(aes_key, public_key_rsa)
    client.send(encrypted_key)

client_sock = socket.socket()
port = 1089
ip = "127.0.0.1"
client_sock.connect((ip, port))

window = tk.Tk()
window.title("Key Exchange Method Selection")
window.geometry("300x400")

var = tk.IntVar()
tk.Label(window, text="Select Key Exchange Method:").pack()
tk.Radiobutton(window, text="RSA", variable=var)