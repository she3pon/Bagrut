import tkinter as tk
from tkinter import messagebox
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random
from base64 import b64encode, b64decode# in datastore is the users of all time
global username , password ,valid, public_rsa_key , s,exchange_type
def encrypt_message_aes(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    return iv + ciphertext




from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

def perform_diffie_hellman(server_socket):
    # Receive Diffie-Hellman parameters from the server
    var= server_socket.recv(20000).decode().split(',')
    print(var)
    prime, generator, server_public_key = map(int, var)

    # Generate private key for the client
    private_key = random.randint(2, prime - 2)

    # Calculate public key for the client
    public_key = pow(generator, private_key, prime)

    # Send the client's public key to the server
    server_socket.send(str(public_key).encode())

    # Calculate the shared secret
    shared_secret = pow(server_public_key, private_key, prime)

    # Convert the shared secret to bytes
    shared_secret_bytes = long_to_bytes(shared_secret)

    # Use the shared secret as the AES key
    aes_key = shared_secret_bytes[:16]  # Use the first 16 bytes for AES-128

    return aes_key


def decrypt_message_aes(ciphertext, key):
    iv = b64decode(ciphertext[:24])
    ciphertext_bytes = b64decode(ciphertext[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
    return decrypted_message.decode('utf-8')

def login():
    global username, password ,s # Declare as global

    username = username_entry_login .get()
    password = password_entry_login.get()
    message=f"90,login,{username},{password},,,,,,"
    message = encrypt_message_aes(message, aes_key)
    print(message)
    s.send(message.encode())

    recved = s.recv(100000)
    print(recved)
    recved = decrypt_message_aes(recved, aes_key)

    if recved== "login success":
        login_status.config(text="Login successful", fg="green")
    else:
        login_status.config(text="Login failed. Please try again.", fg="red")
  #  s.close()

def sign_up():
    global username, password ,email,s# Declare as global
    username = username_entry_sign_up.get()
    password = password_entry_sign_up.get()
    confirm_password = confirm_password_entry_sign_up.get()
    email=email_entry_sign_up.get()

    if password == confirm_password:
        message="90," + "signup," + username + "," + password+","+email
        message=encrypt_message_aes(message,aes_key)
        print(message)
        s.send(message.encode())  # enters into server the user
        #print("the passwords are the same ")
        recved = s.recv(100000)
        print(recved)
        recved=decrypt_message_aes(recved,aes_key)
        if "newsignup" == recved:
            sign_up_status.config(text="Sign up successful", fg="green")
        else:
            sign_up_status.config(text="already signed in or other problem.", fg="red")
    else:
        sign_up_status.config(text="Passwords do not match.", fg="red")
    #s.close()

def forgot_password():
    global email
    email = email_entry.get()
   
    message=f"90,"+"email,"+email
    message = encrypt_message_aes(message, aes_key)
    print(message)
    s.send(message.encode()) 

    recved = s.recv(100000)
    recved=decrypt_message_aes(recved,aes_key)
    print(recved)

    if recved=="emailsent":
        forgotpasword_status.config(text="code sent to email", fg="green")
    else:
        forgotpasword_status.config(text="something failled nigga", fg="red")
    
    # Here you send a request to your server to send a random code to the user's email
    print("Forgot password request sent for email:", email)

def submit_email():
    # Here you can implement the logic to send the email to the server
    print("Email submitted:", email_entry.get())

def submit_code():
    code = code_entry.get()
    # Here you can verify the code with the server and proceed with password reset
    print("Code submitted:", code_entry.get())

def show_forgot_password_page():
    # Hide the login page
    login_frame.pack_forget()
    # Show the forgot password page
    forgot_password_frame.pack()

def show_login_page():
    # Hide the forgot password page and sign-up page
    forgot_password_frame.pack_forget()
    sign_up_frame.pack_forget()
    # Show the login page
    login_frame.pack()

def show_sign_up_page():
    # Hide the login page
    login_frame.pack_forget()
    # Show the sign-up page
    sign_up_frame.pack()

def show_login_page_from_sign_up():
    # Hide the sign-up page
    sign_up_frame.pack_forget()
    # Show the login page
    login_frame.pack()



# Generate a random AES key
def generate_aes_key(key_size):
    return get_random_bytes(key_size)

# Example usage:
key_size = 16  # 16 bytes (128 bits) for AES-128, 24 bytes (192 bits) for AES-192, or 32 bytes (256 bits) for AES-256
aes_key = generate_aes_key(key_size)


def submit_selection():
    global exchange_type,public_rsa_key
    if var.get() == 1:
        # RSA selected
        messagebox.showinfo("Selected Key Exchange Method", "RSA selected.")
        exchange_type = "rsa"
        # Call function to initiate RSA key exchange
        initiate_rsa_key_exchange()
        
        s.send(f"3,{exchange_type}".encode())
        public_rsa_key = s.recv(100000)
        print(public_rsa_key)
        if public_rsa_key!=None:
            send_encrypted_aes_rsa(s)
    #send_encrypted_aes_rsa(s)
            print("sent encrypted aes rsa")
            print(f"aes key is : {aes_key.hex()}")

        


    elif var.get() == 2:
        # Diffie-Hellman selected
        messagebox.showinfo("Selected Key Exchange Method", "Diffie-Hellman selected.")
        exchange_type = "dph"
        # Call function to initiate Diffie-Hellman key exchange
        initiate_diffie_hellman_key_exchange()
    else:
        messagebox.showerror("Error", "Please select a key exchange method.")

    window.destroy()  # Close the window after selection


def initiate_rsa_key_exchange():
    # Implement RSA key exchange logic
    print("Initiating RSA key exchange...")
    # Your code here

def initiate_diffie_hellman_key_exchange():
    global aes_key
    s.send(f"3,{exchange_type}".encode())
    aes_key = perform_diffie_hellman(s)
    print(f"Diffie-Hellman key exchange completed. AES key: {aes_key.hex()}")


def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    """
    Encrypts AES key using RSA public key.
    """
    rsa_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    """
    Decrypts AES key using RSA private key.
    """
    rsa_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return decrypted_aes_key

def send_encrypted_aes_rsa(cleint):
    tosend=encrypt_aes_key_with_rsa(aes_key,public_rsa_key)
    cleint.send(tosend)

s = socket.socket()
port = 1089
ip = "127.0.0.1"
s.connect((ip, port))

window = tk.Tk()
window.title("Key Exchange Method Selection")
window.geometry("300x400")  # Width x Height
# Create radio buttons
var = tk.IntVar()
tk.Label(window, text="Select Key Exchange Method:").pack()
tk.Radiobutton(window, text="RSA", variable=var, value=1).pack(anchor=tk.W)
tk.Radiobutton(window, text="Diffie-Hellman", variable=var, value=2).pack(anchor=tk.W)

# Create Submit button
tk.Button(window, text="Submit", command=submit_selection).pack()

# Run the Tkinter event loop
window.mainloop()



#public_rsa_key = s.recv(1000)#this is rsa code
#print(public_rsa_key)

if True:
    reply = s.recv(10000)
    print(reply)
    if reply == b"key aquired":

        #this is start of second tkinterpage
        root = tk.Tk()
        root.title("Login Page")

        # Login Frame
        login_frame = tk.Frame(root)

        # Sign Up Frame
        sign_up_frame = tk.Frame(root)

        # Forgot Password Frame
        forgot_password_frame = tk.Frame(root)

        # Set the size of the window
        root.geometry("300x400")  # Width x Height

        # Username Label and Entry for Login
        username_label_login = tk.Label(login_frame, text="Username:")
        username_label_login.pack()
        username_entry_login = tk.Entry(login_frame)
        username_entry_login.pack(pady=5)

        # Password Label and Entry for Login
        password_label_login = tk.Label(login_frame, text="Password:")
        password_label_login.pack()
        password_entry_login = tk.Entry(login_frame, show="*")
        password_entry_login.pack(pady=5)



        # Create login button
        login_button = tk.Button(login_frame, text="Login", command=login)
        login_button.pack(pady=5)


        login_status = tk.Label(login_frame, text="", fg="black")
        login_status.pack(pady=5)

        # Create forgot password button
        forgot_password_button = tk.Button(login_frame, text="Forgot Password", command=show_forgot_password_page)
        forgot_password_button.pack(pady=5)

        # Create sign-up button
        sign_up_button = tk.Button(login_frame, text="Sign Up", command=show_sign_up_page)
        sign_up_button.pack(pady=5)

        # Username Label and Entry for Sign Up
        print("4")
        username_label_sign_up = tk.Label(sign_up_frame, text="Username:")
        username_label_sign_up.pack()
        username_entry_sign_up = tk.Entry(sign_up_frame)
        username_entry_sign_up.pack(pady=5)

        # Password Label and Entry for Sign Up
        password_label_sign_up = tk.Label(sign_up_frame, text="Password:")
        password_label_sign_up.pack()
        password_entry_sign_up = tk.Entry(sign_up_frame, show="*")
        password_entry_sign_up.pack(pady=5)

        # Confirm Password Label and Entry for Sign Up
        confirm_password_label_sign_up = tk.Label(sign_up_frame, text="Confirm Password:")
        confirm_password_label_sign_up.pack()
        confirm_password_entry_sign_up = tk.Entry(sign_up_frame, show="*")
        confirm_password_entry_sign_up.pack(pady=5)


        # Confirm Password Label and Entry for Sign Up
        email_label_sign_up = tk.Label(sign_up_frame, text="enter email:")
        email_label_sign_up.pack()
        email_entry_sign_up = tk.Entry(sign_up_frame)
        email_entry_sign_up.pack(pady=5)





        # Create sign-up button for Sign Up
        submit_sign_up_button = tk.Button(sign_up_frame, text="Sign Up", command=sign_up)
        submit_sign_up_button.pack(pady=5)

        sign_up_status = tk.Label(sign_up_frame, text="", fg="black")
        sign_up_status.pack(pady=5)

        # Create back to login button for Sign Up
        back_to_login_button_sign_up = tk.Button(sign_up_frame, text="Back to Login", command=show_login_page_from_sign_up)
        back_to_login_button_sign_up.pack(pady=5)


        # Email Label and Entry for Forgot Password
        email_label_forgot_password = tk.Label(forgot_password_frame, text="username:")
        email_label_forgot_password.pack()
        email_entry = tk.Entry(forgot_password_frame)
        email_entry.pack(pady=5)


        # Create submit button for Email
        print("3")
        submit_email_button = tk.Button(forgot_password_frame, text="Submit Email", command=forgot_password)
        submit_email_button.pack(pady=5)
        forgotpasword_status= tk.Label(forgot_password_frame, text="", fg="black")
        forgotpasword_status.pack(pady=5)

        # Submit Code Label and Entry for Forgot Password
        code_label_forgot_password = tk.Label(forgot_password_frame, text="Code:")
        code_label_forgot_password.pack()
        code_entry = tk.Entry(forgot_password_frame)
        code_entry.pack(pady=5)

        # Create submit button for Code
        submit_code_button = tk.Button(forgot_password_frame, text="Submit Code", command=submit_code)
        submit_code_button.pack(pady=5)
        code_up_status = tk.Label(forgot_password_frame, text="", fg="black")
        code_up_status.pack(pady=5)

        # Create back to login button for Forgot Password
        back_to_login_button_forgot_password = tk.Button(forgot_password_frame, text="Back to Login", command=show_login_page)
        back_to_login_button_forgot_password.pack(pady=5)

        # Initially show the login page
        show_login_page()

        # Run the Tkinter event loop
        root.mainloop()
s.close()



