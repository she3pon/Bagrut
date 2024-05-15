import socket
import threading
import pickle
import secrets
import hashlib
import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
import random
import time

from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

def generate_dh_parameters(key_size=2048):
    # Generate a prime number for Diffie-Hellman
    prime = getPrime(key_size)

    # Choose a generator (a random integer smaller than the prime)
    generator = random.randint(2, prime - 1)

    return prime, generator

def perform_diffie_hellman(client_socket):
    # Generate Diffie-Hellman parameters
    prime, generator = generate_dh_parameters()

    # Generate private key for the server
    private_key = random.randint(2, prime - 2)

    # Calculate public key for the server
    public_key = pow(generator, private_key, prime)

    # Send the parameters and public key to the client
    client_socket.send(f"{prime},{generator},{public_key}".encode())

    # Receive the client's public key
    client_public_key = int(client_socket.recv(2000000).decode())

    # Calculate the shared secret
    shared_secret = pow(client_public_key, private_key, prime)

    # Convert the shared secret to bytes
    shared_secret_bytes = long_to_bytes(shared_secret)

    # Use the shared secret as the AES key
    aes_key = shared_secret_bytes[:16]  # Use the first 16 bytes for AES-128

    return aes_key

def handle_diffie_hellman(client_socket):
    global aes_key
    aes_key = perform_diffie_hellman(client_socket)
    print(f"Diffie-Hellman key exchange completed. AES key: {aes_key.hex()}")
    return aes_key




def generate_code():
    """Generate a random code with the specified number of digits."""
    return random.randint(1000, 9999)

class message:
    def __init__(self,reply):
        reply=reply.split(b",")
        #print(reply)
        try:
            self.length=reply[0]
        except:
            pass
        try:
            self.method=reply[1]
        except:
            pass
        try:
            self.username=reply[2]
        except:
            pass
        try:
            self.password=reply[3]
        except:
            pass
        try:
            self.email=reply[4]
        except:
            pass
        try:
            self.text=reply[5]
        except:
            pass

class Person:
    def __init__(this, user,password,email,salt,peper):
        this.username=user
        this.password=password
        this.email=email
        this.salt=salt
        this.peper=peper
        this.messages=[]

def hash_password(password, salt):
    # Combine the password and salt
    salted_password = password.decode() +peper+ str(salt)

    # Hash the salted password using SHA-256 algorithm
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()

    return hashed_password

def generate_salt(length=16):
    # Generate a random salt of the specified length (default is 16)
    return secrets.token_hex(length)

def create_person(username, password,email):
    salt=generate_salt(17)
    hashedpassword=hash_password(password,salt)
    person = Person(username, hashedpassword,email,salt,peper)
    return person

def save_to_pickle(persons, filename):
    try:
        with open(filename, 'wb') as file:
            pickle.dump(persons, file)
        print("Person objects saved to pickle file successfully.")
    except Exception as e:
        print("Error occurred while saving to pickle:", e)

def load_from_pickle(filename):
    try:
        with open(filename, 'rb') as file:
            persons = pickle.load(file)
        return persons
    except FileNotFoundError:
        print("Pickle file not found.")
        return []
    except Exception as e:
        print("Error occurred while loading from pickle:", e)
        return []

def check_credentials_in_pickle(username, password, filename):
    persondict = load_from_pickle(filename)

    return username in persondict and hash_password(password,persondict[username].salt)==persondict[username].password

def return_email(username,filename):
    personsdict = load_from_pickle(filename)
    for person in personsdict.values():
        print(person)
        if person.username == username:
            return person.email
    return "there is an error user not in database"

def returnperson(username, password, filename):
    personsdict = load_from_pickle(filename)
    #print(personsdict)
    for person in personsdict.values():
        print(person)
        if person.username == username and person.password== hash_password(password,personsdict[username].salt) :
            return person
    return None


def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    return iv + ciphertext

def decrypt_message(ciphertext, key):
    iv = b64decode(ciphertext[:24])
    print(iv)
    ciphertext_bytes = b64decode(ciphertext[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
    return decrypted_message.decode('utf-8')

def generate_key_pair():
    global private_key ,public_key
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return  public_key

def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    """
    Decrypts AES key using RSA private key.
    """
    rsa_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return decrypted_aes_key

def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    """
    Encrypts AES key using RSA public key.
    """
    rsa_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key



def send_rsa_key(client):
    public_key =generate_key_pair()
    print(public_key)
    client.send(public_key)


def send_public_key(client_socket, public_key):
    key_data = public_key.export_key()
    client_socket.send(key_data)


def send_encrypted(cleint,message):
    tosend=encrypt_message(message,aes_key)
    #print(tosend)
    cleint.send(tosend.encode())



import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import ssl
from email.message import EmailMessage

EMAIL_SENDER="urikes@gmail.com"
EMAIL_PASSWORD="dmel wgkd rcjv wgdr"
def send_email(email_receiver):
    em = EmailMessage()
    em['from'] = EMAIL_SENDER
    em['to'] = email_receiver
    em['subject'] = 'Reset Password Verification'

    em.set_content(f'Your verification code is  {generate_code()} It will expire in 10 minutes')
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
        smtp.sendmail(EMAIL_SENDER, email_receiver, em.as_string())
        print(f'Sent email to {email_receiver}')



#send_email("urikes@gmail.com")



def login(username,password):

    if username in loggedin:
        print("already loggedin")
        return "already loggedin"

    elif check_credentials_in_pickle(username,password,r"datastore.pickle"):
        person=returnperson(username,password,r"datastore.pickle")
        loggedin[person.username]=person
        return "login success"
    else:
        return "login failed"

def signup(username,password,email):
    if not check_credentials_in_pickle(username,password,r"datastore.pickle"):

        person=create_person(username, password,email)
        persondict=load_from_pickle(r"datastore.pickle")
       # print(persondict)
        persondict[person.username]=person
        save_to_pickle(persondict,r"datastore.pickle")
        # saves to pickle file the dictionary with the new person
        return True
    else:
        print("there is already somone with that username not allowed ")
        return False

def send_dph_pkey():
    pass

def handleclient(cleint):
    global aes_key
    msg = cleint.recv(100000)
    msg = message(msg)
    if msg.method == b"dph":
        aes_key=handle_diffie_hellman(cleint)
        print("dph")
        
        print(f"the aes key is :{aes_key.hex()}")
        cleint.send("key aquired".encode())


    if msg.method == b"rsa":
        send_rsa_key(cleint)
        aes_key = decrypt_aes_key_with_rsa(cleint.recv(100000),private_key)
        print(f"the aes key is :{aes_key.hex()}")
        cleint.send("key aquired".encode())

    while True:
        try:
            msg=cleint.recv(100000)
            print("slllalalalalalalalalal")
            msg=decrypt_message(msg,aes_key)
            #print(f"the mesg is :{msg}")
            msg=message(msg.encode())
            print(msg.method)
            if msg.method==b"signup":
                if signup(msg.username,msg.password,msg.email):
                    send_encrypted(cleint,"newsignup")
                    print("yaya")
                else:
                    send_encrypted(cleint,"signupfailed")

            elif msg.method==b"login":
                send_encrypted(cleint,login(msg.username,msg.password))
            # if login succsesfull it sennd succsess else false


            elif msg.method==b"email":
                if msg.username in loggedin:
                    print("already loggedin")
                    send_encrypted(cleint,"already loggedin")

                else:
                    email=return_email(msg.username,"datastore.pickle")
                    print(email)
                    send_email(email.decode())
                    send_encrypted(cleint,"emailsent")
        except:
            print("error")
            break


loggedin={}
peper="niggeresssssadawdasdwadsjfjsekj"
key=0
global public_key,private_key ,aes_key, iv


def main():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 1089))
        s.listen(5)
        global exit_all
        threads = []
        tid = 1
        while True:
            try:
                # print('\nbefore accept')
                client_socket, addr = s.accept()
                t = threading.Thread(target=handleclient, args=[client_socket])
                t.start()
                threads.append(t)
                tid += 1

            except socket.error as err:
                print('socket error', err)
                break
        exit_all = True
        for t in threads:
            t.join()

        print('server will die now')

if __name__ == '__main__':
    main()
