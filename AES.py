pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
KEY = b'Sixteen byte key'  
IV = b'RandomInitVector'  

def encrypt(plain_text):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return base64.b64encode(encrypted_bytes).decode()

def decrypt(encrypted_text):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size)
    return decrypted_bytes.decode()

plain_text = "Hello, AES Encryption!"
encrypted_text = encrypt(plain_text)
decrypted_text = decrypt(encrypted_text)

print(f"Original: {plain_text}")
print(f"Encrypted: {encrypted_text}")
print(f"Decrypted: {decrypted_text}")
