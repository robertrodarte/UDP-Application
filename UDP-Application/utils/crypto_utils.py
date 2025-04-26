from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hmac
import hashlib


# --- RSA Operations ---
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def encrypt_with_rsa(public_key_bytes, message_bytes):
    pub_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    return cipher_rsa.encrypt(message_bytes)


def decrypt_with_rsa(private_key_bytes, encrypted_bytes):
    priv_key = RSA.import_key(private_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    return cipher_rsa.decrypt(encrypted_bytes)


# --- AES Operations ---
def generate_aes_key():
    return get_random_bytes(16)  # 128-bit key


def encrypt_with_aes(aes_key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()


def decrypt_with_aes(aes_key, b64_ciphertext):
    raw = base64.b64decode(b64_ciphertext)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


def generate_hmac(aes_key, message):
    # Generate an HMAC for the message using the provided key
    return hmac.new(aes_key, message.encode(), hashlib.sha256).hexdigest()


def verify_hmac(aes_key, message, received_hmac):
    # Generate an HMAC for the receieved message
    computed_hmac = hmac.new(aes_key, message.encode(), hashlib.sha256).hexdigest()
    # Compare the computed HMAC with the received HMAC
    return hmac.compare_digest(computed_hmac, received_hmac)
