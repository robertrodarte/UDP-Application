import socket
import base64
import secrets
import os
import threading
import cryptography
from utils.crypto_utils import (
    generate_aes_key,
    encrypt_with_rsa,
    decrypt_with_aes,
    encrypt_with_aes,
    generate_hmac,
    verify_hmac,
)

clients = {}
client_keys = {}

LOCAL_IP = "localhost"
SERVER_PORT = 12345


def handle_messages(sock):
    while True:
        # Get data and address from the socket
        data, addr = sock.recvfrom(4096)

        if addr in clients:
            aes_key = clients[addr]
            # Decrypt the message using AES key
            try:
                message_with_hmac = data.decode()
                encrypted, hmac = message_with_hmac.split(":")
                verified_hmac = verify_hmac(aes_key, encrypted, hmac)
                if not verified_hmac:
                    print(f"HMAC verification failed for {addr}")
                    continue
                decrypted = decrypt_with_aes(aes_key, encrypted)
                print(f"Message from {addr}: {decrypted}")
            except Exception as e:
                print(f"Decryption failed for {addr}: {e}")
                continue
            # Broadcast the encrypted message to other clients
            for client_addr, key in clients.items():
                if client_addr != addr:
                    re_encrypted = encrypt_with_aes(key, decrypted)
                    new_hmac = generate_hmac(key, re_encrypted)
                    final_message = f"{re_encrypted}:{new_hmac}"
                    sock.sendto(final_message.encode(), client_addr)
        else:
            # First message is assumed to be client's RSA public key
            rsa_pub_key = base64.b64decode(data)
            aes_key = generate_aes_key()
            encrypted_key = encrypt_with_rsa(rsa_pub_key, aes_key)
            sock.sendto(base64.b64encode(encrypted_key), addr)
            clients[addr] = aes_key
            client_keys[addr] = rsa_pub_key
            print(f"Key exchanged with {addr}")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOCAL_IP, SERVER_PORT))
    print("Server started on port: " + str(SERVER_PORT))
    handle_messages(sock)


if __name__ == "__main__":
    main()
