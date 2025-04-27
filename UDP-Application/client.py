import socket
import base64
import threading
from utils.crypto_utils import (
    generate_rsa_keypair,
    decrypt_with_rsa,
    encrypt_with_aes,
    decrypt_with_aes,
    generate_hmac,
    verify_hmac,
)

SERVER_PORT = 12345
aes_key = None
messages = []


def receive_messages(sock, private_key):
    global aes_key
    while True:
        data, _ = sock.recvfrom(4096)
        if aes_key is None:
            try:
                encrypted_key = base64.b64decode(data)
                aes_key = decrypt_with_rsa(private_key, encrypted_key)
                print("Received and decrypted AES key.")
            except Exception as e:
                print(f"Error decrypting AES key: {e}")
        else:
            try:
                message_with_hmac = data.decode()
                encrypted, hmac = message_with_hmac.split(":")
                verified_hmac = verify_hmac(aes_key, encrypted, hmac)
                if not verified_hmac:
                    print("HMAC verification failed.")
                    continue
                decrypted = decrypt_with_aes(aes_key, encrypted)
                print("========== Received Message ==========")
                print(f"Server Broadcast: {decrypted}\n")
            except Exception as e:
                print(f"Error receiving message: {e}")
                pass


def main():
    global aes_key
    server_addr = ("localhost", SERVER_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Generate RSA keys and send public key
    private_key, public_key = generate_rsa_keypair()
    sock.sendto(base64.b64encode(public_key), server_addr)
    # GUI
    print("\n====================================\n")
    print("========== WELCOME CLIENT ==========\n")
    print("====================================\n")
    print("Begin typing your messages...\n")
    # Start thread to receive messages
    threading.Thread(
        target=receive_messages, args=(sock, private_key), daemon=True
    ).start()
    while True:
        msg = input("Client: ")
        if aes_key:
            encrypted = encrypt_with_aes(aes_key, msg)
            hmac = generate_hmac(aes_key, encrypted)
            final_message = f"{encrypted}:{hmac}"
            sock.sendto(final_message.encode(), server_addr)
        else:
            print("Waiting for key exchange to complete...")


if __name__ == "__main__":
    main()
