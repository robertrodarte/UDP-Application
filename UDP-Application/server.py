import socket
import base64
from utils.crypto_utils import (
    generate_aes_key,
    encrypt_with_rsa,
    decrypt_with_aes,
    encrypt_with_aes,
    generate_hmac,
    verify_hmac,
)

clients = {}
messages = []  # Stores received messages

LOCAL_IP = "localhost"
SERVER_PORT = 12345


def display_gui():
    global messages, clients
    # Clear the screen
    print("\033[H\033[J", end="")  # ANSI escape code to clear the terminal
    print("\n====================================")
    print("=*=*=*=*=* WELCOME SERVER *=*=*=*=*=")
    print("====================================\n")
    print("--------- Connected Clients:--------")
    print("------------------------------------")
    for client in clients.keys():
        print(f"(\033[1;34m{client}\033[0m)")
    print("\n-------- Received Messages: --------")
    print("------------------------------------")
    for msg in messages[-10:]:  # Display the last 10 messages
        print(f"\033[1;32m{msg}\033[0m")
    print("\nWaiting for messages...\n", flush=True)


def handle_messages(sock):
    """Handle incoming messages from clients."""
    global clients, messages
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
                    messages.append(f"HMAC verification failed for {addr}")
                    display_gui()
                    continue
                decrypted = decrypt_with_aes(aes_key, encrypted)
                messages.append(f"Client {addr}: {decrypted}")
                display_gui()
            except Exception as e:
                messages.append(f"Decryption failed for {addr}: {e}")
                display_gui()
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
            messages.append(f"Key exchanged with {addr}")
            display_gui()


def main():
    global clients, messages
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOCAL_IP, SERVER_PORT))

    # Initial GUI display
    display_gui()
    handle_messages(sock)


if __name__ == "__main__":
    main()
