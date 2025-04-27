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
messages = []  # Stores received messages


def receive_messages(sock, private_key):
    global aes_key, messages
    while True:
        data, _ = sock.recvfrom(4096)
        if aes_key is None:
            try:
                encrypted_key = base64.b64decode(data)
                aes_key = decrypt_with_rsa(private_key, encrypted_key)
                messages.append("Received and decrypted AES key.")
                display_gui()  # Refresh the GUI
            except Exception as e:
                messages.append(f"Error decrypting AES key: {e}")
                display_gui()  # Refresh the GUI
        else:
            try:
                message_with_hmac = data.decode()
                encrypted, hmac = message_with_hmac.split(":")
                verified_hmac = verify_hmac(aes_key, encrypted, hmac)
                if not verified_hmac:
                    messages.append("HMAC verification failed.")
                    display_gui()  # Refresh the GUI
                    continue
                decrypted = decrypt_with_aes(aes_key, encrypted)
                messages.append(f"Server Broadcast: {decrypted}")
                display_gui()  # Refresh the GUI
            except Exception as e:
                messages.append(f"Error receiving message: {e}")
                display_gui()  # Refresh the GUI


def display_gui():
    global messages
    # Clear the screen
    print("\033[H\033[J", end="")  # ANSI escape code to clear the terminal
    print("\n====================================")
    print("=*=*=*=*=* WELCOME CLIENT *=*=*=*=*=")
    print("====================================\n")
    print("----------- CHAT HISTORY -----------")
    print("------------------------------------")
    for msg in messages[-10:]:  # Display the last 10 messages
        if msg.startswith("You:"):
            print(f"\033[1;34m{msg}\033[0m")  # Blue text for client messages
        elif msg.startswith("Server Broadcast:"):
            print(f"\033[1;32m{msg}\033[0m")  # Green text for server broadcasts
        elif msg.startswith("Error"):
            print(f"\033[1;31m{msg}\033[0m")  # Red text for error messages
        else:
            print(msg)  # Default color for other messages
    print("\n------------------------------------")
    print("Type your message below:\n", end="", flush=True)


def main():
    global aes_key
    server_addr = ("localhost", SERVER_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Generate RSA keys and send public key
    private_key, public_key = generate_rsa_keypair()
    sock.sendto(base64.b64encode(public_key), server_addr)

    # Start thread to receive messages
    threading.Thread(
        target=receive_messages, args=(sock, private_key), daemon=True
    ).start()

    # Input loop
    while True:
        display_gui()  # Refresh the GUI before taking input
        msg = input()  # Take input without clearing the screen
        if aes_key:
            encrypted = encrypt_with_aes(aes_key, msg)
            hmac = generate_hmac(aes_key, encrypted)
            final_message = f"{encrypted}:{hmac}"
            sock.sendto(final_message.encode(), server_addr)
            messages.append(f"You: {msg}")  # Add the sent message to the display
            display_gui()  # Refresh the GUI after sending
        else:
            print("Waiting for key exchange to complete...")


if __name__ == "__main__":
    main()
