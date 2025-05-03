import socket
import base64
import threading
import logging
from utils.crypto_utils import (
    generate_rsa_keypair,
    decrypt_with_rsa,
    encrypt_with_aes,
    decrypt_with_aes,
    generate_hmac,
    verify_hmac,
)

logging.basicConfig(
    filename="Logging.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - Client: %(message)s"
)

SERVER_PORT = 12345
aes_key = None
messages = []  # Stores received messages

ack_event = threading.Event()


def receive_messages(sock, private_key):
    global aes_key, messages
    while True:
        try:
            data, _ = sock.recvfrom(4096)

            # Handle acknowledgment
            if data.decode() == "ACK":
                ack_event.set()
                logging.info("Received acknowledgment from server.")
                continue

            # Handle AES key exchange
            if aes_key is None:
                try:
                    encrypted_key = base64.b64decode(data)
                    aes_key = decrypt_with_rsa(private_key, encrypted_key)
                    messages.append("You: Received and decrypted AES key.")
                    logging.info("AES key received and decrypted successfully.")
                    display_gui()
                except Exception as e:
                    logging.error(f"Error decrypting AES key: {e}")
                    display_gui()
                continue

            # Handle regular messages
            try:
                message_with_hmac = data.decode()
                if ":" not in message_with_hmac:
                    raise ValueError("Invalid message format received.")
                encrypted, hmac = message_with_hmac.split(":")
                if not verify_hmac(aes_key, encrypted, hmac):
                    logging.error("HMAC verification failed.")
                    messages.append("Error: HMAC verification failed.")
                    display_gui()
                    continue
                decrypted = decrypt_with_aes(aes_key, encrypted)
                messages.append(f"Server Broadcast: {decrypted}")
                logging.info(f"Decrypted Broadcast Successfully: {decrypted}")
                display_gui()
            except Exception as e:
                logging.error(f"Error receiving message: {e}")
                messages.append(f"Error receiving message: {e}")
                display_gui()

        except Exception as e:
            logging.error(f"Socket error: {e}")


def display_gui():
    global messages
    print("\033[H\033[J", end="")  # Clear the screen
    print("\n====================================")
    print("=*=*=*=*=* WELCOME CLIENT *=*=*=*=*=")
    print("====================================\n")
    print("----------- CHAT HISTORY -----------")
    print("------------------------------------")
    for msg in messages[-10:]:
        if msg.startswith("You:"):
            print(f"\033[1;34m{msg}\033[0m")  # Blue
        elif msg.startswith("Server Broadcast:"):
            print(f"\033[1;32m{msg}\033[0m")  # Green
        elif msg.startswith("Error"):
            print(f"\033[1;31m{msg}\033[0m")  # Red
        else:
            print(msg)
    print("\n------------------------------------")
    print("Type your message below:\n", end="", flush=True)


def main():
    global aes_key
    server_addr = ("localhost", SERVER_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Generate RSA keys and send public key
    private_key, public_key = generate_rsa_keypair()
    sock.sendto(base64.b64encode(public_key), server_addr)
    logging.info("Public key sent to server.")

    # Start background receiver
    threading.Thread(target=receive_messages, args=(sock, private_key), daemon=True).start()

    # Input loop
    while True:
        display_gui()
        msg = input()
        if not aes_key:
            print("Waiting for key exchange to complete...")
            continue
        logging.info(f"Sending message: {msg}")
        encrypted = encrypt_with_aes(aes_key, msg)
        hmac = generate_hmac(aes_key, encrypted)
        final_message = f"{encrypted}:{hmac}"
        logging.info("Encrypted message")

        retries = 3
        ack_received = False
        for attempt in range(retries):
            try:
                ack_event.clear()
                sock.sendto(final_message.encode(), server_addr)
                logging.info(f"Sent message (Attempt {attempt + 1})")

                if ack_event.wait(timeout=2):  # This waits without touching the socket
                    ack_received = True
                    break
                else:
                    logging.warning(f"No ACK received, retrying ({attempt + 1}/{retries})...")

            except Exception as e:
                logging.error(f"Send error: {e}")
                break

        if ack_received:
            messages.append(f"You: {msg}")
        else:
            messages.append("Error: Failed to send message after retries.")
        display_gui()



if __name__ == "__main__":
    main()
