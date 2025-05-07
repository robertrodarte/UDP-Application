import socket
import base64
import logging
import threading
from utils.crypto_utils import (
    generate_rsa_keypair,
    decrypt_with_rsa,
    encrypt_with_aes,
    decrypt_with_aes,
    generate_hmac,
    verify_hmac,
)

# Intialize Logging
logging.basicConfig(
    filename="Logging.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - Client: %(message)s",
)


class Client:
    def __init__(self, server_addr: str = "localhost", server_port: int = 12345):
        logging.info("Initializing client...")
        self.server_ip = (server_addr, server_port)
        self.server_port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.private_key = None
        self.aes_key = None
        self.ack_event = threading.Event()
        self.messages = []
        self.receive_thread = threading.Thread(
            target=self.receive_messages, daemon=True
        )
        self.exchange_key()
        self.receive_thread.start()

    def start(self):
        """
        Begin running the client loop to receieve messages and send messages
        Handles AES encryption and HMAC generation
        """
        while True:
            self.display_gui()
            data = input()
            if not self.aes_key:
                logging.info("Waiting for key exchange to complete")
                print("Waiting for key exchange to complete...")
                continue

            encrypted = encrypt_with_aes(self.aes_key, data)
            hmac = generate_hmac(self.aes_key, encrypted)
            message = f"{encrypted}:{hmac}"
            self.send_data(1, message, data, destination_ip=self.server_ip)

    def send_data(self, message_type, message, plaintext=None, destination_ip=None):
        """
        Used to send data to a destination_ip (server).
        Handles ACKS and retries for packet loss and error control
        :param message_type: Determines if its a regular message or key exchange
        :param message: AES encrypted data that is being sent
        :param plaintext: Pre-encrypted data used to display message in the terminal GUI
        :param destination_ip: Address the data is being sent to
        :return: none
        """
        retries = 3
        ack_received = False
        # Loop to resend data if no ACK is receieved in a given timeout
        for attempt in range(retries):
            try:
                # Clear ACK for new packet being sent
                self.ack_event.clear()
                # Create the packet
                final_message = f"{message_type}:{message}"
                logging.info(f"Sending to server: {message_type}:{final_message}")
                # Encode packet into UTF-8 and send to the destination_ip
                self.sock.sendto(final_message.encode(), destination_ip)
                logging.info(f"Sent message (Attempt {attempt + 1})")

                # Note: Receieving messages is threading
                # Wait a max of 2 seconds to recieve an ACK (ack_event.set())
                # Otherwise retransmit message again (3 times maximum)
                if self.ack_event.wait(timeout=2):
                    ack_received = True
                    break
                else:
                    logging.warning(
                        f"No ACK received, retrying ({attempt + 1}/{retries})..."
                    )

            except Exception as e:
                logging.error(f"Send error: {e}")
                break

        # If ACK received display the plaintext message in the terminal GUI
        if ack_received:
            display = plaintext if plaintext else message
            self.messages.append(f"You: {display}")
        else:
            self.messages.append("Error: Failed to send message after retries.")
        # Refresh GUI
        self.display_gui()

    def exchange_key(self):
        """
        Handles initial sending of RSA public key
        """
        logging.info("Generating RSA keypair...")
        self.private_key, public_key = generate_rsa_keypair()
        encoded_key = base64.b64encode(public_key).decode()
        full_message = f"0:{encoded_key}"
        self.sock.sendto(full_message.encode(), self.server_ip)
        logging.info("Public key sent to server.")

    def receive_messages(self):
        """
        Threaded function that:
        1. Receieves data from the server
        2. Checks if data receieved are ACKs
        3. Handles initial AES key exchange
        4. Unpacks the data from packet form
        5. Handles HMAC
        6. Displays messages to GUI
        """
        while True:
            # Check if theres data to recieve
            data, _ = self.sock.recvfrom(4096)
            logging.info(f"Client: Raw incoming message: {data}")
            message = data.decode()

            # ACK is not encrypted and does not follow packet
            # format, so check if the message is an ACK first
            if message == "ACK":
                self.ack_event.set()
                self.display_gui()
                continue

            # Check is an AES key has been exchanged with this server
            # If not, the message receieved is assumed to be an RSA encrypted AES key
            if self.aes_key is None:
                # Handle AES key exchange (not in packet format)
                try:
                    logging.info("Decrypting AES key...")
                    encrypted_key_bytes = base64.b64decode(message)
                    self.aes_key = decrypt_with_rsa(
                        self.private_key, encrypted_key_bytes
                    )
                    # Set aes_key if message received was decrypted to be an RSA key
                    if self.aes_key:
                        logging.info(
                            f"Client: AES key successfully set: {self.aes_key.hex()}"
                        )
                        self.messages.append("AES key received and decrypted.")
                    else:
                        logging.warning("Client: Decryption returned None.")
                except Exception as e:
                    logging.error(f"Client: Exception during AES key decryption: {e}")
                    self.messages.append(f"Error decrypting AES key: {e}")
                # Refresh GUI
                self.display_gui()
                # Continue to next iteration (we already handled the message)
                continue

            # Check if packet format is correct
            if ":" not in message:
                self.messages.append("Error: Malformed message.")
                self.display_gui()
                # Continue to next iteration (we don't care about the data)
                continue

            # If we get here, this message is a broadcast from the server in packet format
            try:
                # Unpack the packet
                encrypted, hmac = message.split(":")
                # Verify the message wasn't altered using the HMAC
                if not verify_hmac(self.aes_key, encrypted, hmac):
                    self.messages.append("Error: HMAC verification failed.")
                    self.display_gui()
                    logging.error("Error: HMAC Verification Failed")
                    return
                # Decrypt the message with AES key
                decrypted = decrypt_with_aes(self.aes_key, encrypted)
                # Display message in the terminal GUI
                self.messages.append(f"Server Broadcast: {decrypted}")
            except Exception as e:
                self.messages.append(f"Error handling message: {e}")
            # Refresh GUI
            self.display_gui()

    def display_gui(self):
        """
        Displays a GUI in the terminal, handling chat history and user input
        Handles color coordination of client, server, and error messages
        """
        print("\033[H\033[J", end="")  # Clear the screen
        print("\n====================================")
        print("=*=*=*=*=* WELCOME CLIENT *=*=*=*=*=")
        print("====================================\n")
        print("----------- CHAT HISTORY -----------")
        print("------------------------------------")
        for msg in self.messages[-10:]:
            if msg.startswith("You:"):
                print(f"\033[1;34m{msg}\033[0m")  # Color code for client (blue)
            elif msg.startswith("Server Broadcast:"):
                print(f"\033[1;32m{msg}\033[0m")  # Color code for server (green)
            elif msg.startswith("Error"):
                print(f"\033[1;31m{msg}\033[0m")  # Color code for errors (red)
            else:
                print(msg)
        print("\n------------------------------------")
        print("Type your message below:\n", end="", flush=True)


def main():
    """
    Creates a new instance of the client using default arguments
    Starts the client application
    """
    client = Client()
    client.start()


if __name__ == "__main__":
    main()
