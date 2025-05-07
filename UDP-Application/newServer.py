import socket
import base64
import logging
from utils.crypto_utils import (
    generate_aes_key,
    encrypt_with_rsa,
    decrypt_with_aes,
    encrypt_with_aes,
    generate_hmac,
    verify_hmac,
)

# Initialize logging
logging.basicConfig(
    filename="Logging.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - Server: %(message)s",
)


class Server:
    def __init__(self, server_addr: str = "localhost", server_port: int = 12345):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((server_addr, server_port))
        self.clients = {}
        self.messages = []
        logging.info("Server initialized and waiting for connections...")

    def display_gui(self):
        """
        Displays a GUI in the terminal, handling chat history and user input
        Handles color coordination of client, server, and error messages
        """
        # Clear the screen
        print("\033[H\033[J", end="")
        print("\n====================================")
        print("=*=*=*=*=* WELCOME SERVER *=*=*=*=*=")
        print("====================================\n")
        print("--------- Connected Clients:--------")
        print("------------------------------------")
        for client in self.clients.keys():
            print(f"(\033[1;34m{client}\033[0m)")
        print("\n-------- Received Messages: --------")
        print("------------------------------------")
        # Display the last 10 messages
        for msg in self.messages[-10:]:
            print(f"\033[1;32m{msg}\033[0m")
        print("\nWaiting for messages...\n", flush=True)

    def verify_and_decrypt_message(self, data, aes_key):
        """
        Verifies the HMAC and decrypts the message
        :param data: The packet sent by a client
        :param aes_key: Key used to decrypt AES encrypted message
        :return: Decrypted message (plaintext)
        """
        try:
            logging.info("Verifying HMAC..")
            message_with_hmac = data.decode()
            # Unpack the packet
            encrypted, hmac = message_with_hmac.split(":")
            # Verify the message was not altered using HMAC
            verified_hmac = verify_hmac(aes_key, encrypted, hmac)
            if not verified_hmac:
                logging.error(f"HMAC verification failed")
                # If HMAC failed, we do not care about the data
                return None
            logging.info(f"HMAC verified successfully.")
            # Decrypt the message if HMAC was verifed
            decrypted = decrypt_with_aes(aes_key, encrypted)
            return decrypted
        except Exception as e:
            logging.error(f"Error during message verification/decryption: {e}")
            return None

    def handle_messages(self):
        """
        Handle incoming messages from clients
        """
        while True:
            # Check if received data
            data, addr = self.sock.recvfrom(4096)
            logging.info(f"Received data from {addr}")

            try:
                message_data = data.decode()
                # If data is not in packet form, then we do not care about it
                if ":" not in message_data:
                    logging.warning("Malformed message received.")
                    # Go to next iteration since we do not care about packet
                    continue
                # If valid packet, unpack it (Message Type : Message)
                type_str, message = message_data.split(":", 1)
                message_type = int(type_str)
            except Exception as e:
                logging.error(f"Failed to parse message: {e}")
                continue
            # Determine is this is an RSA key exchange
            if message_type == 0:
                logging.info(f"Message type 0 received from {addr}")
                # Key exchange
                self.handle_key_exchange(addr, message)
            # Otherwise decrypt the message contents
            elif message_type == 1:
                logging.info(f"Message type 1 received from {addr}")
                # Check if this client is in the client list
                if addr not in self.clients:
                    logging.warning(f"Client {addr} not found.")
                    # Continue to next iteration if not
                    continue
                # Split the message contents
                encrypted, hmac = message.split(":")
                # Grab the AES key for the clients message to decrypt
                aes_key = self.clients[addr]
                # Verify the message was not altered using HMAC
                if not verify_hmac(aes_key, encrypted, hmac):
                    logging.warning("HMAC verification failed.")
                    # If altered, we do not care about it
                    continue
                # Decrypt the AES message with the AES key
                decrypted = decrypt_with_aes(aes_key, encrypted)
                # Show the message in the terminal and who sent it
                self.messages.append(f"{addr}: {decrypted}")
                # Refresh the GUI
                self.display_gui()

                # Send an ACK back to the client
                self.sock.sendto("ACK".encode(), addr)

                # Broadcast to all other clients
                for other_addr, other_key in self.clients.items():
                    # Don't send back to original sender
                    if other_addr == addr:
                        continue
                    # Encrypt the broadcast with other client's key
                    re_encrypted = encrypt_with_aes(other_key, decrypted)
                    # Generate HMAC for verification
                    new_hmac = generate_hmac(other_key, re_encrypted)
                    # Pack the data
                    final_message = f"{re_encrypted}:{new_hmac}"
                    # Send the data (UTF-8)
                    self.sock.sendto(final_message.encode(), other_addr)
            else:
                logging.warning(f"Unknown message type {message_type}")

    def handle_key_exchange(self, addr, message):
        """
        Handles the key exchange with the client
        :param addr: Address of client that wants to exchange
        :param message: Encrypted data of RSA key
        """
        try:
            # Decode the RSA public key
            rsa_pub_key = base64.b64decode(message)
            # Generate an AES key for future messages
            aes_key = generate_aes_key()
            logging.info(f"Generated AES key for {addr}")
            # Encrypt the AES key with the RSA public key
            encrypted_key = encrypt_with_rsa(rsa_pub_key, aes_key)
            logging.info(f"Encrypted AES key for {addr}")
            # Send the encrypted AES key back to the client
            self.sock.sendto(base64.b64encode(encrypted_key), addr)
            # Add client to client list
            self.clients[addr] = aes_key
            # Display key exchanged on GUI
            self.messages.append(f"Key exchanged with {addr}")
            logging.info(f"Key exchanged with {addr}")
            # Refresh GUI
            self.display_gui()
        except Exception as e:
            logging.error(f"Error during key exchange with {addr}: {e}")

    def start(self):
        """
        Start the server
        """
        # Initial GUI display
        self.display_gui()
        self.handle_messages()


def main():
    """
    Creates a new instance of the server using default arguments
    Starts the server application
    """
    server = Server()
    server.start()


if __name__ == "__main__":
    main()
