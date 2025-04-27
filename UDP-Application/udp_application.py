import os


def main():
    print("=== Welcome to the UDP Application ===")
    print("1. Run as Server")
    print("2. Run as Client")
    print("3. Exit")

    while True:
        choice = input("Select an option: ")
        if choice == "1":
            os.system("python server.py")
        elif choice == "2":
            os.system("python client.py")
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
