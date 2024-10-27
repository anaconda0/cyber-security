import socket
import threading
import json

# Simple XOR encryption and decryption functions
def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key for b in data])

def load_user_database():
    try:
        with open("user_database.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_user_database(user_database):
    with open("user_database.json", "w") as file:
        json.dump(user_database, file)

def authenticate_user(conn, key, user_database):
    try:
        encrypted_credentials = conn.recv(1024)
        print(f"Encrypted credentials received: {encrypted_credentials}")

        if not encrypted_credentials:
            print("No encrypted credentials received.")
            conn.sendall(b"Authentication failed: No credentials provided.")
            return False

        decrypted_credentials = xor_encrypt_decrypt(encrypted_credentials, key)
        username, password = decrypted_credentials.decode('utf-8').split(":")
        print(f"Decrypted username: {username}, password: {password}")

        if username in user_database and user_database[username] == password:
            conn.sendall(b"Authentication successful!")
            return True
        else:
            conn.sendall(b"Authentication failed: Incorrect username or password.")
            return False
    except ValueError:
        print("Invalid credentials format.")
        conn.sendall(b"Authentication failed: Invalid credentials format.")
        return False
    except Exception as e:
        print(f"Authentication error: {e}")
        conn.sendall(b"Authentication failed: Internal server error.")
        return False

def handle_signup(credentials, conn, key, user_database):
    try:
        username, password = credentials.split(":")
        if username in user_database:
            conn.sendall(b"Signup failed: Username already exists.")
            return False
        else:
            user_database[username] = password
            save_user_database(user_database)  # Save the updated user database
            conn.sendall(b"Signup successful!")
            return True
    except Exception as e:
        print(f"Signup error: {e}")
        conn.sendall(b"Signup error.")
        return False

def handle_client(conn, addr, key, user_database):
    global connected_clients
    print(f"Connected by {addr}")
    with conn:
        connected_clients.append(conn)
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                decrypted_message = xor_encrypt_decrypt(data, key).decode('utf-8')
                print(f"Received message from {addr}: {decrypted_message}")

                # Check if it's a signup request
                if decrypted_message.startswith("signup:"):
                    success = handle_signup(decrypted_message[7:], conn, key, user_database)
                    if success:
                        print(f"Signup successful for {addr}")
                    else:
                        print(f"Signup failed for {addr}")
                else:
                    broadcast_message(conn, data)
        except ConnectionResetError:
            print(f"Connection reset by {addr}")
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            try:
                connected_clients.remove(conn)  # Remove client connection from the list
            except ValueError:
                pass  # Client connection already removed or not found
            conn.close()
            print(f"Connection closed by {addr}")

def broadcast_message(sender_conn, message):
    global connected_clients
    for client_conn in connected_clients:
        if client_conn != sender_conn:
            try:
                client_conn.sendall(message)
            except Exception as e:
                print(f"Error broadcasting message to {client_conn.getpeername()}: {e}")

def get_local_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.254.254.254', 1))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = '127.0.0.1'
    finally:
        s.close()
    return ip_address

def start_server():
    host = get_local_ip_address()
    port = 12345
    key = 0x56  # Define key as integer

    user_database = load_user_database()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"Server started on {host}:{port}. Waiting for connections...")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr, key, user_database)).start()

if __name__ == "__main__":
    connected_clients = []
    start_server()