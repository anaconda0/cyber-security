import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# Define constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
KEY = 0x56

# Simple XOR encryption and decryption functions
def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key for b in data])

# Define networking functions
def send_message(sock, message_entry, chat_display):
    try:
        if sock and isinstance(sock, socket.socket):
            message = message_entry.get().encode('utf-8')
            encrypted_message = xor_encrypt_decrypt(message, KEY)
            sock.sendall(encrypted_message)
            message_entry.delete(0, 'end')

            sent_message = message.decode('utf-8')
            display_message("You", sent_message, chat_display)
        else:
            print("Invalid or closed socket.")
    except Exception as e:
        print("Error sending message:", e)

def receive_messages(sock, chat_display):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            decrypted_message = xor_encrypt_decrypt(data, KEY).decode('utf-8')
            display_message("Friend", decrypted_message, chat_display)
        except Exception as e:
            print("Error receiving message:", e)
            break

def display_message(sender, message, chat_display):
    chat_display.config(state='normal')
    chat_display.insert('end', f"{sender}: {message}\n")
    chat_display.see('end')
    chat_display.config(state='disabled')

def connect_to_server(credentials, is_signup=False):
    try:
        print("Attempting connection...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        print("Connected to server")

        modified_credentials = credentials if not is_signup else f"signup:{credentials}"
        encrypted_credentials = xor_encrypt_decrypt(modified_credentials.encode('utf-8'), KEY)
        sock.sendall(encrypted_credentials)

        response = sock.recv(1024)
        response_message = xor_encrypt_decrypt(response, KEY).decode('utf-8')
        print("Response:", response_message)

        if response_message in {"Authentication successful!", "Signup successful!"}:
            return sock
        else:
            messagebox.showerror("Error", response_message)
            sock.close()
            return None
    except Exception as e:
        print("Error in connect_to_server:", e)
        messagebox.showerror("Connection Error", str(e))
        return None

def open_chat_window(sock):
    chat_window = tk.Tk()
    chat_window.geometry("500x500")
    chat_window.title("Chat")

    chat_frame = ttk.Frame(master=chat_window, padding="10")
    chat_frame.pack(fill="both", expand=True)

    chat_display = tk.Text(master=chat_frame, height=20, state='disabled', wrap='word')
    chat_display.pack(pady=10, padx=10, fill="both", expand=True)

    scrollbar = ttk.Scrollbar(master=chat_frame, command=chat_display.yview)
    chat_display.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")

    message_entry = ttk.Entry(master=chat_frame)
    message_entry.pack(pady=5, padx=10, fill="x", expand=True)

    receive_thread = threading.Thread(target=receive_messages, args=(sock, chat_display), daemon=True)
    receive_thread.start()

    def on_send_message():
        send_message(sock, message_entry, chat_display)

    send_button = ttk.Button(master=chat_frame, text="Send", command=on_send_message)
    send_button.pack(pady=5)

    chat_display.tag_configure('sent', justify='right')

    chat_window.mainloop()

def setup_gui():
    def login():
        credentials = f"{username_entry.get()}:{password_entry.get()}"
        sock = connect_to_server(credentials)
        if sock:
            login_window.destroy()
            open_chat_window(sock)

    def signup():
        credentials = f"{username_entry.get()}:{password_entry.get()}"
        if connect_to_server(credentials, is_signup=True):
            messagebox.showinfo("Success", "Signup successful!")

    login_window = tk.Tk()
    login_window.geometry("400x300")
    login_window.title("Login / Signup")

    frame = ttk.Frame(master=login_window, padding="20")
    frame.pack(fill="both", expand=True)

    label_username = ttk.Label(master=frame, text="Username:")
    label_username.pack(pady=5)
    username_entry = ttk.Entry(master=frame)
    username_entry.pack(pady=5)

    label_password = ttk.Label(master=frame, text="Password:")
    label_password.pack(pady=5)
    password_entry = ttk.Entry(master=frame, show="*")
    password_entry.pack(pady=5)

    login_button = ttk.Button(master=frame, text="Login", command=login)
    login_button.pack(pady=5)

    signup_button = ttk.Button(master=frame, text="Signup", command=signup)
    signup_button.pack(pady=5)

    login_window.mainloop()

# Call the setup_gui function to run the client application
setup_gui()
