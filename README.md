# Cyber-Security: Encrypted Chat Room Application

A Python-based encrypted chat room application to ensure secure communication between users.

## Overview

This project includes two main components:

1. **Client (`client.py`)** - Sends requests to the server for user authentication.
2. **Server (`server.py`)** - Handles incoming requests and authenticates users based on the data in `user_database.json`.

## Files

- **`client.py`**: The client script that interacts with the server.
- **`server.py`**: The server script that processes authentication requests.
- **`user_database.json`**: A JSON file containing usernames and passwords for authentication.

## Features

- **Basic client-server interaction**.
- **User authentication** using a JSON-based database.

## Requirements

- **Python 3.x**

## Usage

### 1. Start the Server
Run the `server.py` script to start the server:

```bash
python server.py
```

### 2. Run the Client
Open another terminal and run the `client.py` script:

```bash
python client.py
```

### 3. User Login
The client will prompt for a username and password, which will be checked against `user_database.json`.

## User Database Format

The user database (`user_database.json`) follows this format:

```json
{
  "username1": "password1",
  "username2": "password2"
}
```

## Notes

- Update `user_database.json` to add or modify users.
- Ensure the server is running before executing the client script.
