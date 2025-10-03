# QuickChat: A Real-Time Chat Application

## Introduction
QuickChat is a real-time chat application built using Flask, Flask-SocketIO, and Flask-Login. It provides user authentication, encrypted messaging, and temporary chat rooms with configurable expiry times. This project is designed for easy setup and use, with a responsive interface and a focus on privacy and security.

## Features
- User authentication with signup and login functionality.
- Real-time messaging using WebSocket connections.
- Encrypted chat messages using Fernet encryption.
- Temporary chat rooms with expiry options (1 minute, 60 minutes, 6 hours, 1 day, 2 days, 1 week).
- Option to clear chat manually or automatically upon room expiry.
- Responsive design with centered forms and adjustable box sizes.

## Encryption
QuickChat ensures message privacy through Fernet symmetric encryption, a part of the `cryptography` library. Each message is encrypted with a secret key stored in the `.env` file (`CHAT_SECRET_KEY`) before transmission and decrypted only for the intended recipient. This key must be kept secure and unique to prevent unauthorized access. The encryption process happens in real-time, providing end-to-end security within active rooms. Users are advised to generate a strong, random key and never share it, enhancing the confidentiality of their conversations.

## User Safety
User safety is a priority in QuickChat:
- **Authentication Security**: Passwords are securely stored using a robust hashing technique during signup, and login verifies credentials safely to protect against unauthorized access.
- **Input Validation**: The signup process enforces strong passwords (minimum 8 characters, including uppercase, lowercase, numbers, and special characters) and restricts email to Gmail addresses, reducing the risk of weak accounts.
- **Rate Limiting**: Flask-Limiter caps login and signup attempts (10 per minute for login, 5 per minute for signup) to prevent brute-force attacks.
- **Security Headers**: Responses include headers like `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a `Content-Security-Policy` to mitigate common web vulnerabilities such as MIME-type sniffing, clickjacking, and XSS.

## Auto-Clear of Messages
QuickChat implements an automatic message-clearing feature to protect user privacy:
- **Expiry Mechanism**: Each room has an expiry time set during creation (e.g., 1 minute to 1 week), stored in `rooms.json` as an ISO-formatted timestamp.
- **Cleanup Thread**: A background thread runs every 60 seconds, checking for expired rooms. When a room's expiry time is reached, all messages and member data are cleared, and a `clear_messages` event is emitted via SocketIO to update all connected clients.
- **Benefits**: This feature ensures that sensitive conversations are automatically deleted after the chosen duration, reducing the risk of data retention and enhancing privacy. Users can also manually clear chats using the "Clear Chat" button.

## Installation
Follow these steps to set up QuickChat:

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/quickchat.git
   cd quickchat
   ```
2. Install required Python packages:
   ```
   pip install -r requirements.txt
   ```
3. Create a `.env` file with the following variables:
   ```
   SECRET_KEY=your-secret-key
   CHAT_SECRET_KEY=your-encryption-key
   ```
4. Run the application:
   ```
   python app.py
   ```

## Usage
To use QuickChat:

- Access the application at `http://localhost:5000`.
- Sign up with a Gmail address or log in with existing credentials.
- Create a new room or join an existing one using a room code.
- Send encrypted messages in real-time; rooms expire based on the selected duration.
- Clear chat manually via the "Clear Chat" button in the room.

## Project Structure
```
quickchat/
├── app.py                # Main Flask application
├── templates/
│   ├── base.html         # Base template
│   ├── home.html         # Home page template
│   ├── login.html        # Login page template
│   ├── signup.html       # Signup page template
│   └── room.html         # Chat room template
├── static/
│   ├── style.css         # Global CSS styles
│   ├── room.js           # WebSocket client logic
│   └── signup.js         # Signup validation
├── users.json            # User data storage
├── rooms.json            # Room data storage
├── requirements.txt      # Python dependencies
└── .env                  # Environment variables (not committed)
```

## Contributing
Contributions are welcome! Please:
- Fork the repository and create a new branch.
- Submit pull requests with detailed descriptions.
- Report issues via GitHub Issues.

## License
MIT License  
Copyright (c) 2025 Bachu Dhyaneswar