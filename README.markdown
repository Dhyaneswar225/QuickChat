# QUICKCHAT

**QUICKCHAT** is a real-time chat application built with **Flask** and **Flask-SocketIO**. Users can sign up, log in, create or join chat rooms, send messages in real-time, and clear their own chat messages without affecting others. The app uses JSON files for message and user persistence and provides a simple, responsive web-based interface. It is deployed on Render with GitHub integration for seamless updates.

## Features

- ✅ User authentication (Sign up & Login)  
- ✅ Create and join chat rooms with unique room codes  
- ✅ Real-time messaging powered by **Socket.IO**  
- ✅ Clear chat functionality (per user, client-side)  
- ✅ Responsive UI with simple styling  
- ✅ Easy to run locally or deploy for free on Render  
- ✅ Message and user persistence using JSON files (no database)

## Requirements

- Python 3.8+  
- Flask  
- Flask-Login  
- Flask-SocketIO  
- eventlet  
- Werkzeug  

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/quickchat.git
   cd quickchat
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # Mac/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Running the App Locally

1. **Start the Flask app**:
   ```bash
   python app.py
   ```

2. **Open your browser** at:
   ```
   http://127.0.0.1:5000
   ```

3. **(Optional) Share your local app using ngrok**:
   - Install ngrok: `npm install -g ngrok` or download from [ngrok.com](https://ngrok.com).
   - Run:
     ```bash
     ngrok http 5000
     ```
   - Copy the generated public URL (e.g., `https://abc123.ngrok.io`) to share with others for joining rooms and chatting.

## Usage

1. **Sign up** with a unique username and password.
2. **Log in** to access the home page.
3. **Create a room** to generate a unique room code, or **join an existing room** using a room code.
4. **Send messages** in real-time; messages are saved to `rooms.json`.
5. **Clear chat**: Click the "Clear Chat" button to clear messages from your view (client-side, does not affect other users or `rooms.json`).
6. **Log out** to end your session.

## File Structure

```
quickchat/
│
├── app.py              # Main Flask app with SocketIO and routes
├── templates/          # HTML templates for the web interface
│   ├── base.html       # Base layout
│   ├── login.html      # Login page
│   ├── signup.html     # Signup page
│   ├── home.html       # Home page for creating/joining rooms
│   └── room.html       # Chat room interface
├── static/
│   └── style.css       # CSS styling
├── users.json          # User data (persistent usernames/passwords)
├── rooms.json          # Room and message data
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Dependencies

Add the following to `requirements.txt`:

```
Flask==3.0.3
Flask-Login==0.6.3
Flask-SocketIO==5.3.6
eventlet==0.36.1
Werkzeug==3.0.4
```

Install with:
```bash
pip install -r requirements.txt
```

## Deployment on Render with GitHub Integration

QUICKCHAT is deployed on Render, a free hosting platform that supports WebSockets and Python, with automatic deploys from a connected GitHub repository. To replicate or update the deployment:

1. **Push your code to GitHub**:
   - Initialize Git: `git init`, `git add .`, `git commit -m "Initial commit"`.
   - Create a repo on GitHub and push: `git remote add origin https://github.com/yourusername/quickchat.git`, `git push -u origin main`.

2. **Create a Render account**:
   - Sign up at [render.com](https://render.com) and connect your GitHub account.

3. **Deploy a Web Service**:
   - In Render dashboard, click "New" → "Web Service".
   - Select your `quickchat` repo from GitHub.
   - Configure:
     - **Name**: `quickchat-app`
     - **Environment**: Python
     - **Region**: Closest to you (e.g., Oregon)
     - **Branch**: `main`
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `python app.py`
     - **Instance Type**: Free
   - Add environment variable: `SECRET_KEY` (generate with `python -c 'import secrets; print(secrets.token_hex(16))'`).
   - Click "Create Web Service".

4. **GitHub Integration**:
   - The app is linked to your GitHub repo, enabling automatic deploys on `git push`.
   - To update, push changes to your GitHub repo’s `main` branch, and Render rebuilds automatically.

5. **Access**: Once deployed (2-5 minutes), use the provided URL (e.g., `https://quickchat-app.onrender.com`).

**Note**: The free tier sleeps after 15 minutes of inactivity (wakes on request) and resets JSON files (`rooms.json`, `users.json`) on deploys/restarts. For persistent storage, consider client-side solutions or a paid tier.

## License

This project is licensed under the [MIT License](LICENSE).
