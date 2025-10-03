import os
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    CHAT_SECRET_KEY = os.environ.get("CHAT_SECRET_KEY")  # MUST be set to a Fernet key string
    USERS_FILE = os.environ.get("USERS_FILE", "users.json")
    ROOMS_FILE = os.environ.get("ROOMS_FILE", "rooms.json")
