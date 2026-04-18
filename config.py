import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")

SECRET_KEY = "booking-system-secret-key"

PERMANENT_SESSION_LIFETIME = timedelta(days=30)
PASSWORD_RESET_TOKEN_EXPIRY_MINUTES = 60