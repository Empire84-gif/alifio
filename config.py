import os
from datetime import timedelta

# =========================================
# BASE PATH
# =========================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# =========================================
# DATABASE
# =========================================

DATABASE_PATH = os.getenv(
    "DATABASE_PATH",
    os.path.join(BASE_DIR, "database.db")
)

# =========================================
# SECURITY
# =========================================

# Jeśli jest ENV (Render) → użyje go
# Jeśli nie ma (lokalnie) → użyje bezpiecznego fallbacku devowego

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    SECRET_KEY = "dev-secret-key-local-only-change-me"

# =========================================
# SESSION
# =========================================

PERMANENT_SESSION_LIFETIME = timedelta(days=30)

# =========================================
# PASSWORD RESET
# =========================================

PASSWORD_RESET_TOKEN_EXPIRY_MINUTES = 60