import secrets
from datetime import datetime, timedelta

from config import PASSWORD_RESET_TOKEN_EXPIRY_MINUTES
from services.db import get_connection


def create_password_reset_token(admin_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRY_MINUTES)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO password_reset_tokens (admin_id, token, expires_at, used)
        VALUES (?, ?, ?, 0)
    """, (
        admin_id,
        token,
        expires_at.isoformat()
    ))

    conn.commit()
    conn.close()

    return token


def get_valid_reset_token(token: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM password_reset_tokens
        WHERE token = ? AND used = 0
        ORDER BY id DESC
        LIMIT 1
    """, (token,))
    token_row = cursor.fetchone()

    conn.close()

    if not token_row:
        return None

    expires_at = datetime.fromisoformat(token_row["expires_at"])
    if expires_at < datetime.utcnow():
        return None

    return token_row


def mark_token_as_used(token_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE password_reset_tokens
        SET used = 1
        WHERE id = ?
    """, (token_id,))

    conn.commit()
    conn.close()