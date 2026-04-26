import hashlib
import secrets
from datetime import datetime, timedelta

from services.db import get_connection


ACCOUNT_ACTIVATION_EXPIRY_HOURS = 72


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_account_activation_invite(
    email: str,
    business_name: str,
    business_slug: str,
    role: str = "client_admin",
    created_by_user_id: int | None = None,
    expiry_hours: int = ACCOUNT_ACTIVATION_EXPIRY_HOURS,
) -> str:
    email = (email or "").strip().lower()
    business_name = (business_name or "").strip()
    business_slug = (business_slug or "").strip().lower()
    role = (role or "").strip()

    if not email:
        raise ValueError("Email is required.")

    if not business_name:
        raise ValueError("Business name is required.")

    if not business_slug:
        raise ValueError("Business slug is required.")

    if role not in {"client_admin"}:
        raise ValueError("Invalid invite role.")

    raw_token = secrets.token_urlsafe(48)
    token_hash = _hash_token(raw_token)
    expires_at = datetime.utcnow() + timedelta(hours=expiry_hours)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO account_activation_invites (
                email,
                token_hash,
                business_name,
                business_slug,
                role,
                is_used,
                expires_at,
                created_by_user_id
            )
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)
            """,
            (
                email,
                token_hash,
                business_name,
                business_slug,
                role,
                expires_at.isoformat(),
                created_by_user_id,
            )
        )
        conn.commit()
        return raw_token

    finally:
        conn.close()


def get_valid_account_activation_invite(raw_token: str):
    if not raw_token:
        return None

    token_hash = _hash_token(raw_token)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT *
            FROM account_activation_invites
            WHERE token_hash = ?
              AND is_used = 0
            ORDER BY id DESC
            LIMIT 1
            """,
            (token_hash,)
        )
        invite = cursor.fetchone()

    finally:
        conn.close()

    if not invite:
        return None

    expires_at = datetime.fromisoformat(invite["expires_at"])
    if expires_at < datetime.utcnow():
        return None

    return invite


def mark_account_activation_invite_as_used(invite_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            UPDATE account_activation_invites
            SET
                is_used = 1,
                used_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (invite_id,)
        )
        conn.commit()

    finally:
        conn.close()


def build_activation_link(base_url: str, raw_token: str) -> str:
    base_url = (base_url or "").rstrip("/")
    if not base_url:
        raise ValueError("Base URL is required.")

    return f"{base_url}/activate-account/{raw_token}"


def get_latest_invites(limit: int = 20):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT *
            FROM account_activation_invites
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        return cursor.fetchall()

    finally:
        conn.close()