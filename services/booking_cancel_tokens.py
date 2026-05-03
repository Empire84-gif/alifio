import secrets
from datetime import datetime

from services.db import get_connection


def create_booking_cancel_token(booking_id, expires_at=None):
    token = secrets.token_urlsafe(32)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO booking_cancel_tokens (
                booking_id,
                token,
                expires_at
            )
            VALUES (?, ?, ?)
            """,
            (
                booking_id,
                token,
                expires_at,
            ),
        )
        conn.commit()
        return token
    finally:
        conn.close()


def get_booking_cancel_token_record(token):
    if not token:
        return None

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT
                bct.id,
                bct.booking_id,
                bct.token,
                bct.expires_at,
                bct.used_at,
                bct.created_at,
                b.id AS booking_id_real,
                b.client_name,
                b.client_email,
                b.client_phone,
                b.booking_date,
                b.booking_time,
                b.status,
                b.service_id,
                b.employee_id
            FROM booking_cancel_tokens bct
            JOIN bookings b
              ON b.id = bct.booking_id
            WHERE bct.token = ?
            LIMIT 1
            """,
            (token,),
        )
        return cursor.fetchone()
    finally:
        conn.close()


def is_booking_cancel_token_valid(token_row):
    if not token_row:
        return False, "missing"

    if token_row["used_at"]:
        return False, "used"

    if token_row["status"] == "cancelled":
        return False, "already_cancelled"

    expires_at = token_row["expires_at"]
    if expires_at:
        try:
            expires_dt = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expires_dt:
                return False, "expired"
        except ValueError:
            return False, "invalid_expiry"

    return True, "ok"


def mark_booking_cancel_token_used(token):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            UPDATE booking_cancel_tokens
            SET used_at = ?
            WHERE token = ?
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                token,
            ),
        )
        conn.commit()
    finally:
        conn.close()