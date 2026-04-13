from werkzeug.security import generate_password_hash, check_password_hash
from services.db import get_connection


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)


def get_admin_by_email(email: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admins WHERE email = ?", (email,))
    admin = cursor.fetchone()

    conn.close()
    return admin


def get_admin_by_id(admin_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admins WHERE id = ?", (admin_id,))
    admin = cursor.fetchone()

    conn.close()
    return admin


def update_admin_password(admin_id: int, new_password: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE admins
        SET password_hash = ?
        WHERE id = ?
    """, (
        hash_password(new_password),
        admin_id
    ))

    conn.commit()
    conn.close()


def create_default_admin():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM admins")
    total_admins = cursor.fetchone()["total"]

    if total_admins == 0:
        cursor.execute("""
            INSERT INTO admins (email, password_hash, full_name, is_active)
            VALUES (?, ?, ?, 1)
        """, (
            "admin@example.com",
            hash_password("admin123"),
            "Administrator"
        ))
        conn.commit()

    conn.close()