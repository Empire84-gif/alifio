from werkzeug.security import generate_password_hash
from services.db import get_connection

EMAIL = "k.handke@o2.pl"
PASSWORD = "handke300"
FULL_NAME = "Administrator"

def create_admin():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM admins WHERE email = ?", (EMAIL,))
    existing = cursor.fetchone()

    if existing:
        print("Admin z tym adresem e-mail już istnieje.")
        conn.close()
        return

    password_hash = generate_password_hash(PASSWORD)

    cursor.execute("""
        INSERT INTO admins (email, password_hash, full_name, is_active)
        VALUES (?, ?, ?, 1)
    """, (EMAIL, password_hash, FULL_NAME))

    conn.commit()
    conn.close()

    print("Admin został utworzony.")

if __name__ == "__main__":
    create_admin()