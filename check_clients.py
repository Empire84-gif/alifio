from services.db import get_connection

conn = get_connection()
cursor = conn.cursor()

cursor.execute("""
    SELECT id, business_id, full_name, phone, email
    FROM clients
    ORDER BY id DESC
""")

rows = cursor.fetchall()

print("=== KLIENCI W BAZIE ===")
for row in rows:
    print(dict(row))

conn.close()