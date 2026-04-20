from services.db import get_connection

conn = get_connection()
cursor = conn.cursor()

cursor.execute("""
    UPDATE clients
    SET business_id = 1
    WHERE business_id IS NULL OR business_id = 0
""")

print("Zmienionych rekordów:", cursor.rowcount)

conn.commit()
conn.close()