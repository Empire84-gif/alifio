import os
import sqlite3
from config import DATABASE_PATH


def get_connection():
    db_dir = os.path.dirname(DATABASE_PATH)

    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn