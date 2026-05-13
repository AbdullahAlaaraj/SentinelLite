import sqlite3
import os

os.makedirs("data", exist_ok=True)

conn = sqlite3.connect("data/sentinel.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    rule TEXT,
    severity TEXT,
    source_ip TEXT,
    description TEXT
)
""")

conn.commit()