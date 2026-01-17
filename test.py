import sqlite3

SCHEMA = '''
CREATE TABLE IF NOT EXISTS test_table (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT
);
'''

conn = sqlite3.connect("data.db")
conn.executescript(SCHEMA)
conn.close()