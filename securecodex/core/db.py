
import sqlite3
import os

class ScanDB:
    """
    Persistent storage for incremental scan hashes and findings metadata.
    Uses SQLite for efficiency in CI/CD environments.
    """
    
    def __init__(self, db_path: str = ".securecodex.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_hashes (
                    file_path TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.commit()

    def get_hash(self, file_path: str) -> str:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT sha256 FROM file_hashes WHERE file_path = ?", (file_path,))
            row = cursor.fetchone()
            return row[0] if row else None

    def update_hash(self, file_path: str, sha256: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO file_hashes (file_path, sha256, last_scanned)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """, (file_path, sha256))
            conn.commit()

    def clear(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM file_hashes")
                conn.execute("DELETE FROM scan_meta")
                conn.commit()
        except Exception as e:
            print(f"Error clearing database tables: {e}")
            if os.path.exists(self.db_path):
                try:
                    os.remove(self.db_path)
                except:
                    pass
            self._init_db()
