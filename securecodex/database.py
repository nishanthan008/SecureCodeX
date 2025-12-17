import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base

class DatabaseManager:
    """Manages SQLite database for CLI scans"""
    
    def __init__(self, db_path=None):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file. If None, uses temporary database.
        """
        if db_path is None:
            # Use temporary database in current directory
            db_path = ".securecodex_scan.db"
        
        self.db_path = db_path
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        # Create tables
        Base.metadata.create_all(bind=self.engine)
    
    def get_session(self):
        """Get a new database session"""
        return self.SessionLocal()
    
    def cleanup(self, keep_db=False):
        """
        Cleanup database
        
        Args:
            keep_db: If False, delete the database file
        """
        if not keep_db and os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except Exception as e:
                print(f"Warning: Could not delete database file: {e}")
