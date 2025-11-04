import sqlite3
from dataclasses import dataclass
from typing import List, Optional
from config import Config

@dataclass
class User:
    """User model for database operations"""
    id: Optional[int] = None
    username: str = ""
    password_hash: str = ""
    rsa_public_key: str = ""
    rsa_private_key_encrypted: str = ""
    created_at: Optional[str] = None

@dataclass
class FileRecord:
    """File record model for database operations"""
    id: Optional[int] = None
    user_id: int = 0
    original_filename: str = ""
    stored_filename: str = ""
    encrypted_aes_key: str = ""
    sha256_hash: str = ""
    file_size: int = 0
    upload_date: Optional[str] = None

class Database:
    """Database operations for the secure file storage system"""
    
    def __init__(self):
        self.db_path = Config.DATABASE_PATH
    
    def get_connection(self):
        """Get a database connection with row factory"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    # User operations
    def create_user(self, user: User) -> bool:
        """Create a new user in the database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, password_hash, rsa_public_key, rsa_private_key_encrypted)
                    VALUES (?, ?, ?, ?)
                ''', (user.username, user.password_hash, user.rsa_public_key, user.rsa_private_key_encrypted))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False  # Username already exists
        except Exception as e:
            print(f"Error creating user: {e}")
            return False
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
                row = cursor.fetchone()
                if row:
                    return User(
                        id=row['id'],
                        username=row['username'],
                        password_hash=row['password_hash'],
                        rsa_public_key=row['rsa_public_key'],
                        rsa_private_key_encrypted=row['rsa_private_key_encrypted'],
                        created_at=row['created_at']
                    )
                return None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
                row = cursor.fetchone()
                if row:
                    return User(
                        id=row['id'],
                        username=row['username'],
                        password_hash=row['password_hash'],
                        rsa_public_key=row['rsa_public_key'],
                        rsa_private_key_encrypted=row['rsa_private_key_encrypted'],
                        created_at=row['created_at']
                    )
                return None
        except Exception as e:
            print(f"Error getting user by ID: {e}")
            return None
    
    # File operations
    def create_file_record(self, file_record: FileRecord) -> Optional[int]:
        """Create a new file record and return the file ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO files (user_id, original_filename, stored_filename, 
                                     encrypted_aes_key, sha256_hash, file_size)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (file_record.user_id, file_record.original_filename, file_record.stored_filename,
                      file_record.encrypted_aes_key, file_record.sha256_hash, file_record.file_size))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            print(f"Error creating file record: {e}")
            return None
    
    def get_user_files(self, user_id: int) -> List[FileRecord]:
        """Get all files for a specific user"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM files WHERE user_id = ? 
                    ORDER BY upload_date DESC
                ''', (user_id,))
                rows = cursor.fetchall()
                return [FileRecord(
                    id=row['id'],
                    user_id=row['user_id'],
                    original_filename=row['original_filename'],
                    stored_filename=row['stored_filename'],
                    encrypted_aes_key=row['encrypted_aes_key'],
                    sha256_hash=row['sha256_hash'],
                    file_size=row['file_size'],
                    upload_date=row['upload_date']
                ) for row in rows]
        except Exception as e:
            print(f"Error getting user files: {e}")
            return []
    
    def get_file_by_id(self, file_id: int, user_id: int) -> Optional[FileRecord]:
        """Get a specific file by ID (only if it belongs to the user)"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM files WHERE id = ? AND user_id = ?
                ''', (file_id, user_id))
                row = cursor.fetchone()
                if row:
                    return FileRecord(
                        id=row['id'],
                        user_id=row['user_id'],
                        original_filename=row['original_filename'],
                        stored_filename=row['stored_filename'],
                        encrypted_aes_key=row['encrypted_aes_key'],
                        sha256_hash=row['sha256_hash'],
                        file_size=row['file_size'],
                        upload_date=row['upload_date']
                    )
                return None
        except Exception as e:
            print(f"Error getting file by ID: {e}")
            return None
    
    def delete_file_record(self, file_id: int, user_id: int) -> bool:
        """Delete a file record (only if it belongs to the user)"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM files WHERE id = ? AND user_id = ?
                ''', (file_id, user_id))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error deleting file record: {e}")
            return False