import sqlite3
import os
from config import Config

def init_database():
    """Initialize the SQLite database with required tables"""
    
    # Ensure the instance directory exists
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    
    # Connect to database (creates file if it doesn't exist)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                rsa_public_key TEXT NOT NULL,
                rsa_private_key_encrypted TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                encrypted_aes_key TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id)')
        
        conn.commit()
        print("Database initialized successfully!")
        
        # Print table schemas for verification
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table'")
        schemas = cursor.fetchall()
        print("\nCreated tables:")
        for schema in schemas:
            print(f"- {schema[0]}")
            
    except Exception as e:
        print(f"Error initializing database: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == '__main__':
    init_database()