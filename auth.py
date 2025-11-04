import bcrypt
from functools import wraps
from flask import session, redirect, url_for, flash
from models import Database
from crypto_utils import CryptoUtils

class AuthManager:
    """Authentication utilities for user management"""
    
    def __init__(self):
        self.db = Database()
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    
    def register_user(self, username: str, password: str) -> bool:
        """
        Register a new user with RSA keypair generation
        Returns True if successful, False if username exists
        """
        try:
            # Check if user already exists
            if self.db.get_user_by_username(username):
                return False
            
            # Hash password
            password_hash = self.hash_password(password)
            
            # Generate RSA keypair
            public_key_pem, private_key_pem = CryptoUtils.generate_rsa_keypair()
            
            # Encrypt private key with user's password
            encrypted_private_key = CryptoUtils.encrypt_private_key(private_key_pem, password)
            
            # Create user object
            from models import User
            user = User(
                username=username,
                password_hash=password_hash,
                rsa_public_key=public_key_pem,
                rsa_private_key_encrypted=encrypted_private_key
            )
            
            # Save to database
            return self.db.create_user(user)
            
        except Exception as e:
            print(f"Error registering user: {e}")
            return False
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """
        Authenticate user and create session
        Returns True if successful
        """
        try:
            # Get user from database
            user = self.db.get_user_by_username(username)
            if not user:
                return False
            
            # Verify password
            if not self.verify_password(password, user.password_hash):
                return False
            
            # Create session
            session['user_id'] = user.id
            session['username'] = user.username
            
            # Store decrypted private key in session for this login session
            try:
                private_key_pem = CryptoUtils.decrypt_private_key(
                    user.rsa_private_key_encrypted, 
                    password
                )
                session['private_key'] = private_key_pem
            except Exception as e:
                print(f"Error decrypting private key: {e}")
                return False
            
            return True
            
        except Exception as e:
            print(f"Error authenticating user: {e}")
            return False
    
    def logout_user(self):
        """Clear user session"""
        session.clear()
    
    def get_current_user(self):
        """Get current logged-in user"""
        if 'user_id' in session:
            return self.db.get_user_by_id(session['user_id'])
        return None
    
    @staticmethod
    def login_required(f):
        """Decorator to require login for routes"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function