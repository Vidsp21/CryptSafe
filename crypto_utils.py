import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

class CryptoUtils:
    """Cryptographic utilities for file encryption and key management"""
    
    @staticmethod
    def generate_rsa_keypair():
        """
        Generate RSA public/private key pair
        Returns: (public_key_pem, private_key_pem)
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return public_pem.decode('utf-8'), private_pem.decode('utf-8')
    
    @staticmethod
    def encrypt_private_key(private_key_pem: str, password: str) -> str:
        """
        Encrypt private key with password using AES
        """
        # Convert password to bytes and derive key using PBKDF2
        password_bytes = password.encode('utf-8')
        salt = secrets.token_bytes(16)
        
        # Simple key derivation (in production, use PBKDF2 or scrypt)
        key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
        
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Encrypt private key
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad the private key to be multiple of 16 bytes
        private_key_bytes = private_key_pem.encode('utf-8')
        padding_length = 16 - (len(private_key_bytes) % 16)
        padded_private_key = private_key_bytes + bytes([padding_length] * padding_length)
        
        encrypted = encryptor.update(padded_private_key) + encryptor.finalize()
        
        # Combine salt + iv + encrypted_data and encode as base64
        encrypted_with_metadata = salt + iv + encrypted
        return base64.b64encode(encrypted_with_metadata).decode('utf-8')
    
    @staticmethod
    def decrypt_private_key(encrypted_private_key: str, password: str) -> str:
        """
        Decrypt private key with password
        """
        try:
            # Decode from base64
            encrypted_with_metadata = base64.b64decode(encrypted_private_key.encode('utf-8'))
            
            # Extract components
            salt = encrypted_with_metadata[:16]
            iv = encrypted_with_metadata[16:32]
            encrypted_data = encrypted_with_metadata[32:]
            
            # Derive key using same method
            password_bytes = password.encode('utf-8')
            key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000, 32)
            
            # Decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_private_key = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_private_key[-1]
            private_key_bytes = padded_private_key[:-padding_length]
            
            return private_key_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to decrypt private key: {e}")
    
    @staticmethod
    def generate_aes_key() -> bytes:
        """Generate a random 256-bit AES key"""
        return secrets.token_bytes(32)  # 256 bits
    
    @staticmethod
    def encrypt_file_content(file_content: bytes, aes_key: bytes) -> bytes:
        """
        Encrypt file content using AES-256-CBC
        Returns: IV + encrypted_content
        """
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad content to be multiple of 16 bytes
        padding_length = 16 - (len(file_content) % 16)
        padded_content = file_content + bytes([padding_length] * padding_length)
        
        # Encrypt
        encrypted_content = encryptor.update(padded_content) + encryptor.finalize()
        
        # Return IV + encrypted content
        return iv + encrypted_content
    
    @staticmethod
    def decrypt_file_content(encrypted_content: bytes, aes_key: bytes) -> bytes:
        """
        Decrypt file content using AES-256-CBC
        """
        # Extract IV and encrypted data
        iv = encrypted_content[:16]
        encrypted_data = encrypted_content[16:]
        
        # Create cipher
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_content = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_content[-1]
        original_content = padded_content[:-padding_length]
        
        return original_content
    
    @staticmethod
    def encrypt_aes_key_with_rsa(aes_key: bytes, public_key_pem: str) -> str:
        """
        Encrypt AES key using RSA public key
        """
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # Encrypt AES key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return as base64 string
        return base64.b64encode(encrypted_aes_key).decode('utf-8')
    
    @staticmethod
    def decrypt_aes_key_with_rsa(encrypted_aes_key: str, private_key_pem: str) -> bytes:
        """
        Decrypt AES key using RSA private key
        """
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Decode from base64 and decrypt
        encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key.encode('utf-8'))
        aes_key = private_key.decrypt(
            encrypted_aes_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return aes_key
    
    @staticmethod
    def calculate_sha256(content: bytes) -> str:
        """Calculate SHA-256 hash of content"""
        return hashlib.sha256(content).hexdigest()
    
    @staticmethod
    def verify_file_integrity(file_content: bytes, expected_hash: str) -> bool:
        """Verify file integrity using SHA-256 hash"""
        actual_hash = CryptoUtils.calculate_sha256(file_content)
        return actual_hash == expected_hash