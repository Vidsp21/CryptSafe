# Secure File Storage System - Usage Guide

## 🔐 How the Encryption Works

### Overview
This system implements a **hybrid encryption scheme** combining the speed of symmetric encryption (AES) with the security of asymmetric encryption (RSA).

### Encryption Flow

1. **User Registration**:
   - Password is hashed using bcrypt with salt
   - RSA-2048 key pair is generated (public/private)
   - Private key is encrypted with user's password using AES
   - Only encrypted data is stored in database

2. **File Upload Process**:
   ```
   Original File → AES-256 Encryption → Encrypted File Storage
                         ↓
   Random AES Key → RSA Encryption (User's Public Key) → Database Storage
                         ↓
   SHA-256 Hash → Database Storage (Integrity Verification)
   ```

3. **File Download Process**:
   ```
   User Login → Decrypt Private Key (with password)
                         ↓
   Encrypted AES Key → RSA Decryption (Private Key) → AES Key
                         ↓
   Encrypted File → AES Decryption (AES Key) → Original File
                         ↓
   SHA-256 Verification → Integrity Check
   ```

## 🚀 Getting Started

### 1. Start the Application
```bash
cd "c:\Users\HP\Documents\new project"
python app.py
```

### 2. Open Your Browser
Navigate to: `http://127.0.0.1:5000`

### 3. Create Account
- Click "Register"
- Choose a username (minimum 3 characters)
- Create a strong password (minimum 6 characters)
- **Important**: Remember your password - there's no recovery option by design

### 4. Upload Files
- Click "Upload New File"
- Drag and drop or select your file
- File is automatically encrypted before upload
- Maximum file size: 16MB

### 5. Download Files
- Click "Download" next to any file
- File is automatically decrypted using your private key
- Integrity is verified using SHA-256 hash

## 🔒 Security Features

### Encryption Details
- **File Encryption**: AES-256-CBC with random IV
- **Key Encryption**: RSA-2048 with OAEP padding
- **Password Hashing**: bcrypt with salt (cost factor 12)
- **Integrity**: SHA-256 cryptographic hash

### Security Benefits
- **Zero-Knowledge**: Server never sees plaintext files
- **Forward Secrecy**: Each file uses unique AES key
- **Tamper Detection**: SHA-256 integrity verification
- **Secure Storage**: No plaintext passwords or keys

### Key Security Practices
- Private keys are encrypted with user passwords
- AES keys are unique per file and RSA-encrypted
- Session management with secure cookies
- Input validation and sanitization

## 📁 File Management

### Supported Operations
- **Upload**: Encrypt and store files securely
- **Download**: Decrypt and retrieve files with integrity check
- **Delete**: Remove files and cleanup storage
- **View**: List all your encrypted files with metadata

### File Information Displayed
- Original filename
- File size
- Upload date
- Encryption status
- Integrity verification status

## ⚠️ Important Security Notes

### Password Security
- **No Password Recovery**: By design, forgotten passwords cannot be recovered
- **Strong Passwords**: Use complex passwords with mixed characters
- **Unique Passwords**: Don't reuse passwords from other services

### Data Protection
- **Local Storage**: Files stored on local server only
- **No Plaintext**: All files encrypted before storage
- **Session Security**: Login required for all operations
- **Access Control**: Users can only access their own files

## 🔧 Technical Architecture

### Database Schema
```sql
-- Users table
users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,           -- bcrypt hashed
    rsa_public_key TEXT,          -- PEM format
    rsa_private_key_encrypted TEXT -- AES encrypted with password
)

-- Files table  
files (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    original_filename TEXT,
    stored_filename TEXT,         -- UUID + .enc extension
    encrypted_aes_key TEXT,       -- RSA encrypted AES key
    sha256_hash TEXT,            -- For integrity verification
    file_size INTEGER            -- Original file size
)
```

### File Storage
- **Location**: `uploads/` directory
- **Naming**: UUID-based filenames with `.enc` extension
- **Content**: AES-256 encrypted file data with IV
- **Access**: Only through application, not direct file access

## 🛠️ Development Setup

### Requirements
- Python 3.7+
- Flask 2.3.3
- cryptography 41.0.7
- bcrypt 4.1.2
- werkzeug 2.3.7

### Installation
```bash
pip install -r requirements.txt
python init_db.py
python app.py
```

### Project Structure
```
secure-file-storage/
├── app.py              # Main Flask application
├── models.py           # Database models and operations
├── crypto_utils.py     # Cryptographic functions
├── auth.py            # Authentication management
├── config.py          # Application configuration
├── init_db.py         # Database initialization
├── requirements.txt   # Dependencies
├── templates/         # HTML templates
├── static/           # CSS styles
├── uploads/          # Encrypted file storage
└── instance/         # SQLite database
```

## 🔍 Troubleshooting

### Common Issues

**Login Problems**:
- Verify username and password are correct
- Check if user account exists
- Ensure password meets minimum requirements

**Upload Failures**:
- Check file size (max 16MB)
- Ensure sufficient disk space
- Verify user is logged in

**Download Issues**:
- Confirm file ownership
- Check if file exists on server
- Verify user session is active

**Encryption Errors**:
- Restart application
- Clear browser cache/cookies
- Re-login to refresh keys

### Security Warnings
- **Development Server**: Current setup uses Flask dev server
- **HTTPS**: Enable HTTPS in production
- **Key Backup**: No key recovery mechanism exists
- **Session Timeout**: Consider implementing session timeouts

## 📈 Future Enhancements

### Potential Features
- File sharing between users
- JWT-based API authentication
- Key rotation mechanisms
- File versioning
- Audit logging
- Multi-factor authentication
- Progressive file upload
- File type restrictions
- Virus scanning integration

### Production Considerations
- WSGI server deployment (gunicorn, uWSGI)
- PostgreSQL/MySQL database
- Redis session storage
- Load balancing
- SSL/TLS certificates
- Rate limiting
- Monitoring and logging
- Backup strategies

## 📞 Support

For technical issues or questions:
1. Check this documentation
2. Review error messages in browser console
3. Check application logs
4. Verify system requirements

Remember: This is a demonstration system. For production use, additional security hardening and deployment considerations are necessary.