# Secure File Storage System

A Flask-based secure file storage system with user authentication, file encryption/decryption, and integrity verification.

## Features

- **User Authentication**: Secure user registration and login with bcrypt password hashing
- **File Encryption**: AES encryption for files with RSA-encrypted keys
- **Integrity Check**: SHA-256 hashing for file integrity verification
- **Database**: SQLite database for user and file metadata storage
- **Security**: No plaintext file storage, encrypted private keys

## Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite
- **Cryptography**: AES (symmetric) + RSA (asymmetric) encryption
- **Authentication**: bcrypt password hashing
- **Frontend**: HTML/CSS with Jinja2 templates

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Initialize the database:
```bash
python init_db.py
```

3. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Project Structure

```
secure-file-storage/
├── app.py                 # Main Flask application
├── models.py             # Database models
├── crypto_utils.py       # Encryption/decryption utilities
├── auth.py              # Authentication utilities
├── init_db.py           # Database initialization
├── requirements.txt     # Python dependencies
├── config.py           # Application configuration
├── templates/          # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── upload.html
│   └── download.html
├── static/            # CSS and JavaScript files
│   └── style.css
├── uploads/           # Encrypted file storage (created automatically)
└── instance/         # SQLite database location (created automatically)
```

## Security Features

1. **Password Security**: Bcrypt hashing with salt
2. **File Encryption**: AES-256 encryption for file contents
3. **Key Security**: RSA encryption for AES keys
4. **Integrity**: SHA-256 checksums for tamper detection
5. **No Plaintext Storage**: All files stored encrypted

## Usage

1. **Register**: Create a new user account
2. **Login**: Authenticate with username/password
3. **Upload**: Select and upload files (automatically encrypted)
4. **Download**: Download and decrypt your files
5. **Dashboard**: View all your uploaded files

## API Endpoints

- `GET /` - Dashboard (requires login)
- `GET /register` - Registration form
- `POST /register` - Process registration
- `GET /login` - Login form
- `POST /login` - Process login
- `GET /logout` - Logout user
- `GET /upload` - Upload form
- `POST /upload` - Process file upload
- `GET /download/<file_id>` - Download and decrypt file

## Security Notes

- Private keys are encrypted with user passwords
- AES keys are generated per file and encrypted with user's RSA public key
- File integrity is verified using SHA-256 checksums
- Session management uses Flask's secure sessions
- All file operations maintain encryption at rest





