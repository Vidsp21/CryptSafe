import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import tempfile
from io import BytesIO

from config import Config
from models import Database, FileRecord
from auth import AuthManager
from crypto_utils import CryptoUtils

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize components
db = Database()
auth_manager = AuthManager()

@app.route('/')
def dashboard():
    """Main dashboard - shows user's files"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_files = db.get_user_files(session['user_id'])
    return render_template('dashboard.html', files=user_files)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('register.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        # Attempt registration
        if auth_manager.register_user(username, password):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose another.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')
        
        if auth_manager.authenticate_user(username, password):
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    auth_manager.logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@auth_manager.login_required
def upload_file():
    """File upload with encryption"""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return render_template('upload.html')
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'error')
            return render_template('upload.html')
        
        try:
            # Read file content
            file_content = file.read()
            if not file_content:
                flash('File is empty.', 'error')
                return render_template('upload.html')
            
            # Get current user
            user = auth_manager.get_current_user()
            if not user:
                flash('User session invalid.', 'error')
                return redirect(url_for('login'))
            
            # Generate AES key for this file
            aes_key = CryptoUtils.generate_aes_key()
            
            # Encrypt file content
            encrypted_content = CryptoUtils.encrypt_file_content(file_content, aes_key)
            
            # Encrypt AES key with user's RSA public key
            encrypted_aes_key = CryptoUtils.encrypt_aes_key_with_rsa(aes_key, user.rsa_public_key)
            
            # Calculate SHA-256 hash of original file for integrity check
            file_hash = CryptoUtils.calculate_sha256(file_content)
            
            # Generate unique filename for storage
            file_extension = os.path.splitext(secure_filename(file.filename))[1]
            stored_filename = str(uuid.uuid4()) + '.enc'  # All encrypted files get .enc extension
            stored_path = os.path.join(Config.UPLOAD_FOLDER, stored_filename)
            
            # Save encrypted file
            with open(stored_path, 'wb') as f:
                f.write(encrypted_content)
            
            # Create file record in database
            file_record = FileRecord(
                user_id=user.id,
                original_filename=secure_filename(file.filename),
                stored_filename=stored_filename,
                encrypted_aes_key=encrypted_aes_key,
                sha256_hash=file_hash,
                file_size=len(file_content)
            )
            
            file_id = db.create_file_record(file_record)
            if file_id:
                flash(f'File "{file.filename}" uploaded and encrypted successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Clean up if database insert failed
                if os.path.exists(stored_path):
                    os.remove(stored_path)
                flash('Failed to save file record. Please try again.', 'error')
        
        except RequestEntityTooLarge:
            flash('File too large. Maximum size is 16MB.', 'error')
        except Exception as e:
            flash(f'Error uploading file: {str(e)}', 'error')
            print(f"Upload error: {e}")
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
@auth_manager.login_required
def download_file(file_id):
    """File download with decryption"""
    try:
        # Get file record (only if it belongs to current user)
        file_record = db.get_file_by_id(file_id, session['user_id'])
        if not file_record:
            flash('File not found or access denied.', 'error')
            return redirect(url_for('dashboard'))
        
        # Check if encrypted file exists
        stored_path = os.path.join(Config.UPLOAD_FOLDER, file_record.stored_filename)
        if not os.path.exists(stored_path):
            flash('File not found on server.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get user's private key from session
        private_key_pem = session.get('private_key')
        if not private_key_pem:
            flash('Private key not available. Please log in again.', 'error')
            return redirect(url_for('login'))
        
        # Read encrypted file
        with open(stored_path, 'rb') as f:
            encrypted_content = f.read()
        
        # Decrypt AES key using user's RSA private key
        aes_key = CryptoUtils.decrypt_aes_key_with_rsa(
            file_record.encrypted_aes_key, 
            private_key_pem
        )
        
        # Decrypt file content
        decrypted_content = CryptoUtils.decrypt_file_content(encrypted_content, aes_key)
        
        # Verify file integrity
        if not CryptoUtils.verify_file_integrity(decrypted_content, file_record.sha256_hash):
            flash('File integrity check failed. File may be corrupted.', 'error')
            return redirect(url_for('dashboard'))
        
        # Create a BytesIO object to serve the file
        file_data = BytesIO(decrypted_content)
        file_data.seek(0)
        
        # Return file for download
        return send_file(
            file_data,
            as_attachment=True,
            download_name=file_record.original_filename,
            mimetype='application/octet-stream'
        )
    
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        print(f"Download error: {e}")
        return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>', methods=['POST'])
@auth_manager.login_required
def delete_file(file_id):
    """Delete a file"""
    try:
        # Get file record to get stored filename
        file_record = db.get_file_by_id(file_id, session['user_id'])
        if not file_record:
            flash('File not found or access denied.', 'error')
            return redirect(url_for('dashboard'))
        
        # Delete from database
        if db.delete_file_record(file_id, session['user_id']):
            # Delete physical file
            stored_path = os.path.join(Config.UPLOAD_FOLDER, file_record.stored_filename)
            if os.path.exists(stored_path):
                os.remove(stored_path)
            
            flash(f'File "{file_record.original_filename}" deleted successfully.', 'success')
        else:
            flash('Failed to delete file.', 'error')
    
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'error')
        print(f"Delete error: {e}")
    
    return redirect(url_for('dashboard'))

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(url_for('upload_file'))

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Ensure uploads directory exists
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)