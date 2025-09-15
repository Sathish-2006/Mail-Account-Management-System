# Ac## Features

- **Secure Storage**: Passwords are encrypted using Fernet (AES 128) for security
- **User-Friendly Interface**: Clean and intuitive graphical interface built with Tkinter
- **Search Functionality**: Search credentials by email or website
- **Date Tracking**: Automatically tracks creation and modification dates
- **Export Feature**: Export your credentials data to a text file
- **Password Management**: View and copy passwords securely
- **Local Storage**: All data stored locally for maximum privacy

## Files

- `credentials_manager.py` - Main GUI application (start here!)
- `credentials_db.py` - Database backend for storing credentials
- `credentials.db` - SQLite database file (created automatically)
- `encryption.key` - Encryption key file (created automatically)
- `requirements.txt` - Required Python packagesls Management System

A simple and secure account credentials management system built in Python that allows users to store and manage their login credentials for various websites.

## Features

- **Secure Storage**: Passwords are hashed using SHA-256 for security
- **User-Friendly GUI**: Easy-to-use graphical interface built with Tkinter
- **Search Functionality**: Search credentials by email or website
- **Date Tracking**: Automatically tracks creation and modification dates
- **Export Feature**: Export your credentials data to a text file
- **Password Management**: View and copy passwords (with appropriate security measures)

## Files

- `credentials_manager.py` - Main GUI application
- `credentials_db.py` - Database backend for storing credentials
- `test_credentials.py` - Test script to verify functionality
- `credentials.db` - SQLite database file (created automatically)

## How to Use

### 🚀 Quick Start

**Option 1: Use the full virtual environment path**
```bash
.venv/Scripts/python.exe credentials_manager.py
```

**Option 2: Activate virtual environment first**
```bash
.venv\Scripts\Activate.ps1
python credentials_manager.py
```

**Option 3: Install cryptography globally (if you prefer)**
```bash
pip install cryptography
python credentials_manager.py
```

### 1. Run the Application
Open your password manager by running the main application file using one of the methods above.

### 2. Add New Credentials
- Enter your email address
- Enter the website URL or name
- Enter your password
- Click "Add Credential"

### 3. Search Credentials
- Use the search fields to find specific credentials
- Search by email, website, or both
- Click "Search" to filter results
- Click "Show All" to see all credentials

### 4. Edit Credentials
- Select a credential from the list
- Modify the fields as needed
- Click "Update Selected"

### 5. Delete Credentials
- Select a credential from the list
- Click "Delete Selected"
- Confirm the deletion

### 6. Other Features
- **View Password**: Click to see the actual password in a secure popup window
- **Copy Password**: Instantly copy the password to your clipboard
- **Export Data**: Saves all credentials to a text file
- **Clear Fields**: Clears all input fields

## Database Structure

The system stores the following information for each credential:
- **ID**: Unique identifier (auto-generated)
- **Email**: Email address associated with the account
- **Host Website**: Website URL or name
- **Password**: Securely hashed password
- **Date Created**: When the credential was first added
- **Date Modified**: When the credential was last updated

## Security Features

- **Strong Encryption**: Passwords are encrypted using Fernet (AES 128) encryption
- **Key Management**: Encryption keys are automatically generated and stored locally
- **Reversible Security**: Unlike hashing, encryption allows password retrieval when needed
- **Local Storage**: Database and keys are stored locally for maximum privacy
- **Password Visibility**: Passwords can be viewed and copied when needed (the whole point of a password manager!)
- **Secure Display**: Password viewing opens in a separate secure window
