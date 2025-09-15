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
C:/Users/sathi/Account-management-system/.venv/Scripts/python.exe credentials_manager.py
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

## Testing

Run the test script to verify the system works correctly:
```bash
python test_credentials.py
```

This will:
- Add sample credentials
- Test search functionality
- Display all stored credentials
- Verify database operations

## Installation

1. **Clone or download** this repository to your computer
2. **Navigate** to the project directory
3. **Install dependencies** using one of these methods:

### Method 1: Using Virtual Environment (Recommended)
```bash
# The virtual environment is already set up in .venv/
# Install cryptography in the virtual environment
C:/Users/sathi/Account-management-system/.venv/Scripts/python.exe -m pip install cryptography
```

### Method 2: Install Globally
```bash
pip install -r requirements.txt
```

### Method 3: Manual Installation
```bash
pip install cryptography
```

## Requirements

- Python 3.x
- tkinter (usually included with Python)
- sqlite3 (included with Python)
- cryptography (install using methods above)

### Quick Install Dependencies
```bash
pip install -r requirements.txt
```

## Installation

1. Download all the Python files to a folder
2. Run `python credentials_manager.py`
3. The database will be created automatically on first run

## Troubleshooting

### ❌ Common Error: "ModuleNotFoundError: No module named 'cryptography'"

**Problem:** The cryptography package is not installed in the Python environment you're using.

**Solutions:**

1. **Use the virtual environment** (Recommended):
   ```bash
   C:/Users/sathi/Account-management-system/.venv/Scripts/python.exe credentials_manager.py
   ```

2. **Activate virtual environment first**:
   ```bash
   .venv\Scripts\Activate.ps1
   python credentials_manager.py
   ```

3. **Install cryptography globally**:
   ```bash
   pip install cryptography
   python credentials_manager.py
   ```

4. **Install in virtual environment**:
   ```bash
   C:/Users/sathi/Account-management-system/.venv/Scripts/python.exe -m pip install cryptography
   ```

### ✅ Success Indicators
- Application opens without errors
- You can add, view, and copy passwords
- Database file (`credentials.db`) is created automatically
- Encryption key file (`encryption.key`) is created automatically

## Usage Tips

1. **Backup**: Regularly backup your `credentials.db` and `encryption.key` files
2. **Security**: Keep your `encryption.key` file safe - without it, your passwords cannot be decrypted
3. **Updates**: Always update credentials when you change passwords on websites
4. **Organization**: Use consistent website naming for easier searching

## Future Enhancements

- Master password protection
- Password strength checker
- Automatic password generation
- Browser integration
- Two-factor authentication support

## License

This project is open source and available under the MIT License.