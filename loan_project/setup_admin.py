import getpass
from app import app, db, Admin, bcrypt

# This script securely creates the database and the admin user.
# It should be run once from the command line.

def create_admin():
    with app.app_context():
        # Drop existing tables if you want a clean slate (optional)
        # db.drop_all()
        db.create_all()

        # Check if admin already exists
        if Admin.query.filter_by(username='admin').first() is not None:
            print("Admin user already exists.")
            return

        print("--- Create PrivyLoans Admin User ---")
        username = "admin" # Hardcoding for simplicity, can be prompted
        password = getpass.getpass(f"Enter password for admin user '{username}': ")

        if not password:
            print("Error: Password cannot be empty.")
            return

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        new_admin = Admin(
            username=username,
            password_hash=hashed_password,
            mfa_enabled=False
        )
        db.session.add(new_admin)
        db.session.commit()
        
        print(f"\nDatabase 'privyloans.db' created.")
        print(f"Admin user '{username}' created successfully.")

if __name__ == '__main__':
    create_admin()