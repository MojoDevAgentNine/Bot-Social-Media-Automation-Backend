# create_admin.py

import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.hash import bcrypt
from datetime import datetime

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.user import User, UserRole, Profile
from app.database.database import Base
from dotenv import load_dotenv

load_dotenv()

# Database connection
DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/social_automation"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_admin_user(email: str, password: str, full_name: str, phone: str):
    db = SessionLocal()
    try:
        # Check if admin already exists
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            print(f"User with email {email} already exists!")
            return

        # Create admin user
        password = bcrypt.hash(password)
        admin_user = User(
            email=email,
            password=password,
            full_name=full_name,
            phone=phone,
            role=UserRole.ADMIN,
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        db.add(admin_user)
        db.commit()
        db.refresh(admin_user)

        # Create profile for admin
        admin_profile = Profile(
            user_id=admin_user.id,
            address="",
            city="",
            state="",
            zip_code="",
            country=""
        )

        db.add(admin_profile)
        db.commit()

        print(f"Admin user created successfully!")
        print(f"Email: {email}")
        print(f"Full Name: {full_name}")
        print(f"Role: {admin_user.role}")
        print(f"Phone: {phone}")

    except Exception as e:
        print(f"Error creating admin user: {str(e)}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    # You can either hardcode the values:
    # create_admin_user("admin@example.com", "admin123", "+1234567890")

    # Or use input to get values interactively:
    email = input("Enter admin email: ")
    password = input("Enter admin password: ")
    full_name = input("Enter admin full name: ")
    phone = input("Enter admin phone number: ")

    create_admin_user(email, password, full_name, phone)
