import os
from time import perf_counter

import jwt
from passlib.hash import bcrypt
from sqlalchemy.orm import Session
from starlette import status

from app.models.user import User, UserRole, Profile
from app.schemas.user_schema import UserRegisterRequest
from datetime import datetime, timedelta
from fastapi import HTTPException
from app.axiom_logger.authentication import logger
from app.utils.redis import redis_client
from typing import Optional
from multidb_request_handler import DatabaseOperation
import random
import string


class VerificationService:
    def __init__(self):
        self.users_db = DatabaseOperation(
            host='http://127.0.0.1',
            port='44777',
            database_name='social_automation',
            table_name='users',
            username='postgres',
            password='postgres'
        )

        self.verification_db = DatabaseOperation(
            host='http://127.0.0.1',
            port='44777',
            database_name='social_automation',
            table_name='email_verification_codes',
            username='postgres',
            password='postgres'
        )

    def generate_code(self, length: int = 6) -> str:
        """Generate a random verification code"""
        return ''.join(random.choices(string.digits, k=length))

    def create_verification_code(self, user_id: int) -> str:
        """Create a new verification code"""
        code = self.generate_code()
        expires_at = (datetime.utcnow() + timedelta(minutes=10)).isoformat()

        verification_data = {
            "user_id": user_id,
            "code": code,
            "expires_at": expires_at,
            "is_used": False
        }

        status_code, response = self.verification_db.post_request(
            "create",
            data=verification_data
        )

        if status_code != 201:
            raise HTTPException(status_code=500, detail="Failed to create verification code")

        return code

    def verify_code(self, email: str, code: str) -> Optional[dict]:
        """Verify the code and return user if valid"""
        # Get user
        status_code, users = self.users_db.post_request(f"get?email__like={email}")
        if status_code != 200 or not users:
            raise HTTPException(status_code=404, detail="User not found")

        user = users[0]
        # Get verification code
        current_time = datetime.utcnow().isoformat()
        print(current_time)

        status_code, verifications = self.verification_db.post_request(
            f"get?user_id__eq={user['id']}"
            f"&code__eq={code}"
            f"&is_used__eq=false"
        )
        print(status_code, verifications)

        if status_code != 200 or not verifications:
            return None

        # Mark code as used
        verification = verifications[-1]
        print(verification)
        if current_time > verification['expires_at'] :
            raise HTTPException(status_code=400, detail="Verification code has expired")

        if verification['is_used']:
            raise HTTPException(status_code=400, detail="Verification code has already been used")

        if verification['code'] != code:
            raise HTTPException(status_code=400, detail="Invalid verification code")

        status_code, _ = self.verification_db.patch_request(
            f"update/{verification['id']}",
            data={"is_used": True}
        )

        if status_code != 202:
            raise HTTPException(status_code=500, detail="Failed to update verification code")

        return user


# def register_user(db: Session, user: UserRegisterRequest, current_user: User = None):
#     # Check if the user already exists
#     existing_user = db.query(User).filter(User.email == user.email).first()
#     if existing_user:
#         raise ValueError("Email already in use.")
#
#     # Validate role assignment permissions
#     if current_user:
#         # Only super_admin can create admin users
#         if user.role == UserRole.ADMIN and current_user.role != UserRole.SUPER_ADMIN:
#             logger.critical(f"Email: {current_user.email}, Role: {current_user.role} - Only super admins can create admin users")
#             raise HTTPException(
#                 status_code=403,
#                 detail="Only super admins can create admin users"
#             )
#
#         # Only super_admin can create other super_admin users
#         if user.role == UserRole.SUPER_ADMIN and current_user.role != UserRole.SUPER_ADMIN:
#             logger.critical(f"Email: {current_user.email}, Role: {current_user.role} - Only super admins can create super admin users")
#             raise HTTPException(
#                 status_code=403,
#                 detail="Only super admins can create super admin users"
#             )
#
#     # Hash the password
#     password = bcrypt.hash(user.password)
#
#     # Create a new user
#     new_user = User(
#         email=user.email,
#         password=password,
#         full_name=user.full_name,
#         phone=user.phone,
#         role=user.role,  # Set the role from the request
#         is_active=True,
#         created_at=datetime.utcnow(),
#         updated_at=datetime.utcnow(),
#     )
#
#     db.add(new_user)
#     db.commit()
#     db.refresh(new_user)
#
#     # Create an initial profile for the user
#     initial_profile = Profile(
#         user_id=new_user.id,
#         address="",
#         city="",
#         state="",
#         zip_code="",
#         country=""
#     )
#
#     db.add(initial_profile)
#     db.commit()
#     db.refresh(initial_profile)
#     redis_client.delete("all_users")
#     return new_user

async def register_user(user: UserRegisterRequest, current_user: dict = None):
    try:
        # Initialize database connections
        users_db = DatabaseOperation(
            host='http://127.0.0.1',
            port='44777',
            database_name='social_automation',
            table_name='users',
            username='postgres',
            password='postgres'
        )

        profiles_db = DatabaseOperation(
            host='http://127.0.0.1',
            port='44777',
            database_name='social_automation',
            table_name='profiles',
            username='postgres',
            password='postgres'
        )

        # Check if the user already exists
        status_code, existing_users = users_db.post_request(f"get?email__like={user.email}")
        if status_code == 200 and existing_users:
            raise ValueError("Email already in use.")

        # Validate role assignment permissions
        if current_user:
            # Only super_admin can create admin users
            if user.role == "admin" and current_user['role'] != "super_admin":
                logger.critical(
                    f"Email: {current_user['email']}, Role: {current_user['role']} - Only super admins can create admin users")
                raise HTTPException(
                    status_code=403,
                    detail="Only super admins can create admin users"
                )

            # Only super_admin can create other super_admin users
            if user.role == "super_admin" and current_user['role'] != "super_admin":
                logger.critical(
                    f"Email: {current_user['email']}, Role: {current_user['role']} - Only super admins can create super admin users")
                raise HTTPException(
                    status_code=403,
                    detail="Only super admins can create super admin users"
                )

        # Hash the password
        hashed_password = bcrypt.hash(user.password)

        # Prepare user data
        new_user_data = {
            "email": user.email,
            "password": hashed_password,
            "full_name": user.full_name,
            "phone": user.phone,
            "role": user.role,
            "is_active": True,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }

        # Create user
        status_code, created_user = users_db.post_request(
            "create",
            data=new_user_data
        )

        if status_code != 201:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )

        created_user = created_user[0]
        # Create initial profile
        initial_profile_data = {
            "user_id": created_user['id'],
            "address": "",
            "city": "",
            "state": "",
            "zip_code": "",
            "country": ""
        }

        status_code, created_profile = profiles_db.post_request(
            "create",
            data=initial_profile_data
        )

        if status_code != 201:
            # Rollback user creation by deleting the user
            users_db.post_request(f"delete/{created_user['id']}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user profile"
            )

        # Clear cache if using Redis
        try:
            if redis_client:
                redis_client.delete("all_users")
        except Exception as e:
            logger.warning(f"Failed to clear Redis cache: {str(e)}")

        return created_user

    except ValueError as e:
        raise e
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error registering user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register user"
        )




def login_user2(email: str, password: str):
    print("aisi")
    db = DatabaseOperation(
        host='http://127.0.0.1',
        port='44777',
        database_name='social_automation',
        table_name='users',
        username='postgres',
        password='postgres'
    )
    status_code, users = db.post_request(f"get?email__like={email}")

    if status_code != 200 or not users:
        return None

    user = users[0]  # Get the first user that matches

    # Verify password
    if not bcrypt.verify(password, user['password']):
        return None

    return user






def verify_token(token: str):
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        logger.info(f"User ID: {payload.get('user_id')} User Email: {payload.get('email')} - Token verified")
        return payload.get("user_id")  # Return the user ID from the payload
    except jwt.PyJWTError:
        logger.error("Invalid or expired token")
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# First, create the base DatabaseService class
class DatabaseService:
    def __init__(self):
        self.base_config = {
            'host': 'http://127.0.0.1',
            'port': '44777',
            'database_name': 'social_automation',
            'username': 'postgres',
            'password': 'postgres'
        }

    def get_db(self, table_name: str) -> DatabaseOperation:
        return DatabaseOperation(
            **self.base_config,
            table_name=table_name
        )

# Then modify the ProfileService to inherit from DatabaseService
class ProfileService(DatabaseService):
    def __init__(self):
        super().__init__()
        self.users_db = self.get_db('users')
        self.profiles_db = self.get_db('profiles')

    async def update_profile(self, current_user: dict, profile_data: dict):
        try:
            updates_made = False

            # Get existing profile
            status_code, profiles = self.profiles_db.post_request(
                f"get?user_id__eq={current_user['id']}"
            )

            # Initialize existing_profile
            existing_profile = {
                "address": "",
                "city": "",
                "state": "",
                "zip_code": "",
                "country": ""
            }

            # Update existing_profile if found
            if status_code == 200 and profiles and len(profiles) > 0:
                existing_profile.update(profiles[0])

            # Handle full_name update in user table
            if 'full_name' in profile_data and profile_data['full_name'] != current_user.get('full_name'):
                status_code, response = self.users_db.patch_request(
                    f"update/{current_user['id']}",
                    data={"full_name": profile_data['full_name']}
                )
                if status_code != 202:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to update user name"
                    )
                updates_made = True
                current_user['full_name'] = profile_data['full_name']

            # Handle profile updates
            profile_updates = {}
            profile_fields = ['address', 'city', 'state', 'zip_code', 'country']

            for field in profile_fields:
                if field in profile_data and profile_data[field] != existing_profile.get(field):
                    profile_updates[field] = profile_data[field]

            if profile_updates:
                if 'id' in existing_profile:
                    # Update existing profile
                    status_code, response = self.profiles_db.patch_request(
                        f"update/{existing_profile['id']}",
                        data=profile_updates
                    )
                    if status_code != 202:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to update profile"
                        )
                else:
                    # Create new profile
                    new_profile_data = {
                        "user_id": current_user['id'],
                        **profile_updates
                    }
                    status_code, response = self.profiles_db.post_request(
                        "create",
                        json=new_profile_data
                    )
                    if status_code != 201:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to create profile"
                        )
                updates_made = True
                existing_profile.update(profile_updates)

            return {
                "updates_made": updates_made,
                "user": current_user,
                "profile": existing_profile
            }

        except HTTPException as he:
            raise he
        except Exception as e:
            logger.error(f"Error updating profile: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update profile"
            )

