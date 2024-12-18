from typing import Optional
from sqlalchemy.orm import Session
from app.core.auth import verify_token
from app.database.database import get_db
from fastapi import HTTPException, Depends
from app.utils.jwt_utils import decode_token
from fastapi.security import OAuth2PasswordBearer
from multidb_request_handler import DatabaseOperation
from app.core.user_service import get_authenticated_user
from app.models.user import User, UserRole, TokenBlacklist
from fastapi import APIRouter, Depends, HTTPException, status

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class UserService:
    def __init__(self):
        self.users_db = DatabaseOperation(
            host='http://127.0.0.1',
            port='44777',
            database_name='social_automation',
            table_name='users',
            username='postgres',
            password='postgres'
        )

        self.profiles_db = DatabaseOperation(
            host='http://127.0.0.1',
            port='44777',
            database_name='social_automation',
            table_name='profiles',
            username='postgres',
            password='postgres'
        )

        self.token_blacklist_db = DatabaseOperation(
            host='http://127.0.0.1',
            port='44777',
            database_name='social_automation',
            table_name='token_blacklist',
            username='postgres',
            password='postgres'
        )

    async def get_current_user(self, token: str):
        """Get current user from token"""
        try:
            # Check if token is blacklisted
            status_code, blacklisted = self.token_blacklist_db.post_request(
                f"get?token__eq={token}"
            )

            if token in blacklisted:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Decode token to get user_id
            user_id = decode_token(token)

            # Get user
            status_code, users = self.users_db.post_request(f"get")

            for user in users:
                if user['id'] == user_id:
                    return user


        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def get_user_profile(self, user_id: int):
        """Get or create user profile"""
        # Try to get existing profile
        status_code, profiles = self.profiles_db.post_request(
            f"get"
        )

        if status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get profile"
            )

        for profile in profiles:
            if profile['user_id'] == user_id:
                return profile


        # Create new profile if doesn't exist
        new_profile = {
            "user_id": user_id,
            "address": "",
            "city": "",
            "state": "",
            "zip_code": "",
            "country": ""
        }

        status_code, created_profile = self.profiles_db.post_request(
            "create",
            data=new_profile
        )

        if status_code != 201:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create profile"
            )

        return created_profile


# Dependency for getting current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
    user_service = UserService()
    return await user_service.get_current_user(token)


# Function to check if the user has a super_admin role
def get_super_admin_user(current_user: Optional[dict] = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required"
        )
    if current_user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(
            status_code=403,
            detail="Super admin privileges required"
        )
    return current_user
#
# # General function to check if the user has a specific role
# def has_role(required_role: str, token: str = Depends(verify_token)):
#     user = User.get_by_token(token)  # Retrieve user from the token
#     if not user:
#         raise HTTPException(status_code=401, detail="User not found")
#     if user.role != required_role:  # Check if user has the required role
#         raise HTTPException(status_code=403, detail=f"{required_role} privileges required")
#     return user
#
# # Function to ensure user ownership of resources
# def check_user_ownership(user_id: int, token: str = Depends(verify_token)):
#     user = User.get_by_token(token)  # Retrieve user from the token
#     if not user:
#         raise HTTPException(status_code=401, detail="User not found")
#     if user.id != user_id:  # Check if the current user matches the user_id in the request
#         raise HTTPException(status_code=403, detail="You do not have permission to access this resource")
#     return user
