import json
from app.models.user import User
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from app.utils.db_cred import DatabaseManager
from app.utils.redis import redis_client
from app.schemas.user_schema import UserLoginRequest
from multidb_request_handler import DatabaseOperation

# Create an instance of CryptContext for password hashing verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
db_manager = DatabaseManager()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def login_user(db: Session, login_request: UserLoginRequest):
    # Check if the provided username_or_email is an email or username
    user = db.query(User).filter(
        (User.email == login_request.email)
    ).first()

    if user and verify_password(login_request.password, user.password):
        return user  # User authenticated successfully, return user object
    return None  # Authentication failed
users_db = db_manager.get_database('users')
profiles_db = db_manager.get_database('profiles')


def get_all_users():
    status_code, users = users_db.post_request("get")
    if status_code == 200:
        user_ids = [user['id'] for user in users]
        _, profiles = profiles_db.post_request(f"get?user_id__eq={','.join(map(str, user_ids))}")

        # Create a mapping of user_id to profiles for quick lookup
        profiles_map = {profile['user_id']: profile for profile in profiles}

        # Assign the corresponding profile to each user
        for user in users:
            user['profile'] = profiles_map.get(user['id'], {})
    return status_code, users

def get_authenticated_user(db: Session, user_id: int):
    # Query the user based on their ID
    return db.query(User).filter(User.id == user_id).first()