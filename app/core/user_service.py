import json

from sqlalchemy.orm import Session
from app.models.user import User
from passlib.context import CryptContext
from app.schemas.user_schema import UserLoginRequest
from app.utils.redis import redis_client
from multidb_request_handler import DatabaseOperation

# Create an instance of CryptContext for password hashing verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
def get_all_users():
    status_code, users = users_db.post_request("get")
    if status_code == 200:
        for user in users:
            _, profiles = profiles_db.post_request(f"get?user_id__eq={user['id']}")
            user['profile'] = profiles[0] if profiles else {}
    return status_code,users

def get_authenticated_user(db: Session, user_id: int):
    # Query the user based on their ID
    return db.query(User).filter(User.id == user_id).first()