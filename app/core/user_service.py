import json

from sqlalchemy.orm import Session
from app.models.user import User
from passlib.context import CryptContext
from app.schemas.user_schema import UserLoginRequest
from app.utils.redis import redis_client

# Create an instance of CryptContext for password hashing verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def login_user(db: Session, login_request: UserLoginRequest):
    # Check if the provided username_or_email is an email or username
    user = db.query(User).filter(
        (User.email == login_request.email)
    ).first()

    if user and verify_password(login_request.password, user.hashed_password):
        return user  # User authenticated successfully, return user object
    return None  # Authentication failed

def get_all_users(db: Session):
    cached_users = redis_client.get("all_users")

    if cached_users:
        # If found in cache, return the cached data
        return json.loads(cached_users)
    users = db.query(User).all()
    redis_client.setex("all_users", 3600, json.dumps([user.to_dict() for user in users]))  # Assuming `to_dict` method exists
    return users

def get_authenticated_user(db: Session, user_id: int):
    # Query the user based on their ID
    return db.query(User).filter(User.id == user_id).first()