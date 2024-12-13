import jwt as pyjwt
from fastapi import HTTPException
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os

load_dotenv()  # Load environment variables from .env file
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1500  # Set expiration time for access token (15 minutes)
REFRESH_TOKEN_EXPIRE_DAYS = 30  # Set expiration time for refresh token (30 days)

# Create access token
def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    encoded_jwt = pyjwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Create refresh token
def create_refresh_token(data: dict):
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    encoded_jwt = pyjwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    try:
        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("user_id")
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=403, detail="Invalid token")