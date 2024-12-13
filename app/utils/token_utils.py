from app.utils.redis import redis_client
import secrets

class TokenStorage:
    PREFIX = "pwd_reset:"
    EXPIRY = 3600  # 1 hour in seconds

    @classmethod
    def store_token(cls, email: str, token: str):
        """Store token in Redis with expiry"""
        key = f"{cls.PREFIX}{email}"
        redis_client.setex(key, cls.EXPIRY, token)

    @classmethod
    def get_token(cls, email: str) -> str:
        """Retrieve token from Redis"""
        key = f"{cls.PREFIX}{email}"
        return redis_client.get(key)

    @classmethod
    def delete_token(cls, email: str):
        """Delete token from Redis"""
        key = f"{cls.PREFIX}{email}"
        redis_client.delete(key)

    @classmethod
    def verify_token(cls, email: str, token: str) -> bool:
        """Verify if token matches stored token"""
        stored_token = cls.get_token(email)
        return stored_token == token


def create_password_reset_token() -> str:
    """Generate a secure random token for password reset"""
    return secrets.token_urlsafe(32)
