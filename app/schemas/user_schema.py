from pydantic import BaseModel, EmailStr, Field
from app.models.user import UserRole
from typing import Optional


class UserRegisterRequest(BaseModel):
    email: EmailStr
    phone: str
    password: str
    role: UserRole = UserRole.USER  # Default role is normal user

    class Config:
        use_enum_values = True


class UserUpdateRequest(BaseModel):
    email: EmailStr


class PasswordResetRequest(BaseModel):
    new_password: str


class UserLoginRequest(BaseModel):
    email: str  # Can be either username or email
    password: str  # Password is required


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=6)
    new_password: str = Field(..., min_length=6)
    confirm_password: str = Field(..., min_length=6)


class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: Optional[str] = None


class ProfileResponse(BaseModel):
    full_name: str
    email: EmailStr
    phone: str
    address: str
    city: str
    state: str
    zip_code: str
    country: str

    class Config:
        from_attributes = True

class VerificationCodeRequest(BaseModel):
    email: EmailStr
    code: str

class LoginResponsePending(BaseModel):
    message: str
    email: str
    requires_verification: bool = True

class LoginResponseComplete(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=6)
    confirm_password: str = Field(..., min_length=6)

    class Config:
        json_schema_extra = {
            "example": {
                "new_password": "newSecurePassword123",
                "confirm_password": "newSecurePassword123"
            }
        }


class ForgotPasswordResponse(BaseModel):
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "message": "If the email exists in our system, you will receive a password reset link shortly"
            }
        }


class ResetPasswordResponse(BaseModel):
    message: str

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Password has been reset successfully. Please login with your new password"
            }
        }
