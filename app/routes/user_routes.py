import os

from starlette import status
import requests
from app.axiom_logger.authentication import logger
from app.core.permissions import get_super_admin_user, get_current_user, oauth2_scheme, UserService
from app.schemas.user_schema import UserRegisterRequest, ProfileUpdateRequest, \
    ChangePasswordRequest, ProfileResponse, VerificationCodeRequest, LoginResponsePending, LoginResponseComplete
from app.core.auth import register_user, login_user2, VerificationService, ProfileService
from app.schemas.user_schema import UserLoginRequest
from app.core.user_service import login_user, get_all_users
from app.utils.email_utils import create_verification_code, send_verification_email, send_password_reset_email
from app.utils.jwt_utils import create_access_token, create_refresh_token
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.database import get_db
from passlib.hash import bcrypt
from app.models.user import User, Profile, TokenBlacklist, EmailVerificationCode
import jwt
from datetime import datetime
from fastapi.responses import  HTMLResponse
from app.utils.rate_limiter import limiter
from app.utils.redis import redis_client
from app.utils.token_utils import create_password_reset_token, TokenStorage
from app.database import get_usres_table
from multidb_request_handler import DatabaseOperation

router = APIRouter()



import asyncio

@router.post("/register")
def register(
    request: UserRegisterRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_super_admin_user)  # Add this dependency
):
    try:
        user = asyncio.run(register_user(request))
        logger.info(f"Email: {current_user.get('email')} created user Email: {user}, Role: {user} - User registered successfully")
        return {
            "message": "User registered successfully",
            "user": {
                "email": user.get('email'),
                "role": user.get('role')
            }
        }
    except ValueError as e:
        logger.error(f"Email: {request.email}, Role: {request.role} - {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))




@router.post("/login")
def login(login_request: UserLoginRequest):
    # Authenticate user
    try:
        # Authenticate user
        print(login_request.email, login_request.password)
        user = login_user2(
            login_request.email,
            login_request.password
        )
        print("i am here")

        if not user:
            logger.error(f"Invalid login attempt for email: {login_request.email}")
            raise HTTPException(
                status_code=400,
                detail="Invalid username/email or password"
            )

        # Generate and send verification code
        verification_code = create_verification_code(user['id'])
        success = send_verification_email(user['email'], verification_code)

        if not success:
            logger.error(f"Failed to send verification email to {user['email']}")
            raise HTTPException(
                status_code=500,
                detail="Failed to send verification email"
            )

        logger.info(f"Verification code sent to {user['email']}")
        return LoginResponsePending(
            message="Verification code sent to your email",
            email=user['email'],
            requires_verification=True
        )

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred during login"
        )


@router.post("/verify-code")
def verify_code(verification_request: VerificationCodeRequest):
    try:
        verification_service = VerificationService()

        # Verify code
        user = verification_service.verify_code(
            email=verification_request.email,
            code=verification_request.code
        )
        print(verification_request.code)
        print(user)

        if not user:
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired verification code"
            )

        # Generate tokens
        access_token = create_access_token(data={"user_id": user['id']})
        refresh_token = create_refresh_token(data={"user_id": user['id']})

        logger.info(f"Email: {user['email']} verified successfully")
        return LoginResponseComplete(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Verification error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred during verification"
        )




@router.post("/logout")
def logout(
        token: str = Depends(oauth2_scheme),
        current_user: User = Depends(get_current_user)
):
    try:
        # Initialize database connection for token blacklist
        blacklist_db = DatabaseOperation(
            host='http://127.0.0.1',
            port='44777',
            database_name='social_automation',
            table_name='token_blacklist',
            username='postgres',
            password='postgres'
        )

        # Add token to blacklist
        blacklist_data = {
            "token": token,
            "created_at": datetime.utcnow().isoformat(),
            "user_id": current_user.get('id')  # Optional: track who logged out
        }

        status_code, response = blacklist_db.post_request(
            "create",
            data=blacklist_data
        )

        if status_code != 201:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to logout"
            )

        # Log the successful logout
        logger.info(
            f"User logged out successfully - "
            f"Email: {current_user.get('email')}, "
            f"Role: {current_user.get('role')}"
        )

        return {
            "message": "Logged out successfully",
            "timestamp": datetime.utcnow().isoformat()
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(
            f"Logout error - "
            f"User: {current_user.get('email')}, "
            f"Error: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to logout"
        )




@router.post("/refresh_token")
def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    try:
        # Decode the refresh token
        payload = jwt.decode(refresh_token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        user_id = payload.get("user_id")

        if user_id is None:
            logger.warning(f"User ID: {user_id}, User Email: {payload.get('email')} - Invalid refresh token")
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        # You can check if the user exists in the database (optional)
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            logger.warning(f"User ID: {user_id}, User Email: {payload.get('email')} - User not found")
            raise HTTPException(status_code=404, detail="User not found")

        # Create a new access token
        new_access_token = create_access_token(data={"user_id": user.id})
        logger.info(f"User ID: {user_id}, User Email: {payload.get('email')} - New access token created")
        # Return the new access token
        return {"access_token": new_access_token, "token_type": "bearer"}

    except jwt.PyJWTError:
        logger.error(f"Invalid refresh token")
        raise HTTPException(status_code=401, detail="Invalid refresh token")




@router.get("/all_users")
def get_users(db: Session = Depends(get_db), current_user: dict = Depends(get_super_admin_user)):
    # Get all users from the database
    users = get_all_users()
    # logger.info(f"Email: {current_user.email}, Role: {current_user.role} - All users retrieved successfully")
    return {"users": users}




@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    try:
        user_service = UserService()

        # Get or create profile
        profile = await user_service.get_user_profile(current_user['id'])

        logger.info(
            f"Email: {current_user['email']}, Role: {current_user['role']} - User profile retrieved successfully")

        # Return user and profile data
        return {
            "email": current_user['email'],
            "full_name": current_user['full_name'],
            "is_active": current_user['is_active'],
            "role": current_user['role'],
            "phone": current_user.get('phone', ''),
            "address": profile.get('address', ''),
            "city": profile.get('city', ''),
            "state": profile.get('state', ''),
            "zip_code": profile.get('zip_code', ''),
            "country": profile.get('country', '')
        }

    except Exception as e:
        logger.error(f"Error retrieving user profile: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving user profile"
        )


@router.patch("/update_profile", response_model=ProfileResponse)
async def update_user_profile(
        profile_data: ProfileUpdateRequest,
        current_user: dict = Depends(get_current_user)
):
    try:
        user_service = ProfileService()

        result = await user_service.update_profile(
            current_user=current_user,
            profile_data=profile_data.model_dump(exclude_unset=True)
        )

        if result["updates_made"]:
            # Clear cache if using Redis
            try:
                if redis_client:
                    redis_client.delete("all_users")
            except Exception as e:
                logger.warning(f"Failed to clear Redis cache: {str(e)}")

            logger.info(f"Profile updated for user {current_user['email']}")

        # Construct response
        return ProfileResponse(
            full_name=result["user"].get('full_name', ''),
            email=result["user"].get('email', ''),
            phone=result["user"].get('phone', ''),
            address=result["profile"].get('address', ''),
            city=result["profile"].get('city', ''),
            state=result["profile"].get('state', ''),
            zip_code=result["profile"].get('zip_code', ''),
            country=result["profile"].get('country', '')
        )

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error in update_user_profile route: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )


@router.post("/change_password")
async def change_password(
    request: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    token: str = Depends(oauth2_scheme)  # The current JWT token
):
    # Verify the old password
    if not bcrypt.verify(request.old_password, current_user.hashed_password):
        logger.warning(f"User ID: {current_user.id}, User Email: {current_user.email} - Old password is incorrect")
        raise HTTPException(status_code=400, detail="Old password is incorrect")

    # Check if new password and confirm password match
    if request.new_password != request.confirm_password:
        logger.warning(f"User ID: {current_user.id}, User Email: {current_user.email} - New password and confirmation do not match")
        raise HTTPException(status_code=400, detail="New password and confirmation do not match")

    # Hash the new password and update the database
    hashed_password = bcrypt.hash(request.new_password)
    current_user.hashed_password = hashed_password
    db.commit()
    db.refresh(current_user)

    # Add the current token to the blacklist
    db.add(TokenBlacklist(token=token))
    db.commit()
    logger.info(f"User ID: {current_user.id}, User Email: {current_user.email} - Password changed successfully")
    return {"message": "Password changed successfully. Please log in again to continue."}


# @router.post("/change_password")
# async def change_password(
#         request: ChangePasswordRequest,
#         current_user: dict = Depends(get_current_user),
#         token: str = Depends(oauth2_scheme)
# ):
#     try:
#         # Initialize database connections
#         users_db = DatabaseOperation(
#             host='http://127.0.0.1',
#             port='44777',
#             database_name='social_automation',
#             table_name='users',
#             username='postgres',
#             password='postgres'
#         )
#
#         blacklist_db = DatabaseOperation(
#             host='http://127.0.0.1',
#             port='44777',
#             database_name='social_automation',
#             table_name='token_blacklist',
#             username='postgres',
#             password='postgres'
#         )
#
#         # Get current user's password
#         status_code, users = users_db.post_request(f"get?id__eq={current_user['id']}")
#         if status_code != 200 or not users:
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND,
#                 detail="User not found"
#             )
#
#         user = users[0]
#
#         # Verify the old password
#         if not bcrypt.verify(request.old_password, user['password']):
#             logger.warning(
#                 f"User ID: {user['id']}, "
#                 f"User Email: {user['email']} - "
#                 f"Old password is incorrect"
#             )
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Old password is incorrect"
#             )
#
#         # Check if new password and confirm password match
#         if request.new_password != request.confirm_password:
#             logger.warning(
#                 f"User ID: {user['id']}, "
#                 f"User Email: {user['email']} - "
#                 f"New password and confirmation do not match"
#             )
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="New password and confirmation do not match"
#             )
#
#         # Hash the new password
#         hashed_password = bcrypt.hash(request.new_password)
#
#         # Update user's password
#         status_code, _ = users_db.patch_request(
#             f"update/{user['id']}",
#             data={"password": hashed_password}
#         )
#
#         if status_code != 202:
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail="Failed to update password"
#             )
#
#         # Add the current token to the blacklist
#         blacklist_data = {
#             "token": token,
#             "created_at": datetime.utcnow().isoformat(),
#             "user_id": user['id']
#         }
#
#         status_code, _ = blacklist_db.post_request(
#             "create",
#             data=blacklist_data
#         )
#
#         if status_code != 201:
#             logger.error(
#                 f"Failed to blacklist token for user {user['email']} "
#                 f"during password change"
#             )
#             # Continue anyway as password was changed successfully
#
#         # Clear any cached data
#         try:
#             if redis_client:
#                 redis_client.delete(f"user_token_{user['id']}")
#                 redis_client.delete("all_users")
#         except Exception as e:
#             logger.warning(f"Failed to clear Redis cache: {str(e)}")
#
#         logger.info(
#             f"User ID: {user['id']}, "
#             f"User Email: {user['email']} - "
#             f"Password changed successfully"
#         )
#
#         return {
#             "message": "Password changed successfully. Please log in again to continue.",
#             "timestamp": datetime.utcnow().isoformat()
#         }
#
#     except HTTPException as he:
#         raise he
#     except Exception as e:
#         logger.error(
#             f"Password change error - "
#             f"User: {current_user.get('email')}, "
#             f"Error: {str(e)}"
#         )
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Failed to change password"
#         )


from fastapi import  Depends, HTTPException, Request, BackgroundTasks
from app.schemas.user_schema import ForgotPasswordRequest, ForgotPasswordResponse


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
@limiter.limit("50/hour")
async def forgot_password(
        request: Request,
        forgot_request: ForgotPasswordRequest,
        background_tasks: BackgroundTasks,  # Inject BackgroundTasks
        db: Session = Depends(get_db)
):
    try:
        logger.info(f"Password reset requested for email: {forgot_request.email}")

        user = db.query(User).filter(User.email == forgot_request.email).first()
        if user:
            # Generate reset token
            reset_token = create_password_reset_token()

            # Store token in Redis
            TokenStorage.store_token(forgot_request.email, reset_token)

            # Add email sending to background tasks
            background_tasks.add_task(
                send_password_reset_email,
                forgot_request.email,
                reset_token
            )

            logger.info(f"Password reset link scheduled for: {forgot_request.email}")

        # Return immediate response
        return ForgotPasswordResponse(
            message="If the email exists in our system, you will receive a password reset link shortly"
        )

    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to process password reset request"
        )
from fastapi import Form


@router.get("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_page(
    token: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Render the password reset form page
    """
    try:
        # Verify token exists and is valid
        email = None
        for key in redis_client.scan_iter(f"{TokenStorage.PREFIX}*"):
            current_email = key.replace(TokenStorage.PREFIX, "") if isinstance(key, str) else key.decode().replace(TokenStorage.PREFIX, "")
            stored_token = TokenStorage.get_token(current_email)
            if stored_token == token:
                email = current_email
                break

        if not email:
            return """
            <html>
                <body>
                    <h1>Invalid or Expired Link</h1>
                    <p>The password reset link is invalid or has expired. Please request a new one.</p>
                </body>
            </html>
            """

        # Simple HTML form without JavaScript
        return f"""
        <html>
            <head>
                <title>Reset Password</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        max-width: 500px;
                        margin: 50px auto;
                        padding: 20px;
                    }}
                    .form-group {{
                        margin-bottom: 15px;
                    }}
                    label {{
                        display: block;
                        margin-bottom: 5px;
                    }}
                    input {{
                        width: 100%;
                        padding: 8px;
                        margin-bottom: 10px;
                    }}
                    button {{
                        background-color: #4CAF50;
                        color: white;
                        padding: 10px 15px;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                    }}
                </style>
            </head>
            <body>
                <h2>Reset Your Password</h2>
                <form method="POST" action="/user/reset-password/{token}">
                    <div class="form-group">
                        <label for="new_password">New Password:</label>
                        <input type="password" 
                               id="new_password" 
                               name="new_password" 
                               required 
                               minlength="6">
                    </div>
                    <div class="form-group">
                        <label for="confirm_password">Confirm Password:</label>
                        <input type="password" 
                               id="confirm_password" 
                               name="confirm_password" 
                               required>
                    </div>
                    <button type="submit">Reset Password</button>
                </form>
            </body>
        </html>
        """

    except Exception as e:
        logger.error(f"Error rendering reset password page: {str(e)}")
        return """
        <html>
            <body>
                <h1>Error</h1>
                <p>An error occurred. Please try again later.</p>
            </body>
        </html>
        """

@router.get("/reset-success", response_class=HTMLResponse)
async def reset_success():
    """
    Show success page after password reset
    """
    return """
    <html>
        <head>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 500px;
                    margin: 50px auto;
                    padding: 20px;
                    text-align: center;
                }
                .success {
                    color: #4CAF50;
                    margin-bottom: 20px;
                }
                .login-link {
                    color: #4CAF50;
                    text-decoration: none;
                }
            </style>
        </head>
        <body>
            <h2 class="success">Password Reset Successful!</h2>
            <p>Your password has been successfully reset.</p>
            <p>Please <a href="/login" class="login-link">login</a> with your new password.</p>
        </body>
    </html>
    """


# Update your existing POST endpoint
@router.post("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password(
        token: str,
        request: Request,
        new_password: str = Form(...),
        confirm_password: str = Form(...),
        db: Session = Depends(get_db)
):
    try:
        # Verify passwords match
        if new_password != confirm_password:
            return """
            <html>
                <body>
                    <h1>Error</h1>
                    <p>Passwords do not match. Please try again.</p>
                    <a href="javascript:history.back()">Go Back</a>
                </body>
            </html>
            """

        # Get email from token
        email = None
        for key in redis_client.scan_iter(f"{TokenStorage.PREFIX}*"):
            current_email = key.replace(TokenStorage.PREFIX, "") if isinstance(key, str) else key.decode().replace(
                TokenStorage.PREFIX, "")
            stored_token = TokenStorage.get_token(current_email)
            if stored_token == token:
                email = current_email
                break

        if not email:
            return """
            <html>
                <body>
                    <h1>Invalid Link</h1>
                    <p>The password reset link is invalid or has expired.</p>
                </body>
            </html>
            """

        # Update password
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return """
            <html>
                <body>
                    <h1>Error</h1>
                    <p>User not found.</p>
                </body>
            </html>
            """

        # Update password with new hash
        user.hashed_password = bcrypt.hash(new_password)
        db.commit()

        # Delete used token
        TokenStorage.delete_token(email)

        logger.info(f"Password reset successful for user: {email}")

        # Redirect to success page
        return """
        <html>
            <head>
                <meta http-equiv="refresh" content="3;url=/login">
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        max-width: 500px;
                        margin: 50px auto;
                        padding: 20px;
                        text-align: center;
                    }
                    .success {
                        color: #4CAF50;
                    }
                </style>
            </head>
            <body>
                <h2 class="success">Password Reset Successful!</h2>
                <p>Your password has been successfully reset.</p>
                <p>You will be redirected to the login page in 3 seconds...</p>
                <p>If you are not redirected, <a href="/login">click here</a>.</p>
            </body>
        </html>
        """

    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        return """
        <html>
            <body>
                <h1>Error</h1>
                <p>An error occurred while resetting your password.</p>
                <p>Please try again later.</p>
            </body>
        </html>
        """
