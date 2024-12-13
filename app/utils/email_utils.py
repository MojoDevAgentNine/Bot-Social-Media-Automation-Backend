# utils/email_utils.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import random
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.user import EmailVerificationCode
from dotenv import load_dotenv

from multidb_request_handler import DatabaseOperation

load_dotenv()


def generate_verification_code():
    return ''.join(random.choices('0123456789', k=6))


def send_verification_email(to_email: str, verification_code: str):
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")

    msg = MIMEMultipart()
    msg['From'] = smtp_username
    msg['To'] = to_email
    msg['Subject'] = "Your Verification Code"

    body = f"""
    Your verification code is: {verification_code}

    This code will expire in 10 minutes.
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def create_verification_code(user_id: int) -> str:
    db = DatabaseOperation(
        host='http://127.0.0.1',
        port='44777',
        database_name='social_automation',
        table_name='email_verification_codes',
        username='postgres',
        password='postgres'
    )

    # Generate verification code
    code = generate_verification_code()  # Implement this function

    # Store verification code
    verification_data = {
        "user_id": user_id,
        "code": code,
        "expires_at": (datetime.now() + timedelta(minutes=10)).isoformat(),
        "is_used": False
    }

    status_code, response = db.post_request("create", data=verification_data)

    if status_code != 201:
        raise Exception("Failed to create verification code")

    return code

from app.axiom_logger.authentication import logger
async def send_password_reset_email(email: str, reset_token: str):
    try:
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_port = int(os.getenv("SMTP_PORT"))
        smtp_username = os.getenv("SMTP_USERNAME")
        smtp_password = os.getenv("SMTP_PASSWORD")
        frontend_url = os.getenv("FRONTEND_URL")
        print(frontend_url)

        # Create reset link with token in URL
        reset_link = f"{frontend_url}/user/reset-password/{reset_token}"
        print(reset_link)

        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = email
        msg['Subject'] = "Password Reset Request"

        body = f"""
        <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>You have requested to reset your password. Click the button below to set a new password:</p>
                <p>
                    <a href="{reset_link}" style="
                        background-color: #4CAF50;
                        border: none;
                        color: white;
                        padding: 15px 32px;
                        text-align: center;
                        text-decoration: none;
                        display: inline-block;
                        font-size: 16px;
                        margin: 4px 2px;
                        cursor: pointer;
                        border-radius: 4px;">
                        Reset Password
                    </a>
                </p>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p>{reset_link}</p>
            </body>
        </html>
        """
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()

    except Exception as e:
        logger.error(f"Failed to send password reset email to {email}: {str(e)}")
        raise Exception("Failed to send password reset email")

    return "Password reset email sent successfully"