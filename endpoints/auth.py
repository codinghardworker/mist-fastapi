import os
import re
import time
import random
import logging
import smtplib
from uuid import uuid4
from datetime import datetime, timedelta
from typing import Dict

from fastapi.responses import RedirectResponse
from database.models.models import User
from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from database.db.db_connection import get_db
from database.models import models
from database.schemas import schemas
from database.auth.hashing import Hash
from database.auth.token import create_access_token
from database.auth.oauth2 import get_current_user

router = APIRouter(prefix="/auth", tags=["Auth"])

# Environment variables
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
SENDER_EMAIL = "techcoderhelp@gmail.com"
SENDER_PASSWORD = "zvqe jxlp asgk hdcj"
ADMIN_EMAIL = "admin@livefusion.com"


# Temporary in-memory storage
otp_storage: Dict[str, dict] = {}
reset_tokens: Dict[str, int] = {}

# ============================== Schemas ==============================

class RegistrationRequest(BaseModel):
    username: str
    email: EmailStr
    password1: str
    password2: str

class OTPRequest(BaseModel):
    email: EmailStr
    otp: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    confirm_password: str

# ============================== Helpers ==============================

def send_email(recipient: str, subject: str, body: str) -> bool:
    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        logging.error(f"Failed to send email: {e}")
        return False

def send_otp_email(email: str, otp: str) -> bool:
    return send_email(
        email,
        "Your OTP Verification Code",
        f"Your verification code is: {otp}\nThis will expire in 5 minutes."
    )

def send_reset_link(email: str, reset_link: str) -> bool:
    return send_email(
        email,
        "Password Reset Request",
        f"Click the link to reset your password:\n{reset_link}\n\nExpires in 1 hour."
    )


# Add these new helper functions
async def send_user_registration_email(email: str, db: Session) -> bool:
    return send_email(
        email,
        "Registration Successful",
        "Your account has been created. An admin will assign stream access to you soon."
    )

async def send_admin_tag_assignment_email(user_data: dict, db: Session) -> bool:
    """Send notification to admins about new user registration"""
    # Get all admin emails
    admin_emails = [user.email for user in db.query(models.User).filter(models.User.role == "admin").all()]
    domain = os.getenv('DOMAIN', 'http://localhost:8000')
    assignment_url = f"{domain}/dashboard/admin"
    
    # Send to all admins
    results = []
    for admin_email in admin_emails:
        results.append(send_email(
            admin_email,
            "New User Registration - Tag Assignment Required",
            f"""
            A new user has registered:\n
            Username: {user_data['username']}\n
            Email: {user_data['email']}\n\n
            Please log in to the admin dashboard to assign stream tags to this user.\n\n
            Url: {assignment_url}
            """
        ))
    
    return all(results)

# ============================== Endpoints ==============================

@router.post("/register", status_code=status.HTTP_200_OK)
async def register_user(request: RegistrationRequest, db: Session = Depends(get_db)):
    if request.password1 != request.password2:
        raise HTTPException(400, detail="Passwords do not match")
    if len(request.password1) < 8 or not any(c.isdigit() for c in request.password1):
        raise HTTPException(400, detail="Password must be at least 8 characters with a number")

    if db.query(models.User).filter(
        (models.User.email == request.email) |
        (models.User.username == request.username)
    ).first():
        raise HTTPException(400, detail="Email or username already registered")

    otp = str(random.randint(100000, 999999))
    otp_storage[request.email] = {
        "otp": otp,
        "expiry": time.time() + 300,
        "user_data": {
            "username": request.username,
            "email": request.email,
            "password": request.password1,
            "allowed_tags": "No Stream is Assigned to you currently, admin will assign you soon"
        }
    }

    if not send_otp_email(request.email, otp):
        raise HTTPException(500, detail="Failed to send OTP")

    return {"message": "OTP sent to email"}

# Update the verify-otp endpoint
@router.post("/verify-otp", status_code=status.HTTP_200_OK)
async def verify_otp(request: OTPRequest, db: Session = Depends(get_db)):
    record = otp_storage.get(request.email)
    if not record or time.time() > record["expiry"]:
        otp_storage.pop(request.email, None)
        raise HTTPException(400, detail="OTP expired or not found")
    if record["otp"] != request.otp:
        raise HTTPException(400, detail="Invalid OTP")

    user_data = record["user_data"]
    user = models.User(
        username=user_data["username"],
        email=user_data["email"],
        password=Hash.bcrypt(user_data["password"]),
        is_active=True,
        allowed_tags=user_data["allowed_tags"],
        role="user"  # Explicitly set role
    )
    try:
        db.add(user)
        db.commit()
        
        # Send email to user
        await send_user_registration_email(user.email, db)
        
        # Send email to all admins
        await send_admin_tag_assignment_email(user_data, db)
            
        return {"message": "Registration successful"}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, detail=f"Failed to create user: {str(e)}")
    finally:
        otp_storage.pop(request.email, None)

@router.post("/login", status_code=status.HTTP_200_OK)
def login(request: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Check if the user exists in the database
    user = db.query(models.User).filter(models.User.email == request.username).first()
    
    # If user doesn't exist, raise error
    if not user:
        raise HTTPException(401, detail="Invalid credentials")
    
    # Check if the provided password matches the stored hashed password
    if not Hash.verify(user.password, request.password):
        raise HTTPException(401, detail="Invalid credentials")
    
    # Create an access token after successful authentication
    token = create_access_token(data={"sub": user.email})
    
    # Log the login attempt for debugging purposes (remove in production)
    logging.info(f"User logged in successfully: {user.email}")
    
    # Return the token along with the token type
    return {"access_token": token, "token_type": "bearer"}

@router.post("/forgot-password", status_code=status.HTTP_200_OK)
def forgot_password(email: EmailStr, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(404, detail="Email not found")

    token = str(uuid4())
    reset_tokens[token] = {"user_id": user.id, "expiry": time.time() + 3600}
    reset_link = f"https://yourapp.com/reset-password?token={token}"

    if not send_reset_link(email, reset_link):
        raise HTTPException(500, detail="Failed to send reset link")

    return {"message": "Reset link sent"}

@router.post("/reset-password", status_code=status.HTTP_200_OK)
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    token_data = reset_tokens.get(req.token)
    if not token_data or time.time() > token_data["expiry"]:
        reset_tokens.pop(req.token, None)
        raise HTTPException(400, detail="Invalid or expired token")

    user = db.query(models.User).filter(models.User.id == token_data["user_id"]).first()
    if not user:
        raise HTTPException(404, detail="User not found")
    if req.new_password != req.confirm_password:
        raise HTTPException(400, detail="Passwords do not match")
    if Hash.verify(user.password, req.new_password):
        raise HTTPException(400, detail="New password cannot be the same as old one")

    user.password = Hash.bcrypt(req.new_password)
    db.commit()
    reset_tokens.pop(req.token, None)
    return {"message": "Password updated successfully"}

@router.get("/profile", response_model=schemas.UserOut)
def get_profile(current_user: schemas.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(models.User).filter(models.User.email == current_user.email).first()

@router.put("/profile", response_model=schemas.UserOut)
def update_profile(update_data: schemas.UpdateUser,
                   current_user: schemas.User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == current_user.email).first()
    if not user:
        raise HTTPException(404, detail="User not found")
    if update_data.email and update_data.email != user.email:
        if db.query(models.User).filter(models.User.email == update_data.email).first():
            raise HTTPException(400, detail="Email already in use")
        user.email = update_data.email
    if update_data.username:
        user.username = update_data.username
    db.commit()
    return user

@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(401, detail="Invalid authorization header")

    token = auth_header.split(" ")[1]
    if db.query(models.BlacklistedToken).filter_by(token=token).first():
        raise HTTPException(400, detail="Token already blacklisted")

    db.add(models.BlacklistedToken(token=token, reason="User logout"))
    db.commit()
    return {"message": "Logged out successfully"}
