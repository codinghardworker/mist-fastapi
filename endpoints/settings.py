from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
import os

from database.db.db_connection import get_db
from database.models.models import AppSettings, User
from database.schemas import schemas
from database.auth.oauth2 import get_current_user

router = APIRouter(prefix="/settings", tags=["Settings"])

# Default settings configuration - now only contains keys and descriptions, values come from env
DEFAULT_SETTINGS = [
    {
        "key": "MIST_HOST",
        "description": "MistServer hostname or IP"
    },
    {
        "key": "MIST_PORT",
        "description": "MistServer API port"
    },
    {
        "key": "MIST_USERNAME",
        "description": "MistServer API username"
    },
    {
        "key": "MIST_PASSWORD",
        "description": "MistServer API password"
    },
    {
        "key": "DOMAIN",
        "description": "Application domain for generating URLs"
    },
    {
        "key": "SMTP_SERVER",
        "description": "SMTP server for email"
    },
    {
        "key": "SMTP_PORT",
        "description": "SMTP server port"
    },
    {
        "key": "SENDER_EMAIL",
        "description": "Email address for sending emails"
    },
    {
        "key": "SENDER_PASSWORD",
        "description": "Email password or app password"
    }
]

def initialize_settings_on_startup():
    """Initialize default settings if they don't exist, pulling values from env"""
    db: Session = next(get_db())
    try:
        for setting in DEFAULT_SETTINGS:
            existing = db.query(AppSettings).filter(AppSettings.key == setting["key"]).first()
            if not existing:
                # Get value from environment variables
                value = os.getenv(setting["key"], "")
                db_setting = AppSettings(
                    key=setting["key"],
                    value=value,
                    description=setting["description"]
                )
                db.add(db_setting)
        db.commit()
    finally:
        db.close()

@router.get("/", response_model=List[schemas.AppSettingsOut])
def get_all_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all settings (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return db.query(AppSettings).all()

@router.get("/{key}", response_model=schemas.AppSettingsOut)
def get_setting(
    key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific setting (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
        
    setting = db.query(AppSettings).filter(AppSettings.key == key).first()
    if not setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Setting not found"
        )
    return setting

@router.put("/{key}", response_model=schemas.AppSettingsOut)
def update_setting(
    key: str,
    setting_update: schemas.AppSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a setting (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
        
    setting = db.query(AppSettings).filter(AppSettings.key == key).first()
    if not setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Setting not found"
        )
            
    setting.value = setting_update.value
    setting.updated_at = datetime.utcnow()
    setting.updated_by = current_user.id
    
    # Update environment variable in runtime
    os.environ[key] = setting_update.value
    
    db.commit()
    db.refresh(setting)
    
    return setting

def get_setting_value(key: str, db: Session):
    """Helper function to get a setting value from database"""
    setting = db.query(AppSettings).filter(AppSettings.key == key).first()
    if setting:
        return setting.value
    return os.getenv(key, "")