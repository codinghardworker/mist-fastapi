from typing import List
from fastapi import APIRouter, Depends, HTTPException ,status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.db.db_connection import get_db
from database.models import models
from database.schemas import schemas
from database.auth.oauth2 import get_current_user
from database.models.models import User, UserPushLimit


router = APIRouter(
    prefix="/admin",
    tags=["Admin"]
)

@router.post("/api/admin/set_push_limit")
async def set_push_limit(
    user_id: int, 
    max_pushes: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user_limit = db.query(UserPushLimit).filter(UserPushLimit.user_id == user_id).first()
    if not user_limit:
        user_limit = UserPushLimit(user_id=user_id, max_concurrent_pushes=max_pushes)
        db.add(user_limit)
    else:
        user_limit.max_concurrent_pushes = max_pushes
    
    db.commit()
    return {"success": True, "new_limit": max_pushes}


class RoleUpdate(BaseModel):
    role: str

class TagUpdate(BaseModel):
    tag: str

class PushLimitUpdate(BaseModel):
    max_pushes: int

# Update the get_all_users endpoint to ensure consistent response
@router.get("/users", response_model=List[schemas.UserOut])
async def get_all_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all users (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can access this endpoint"
        )
    
    users = db.query(User).all()
    for user in users:
        user_limit = db.query(UserPushLimit).filter(UserPushLimit.user_id == user.id).first()
        
        # Set default push limit if none exists
        if not user_limit:
            user_limit = UserPushLimit(user_id=user.id, max_concurrent_pushes=1)
            db.add(user_limit)
            db.commit()
            db.refresh(user_limit)
        
        # Convert UserPushLimit object to dictionary
        user.push_limit = {
            "max_concurrent_pushes": user_limit.max_concurrent_pushes,
            "current_pushes": user_limit.current_pushes
        }
    
    return users

@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    role_update: RoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update user role (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.role = role_update.role
    db.commit()
    return {"success": True, "new_role": user.role}


@router.put("/users/{user_id}/tag")
async def update_user_tag(
    user_id: int,
    tag_update: TagUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update user's allowed tag (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.allowed_tags = tag_update.tag
    db.commit()
    return {"success": True, "new_tag": user.allowed_tags}

@router.put("/users/{user_id}/push-limit")
async def update_push_limit(
    user_id: int,
    limit_update: PushLimitUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update user's push limit (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # First fetch the current limit from database
    user_limit = db.query(UserPushLimit).filter(UserPushLimit.user_id == user_id).first()
    
    if not user_limit:
        # If no limit exists, create new with default 1
        original_limit = 1
        user_limit = UserPushLimit(
            user_id=user_id,
            max_concurrent_pushes=limit_update.max_pushes,
            current_pushes=0
        )
        db.add(user_limit)
    else:
        # Store original value before updating
        original_limit = user_limit.max_concurrent_pushes
        user_limit.max_concurrent_pushes = limit_update.max_pushes
    
    try:
        db.commit()
        db.refresh(user_limit)
        return {
            "success": True,
            "new_limit": limit_update.max_pushes,
            "original_limit": original_limit
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update push limit: {str(e)}"
        )
    
