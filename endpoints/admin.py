from fastapi import APIRouter, Depends, HTTPException ,status
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

@router.get("/users", response_model=list[schemas.UserOut])
async def get_all_users(
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """Get all users (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can access this endpoint"
        )
    
    users = db.query(models.User).all()
    return users

@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    role_update: schemas.RoleUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """Update user role (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can access this endpoint"
        )
    
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.role = role_update.role
    db.commit()
    db.refresh(user)
    return user

