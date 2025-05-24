from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: EmailStr

class User(BaseModel):
    name: str
    email: EmailStr
    password1: str
    password2: str
    
    class Config:
        from_attributes = True  # Changed from orm_mode

class UserCreate(UserBase):
    password1: str
    password2: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(UserBase):
    id: int
    role: str
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str

class UpdateUser(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None

class UserBasicInfo(BaseModel):
    username: str
    email: EmailStr
    role: str

    class Config:
        from_attributes = True

class RoleUpdate(BaseModel):
    role: str  # 'user' or 'admin'