from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from datetime import datetime

# In your schemas.py
class TagsUpdate(BaseModel):
    tags: List[str]

class PushLimitUpdate(BaseModel):
    max_pushes: int = Field(ge=1, le=10)  # Adjust max limit as needed
    
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

# Update the UserOut schema in schemas.py to include push_limit
class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    allowed_tags: Optional[str] = None
    created_at: datetime
    push_limit: Optional[dict] = None  # This should be a dictionary
    
    class Config:
        from_attributes = True  # Changed from orm_mode

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