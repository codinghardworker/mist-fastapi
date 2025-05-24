from typing import Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session
from database.auth.token import ALGORITHM, SECRET_KEY, verify_token
from database.models.models import User
from database.db.db_connection import get_db
import jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
def get_current_user(request: Request, db: Session = Depends(get_db)):
    """
    Extracts and verifies the token from the Authorization header, Cookie, or query parameter.
    Returns user data if the token is valid.
    """
    token = None
    
    # Try to get token from Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    
    # Try to get token from cookies
    if not token:
        token = request.cookies.get("access_token")
    
    # Try to get token from query parameter
    if not token:
        token = request.query_params.get("token")
    
    # Raise error if no token is found
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create exception for invalid or expired tokens
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Verify the token
        token_data = verify_token(token, credentials_exception)
        
        # Get the user from the database
        user = db.query(User).filter(User.email == token_data.email).first()
        
        if user is None:
            raise credentials_exception
            
        # Return the actual user object, not a dictionary
        return user
        
    except HTTPException as e:
        # Handle explicit HTTP exceptions (e.g., invalid credentials)
        raise e
    except JWTError:
        # Handle generic JWT decoding errors
        raise credentials_exception

async def get_current_user_optional(request: Request) -> Optional[User]:
    """Get current user if valid token exists, otherwise return None"""
    try:
        # Try to get the Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
            
        token = auth_header.split(" ")[1]
        
        # Verify the token (this will raise exceptions if invalid)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
            
        # Get user from database
        db = next(get_db())  # Get a new DB session
        user = db.query(User).filter(User.username == username).first()
        return user
        
    except Exception:
        # Catch all exceptions (JWTError, DB errors, etc)
        return None