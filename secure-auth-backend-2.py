# secure_api.py
# FastAPI backend with secure authentication and 2FA

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import hashlib
import hmac
import secrets
import jwt
import re
from enum import Enum

# ===== Configuration =====
SECRET_KEY = "your-secret-key-change-in-production-use-env-var"  # Use environment variable in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
TEMP_TOKEN_EXPIRE_MINUTES = 5  # For 2FA flow

# ===== Static User Database (In production, use a real database) =====
# Passwords are hashed using SHA256 (use bcrypt/scrypt/argon2 in production)
USERS_DB = {
    "admin": {
        "username": "admin",
        "hashed_password": hashlib.sha256("SecurePass123!".encode()).hexdigest(),
        "role": "admin",
        "email": "admin@example.com",
        "requires_2fa": True,
        "totp_secret": "JBSWY3DPEHPK3PXP",  # In production, generate unique secrets
        "failed_attempts": 0,
        "locked_until": None
    },
    "user": {
        "username": "user",
        "hashed_password": hashlib.sha256("UserPass456!".encode()).hexdigest(),
        "role": "user",
        "email": "user@example.com",
        "requires_2fa": True,
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "failed_attempts": 0,
        "locked_until": None
    }
}

# Store active refresh tokens (in production, use Redis/database)
REFRESH_TOKENS_STORE = {}

# Store used 2FA codes to prevent replay attacks
USED_2FA_CODES = {}

# ===== Models =====
class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=100)
    
    @validator('username')
    def validate_username(cls, v):
        # Prevent injection attacks
        if not re.match("^[a-zA-Z0-9_-]+$", v):
            raise ValueError("Invalid username format")
        return v

class TwoFactorRequest(BaseModel):
    code: str = Field(..., regex="^[0-9]{6}$")

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    user: Optional[Dict[str, Any]] = None
    requires_2fa: bool = False
    temp_token: Optional[str] = None

class RefreshRequest(BaseModel):
    refresh_token: str

class ProtectedDataResponse(BaseModel):
    message: str
    timestamp: datetime
    data: Dict[str, Any]

# ===== Security Utilities =====
def hash_password(password: str) -> str:
    """Hash password using SHA256 (use bcrypt in production)"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return hash_password(plain_password) == hashed_password

def create_token(data: dict, expires_delta: timedelta, token_type: str = "access") -> str:
    """Create JWT token with expiration"""
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": token_type,
        "jti": secrets.token_urlsafe(16)  # JWT ID for tracking
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> dict:
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

def verify_2fa_code(username: str, code: str) -> bool:
    """Verify 2FA code (simplified for demo - use pyotp in production)"""
    # Check if code was already used (replay attack prevention)
    code_key = f"{username}:{code}"
    if code_key in USED_2FA_CODES:
        if datetime.utcnow() - USED_2FA_CODES[code_key] < timedelta(minutes=5):
            return False
    
    # For demo purposes, accept "123456" as valid code
    # In production, use TOTP/HOTP with pyotp library
    if code == "123456":
        USED_2FA_CODES[code_key] = datetime.utcnow()
        # Clean old codes
        clean_old_2fa_codes()
        return True
    return False

def clean_old_2fa_codes():
    """Remove old used 2FA codes"""
    current_time = datetime.utcnow()
    expired_codes = [
        key for key, timestamp in USED_2FA_CODES.items()
        if current_time - timestamp > timedelta(minutes=10)
    ]
    for key in expired_codes:
        del USED_2FA_CODES[key]

def check_account_lockout(user: dict) -> bool:
    """Check if account is locked due to failed attempts"""
    if user.get("locked_until"):
        if datetime.utcnow() < user["locked_until"]:
            return True
        else:
            # Unlock account
            user["locked_until"] = None
            user["failed_attempts"] = 0
    return False

def handle_failed_attempt(username: str):
    """Handle failed login attempt"""
    if username in USERS_DB:
        user = USERS_DB[username]
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        
        # Lock account after 5 failed attempts
        if user["failed_attempts"] >= 5:
            user["locked_until"] = datetime.utcnow() + timedelta(minutes=15)
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account locked due to multiple failed attempts. Try again in 15 minutes."
            )

# ===== FastAPI App =====
app = FastAPI(title="Secure Auth API", version="1.0.0")

# CORS configuration (adjust origins in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:5500"],  # Adjust for your frontend
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Rate-Limit", "X-Rate-Limit-Remaining"]
)

# Security scheme
security = HTTPBearer()

# ===== Dependencies =====
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate access token and return current user"""
    token = credentials.credentials
    
    try:
        payload = decode_token(token)
        
        # Verify token type
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        username = payload.get("sub")
        if username is None or username not in USERS_DB:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )
        
        return USERS_DB[username]
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

async def verify_temp_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate temporary token for 2FA"""
    token = credentials.credentials
    
    try:
        payload = decode_token(token)
        
        # Verify token type
        if payload.get("type") != "temp_2fa":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type for 2FA"
            )
        
        username = payload.get("sub")
        if username is None or username not in USERS_DB:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )
        
        return username
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA token"
        )

# ===== Endpoints =====
@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "service": "Secure Auth API"
    }

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    """Login endpoint with 2FA support"""
    
    # Rate limiting check (implement with Redis in production)
    # For demo, we'll skip this
    
    # Validate user exists
    user = USERS_DB.get(request.username)
    if not user:
        handle_failed_attempt(request.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Check account lockout
    if check_account_lockout(user):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked. Please try again later."
        )
    
    # Verify password
    if not verify_password(request.password, user["hashed_password"]):
        handle_failed_attempt(request.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Reset failed attempts on successful password verification
    user["failed_attempts"] = 0
    user["locked_until"] = None
    
    # Check if 2FA is required
    if user.get("requires_2fa", False):
        # Create temporary token for 2FA flow
        temp_token = create_token(
            data={"sub": request.username},
            expires_delta=timedelta(minutes=TEMP_TOKEN_EXPIRE_MINUTES),
            token_type="temp_2fa"
        )
        
        return TokenResponse(
            access_token="",
            token_type="bearer",
            expires_in=0,
            requires_2fa=True,
            temp_token=temp_token
        )
    
    # Create tokens for non-2FA users
    access_token = create_token(
        data={"sub": request.username, "role": user["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access"
    )
    
    refresh_token = create_token(
        data={"sub": request.username},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        token_type="refresh"
    )
    
    # Store refresh token
    REFRESH_TOKENS_STORE[refresh_token] = {
        "username": request.username,
        "created_at": datetime.utcnow()
    }
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user={
            "username": user["username"],
            "role": user["role"],
            "email": user["email"]
        }
    )

@app.post("/api/auth/verify-2fa", response_model=TokenResponse)
async def verify_2fa(
    request: TwoFactorRequest,
    username: str = Depends(verify_temp_token)
):
    """Verify 2FA code and complete login"""
    
    user = USERS_DB[username]
    
    # Verify 2FA code
    if not verify_2fa_code(username, request.code):
        # Track failed 2FA attempts
        handle_failed_attempt(username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code"
        )
    
    # Reset failed attempts
    user["failed_attempts"] = 0
    
    # Create access and refresh tokens
    access_token = create_token(
        data={"sub": username, "role": user["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access"
    )
    
    refresh_token = create_token(
        data={"sub": username},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        token_type="refresh"
    )
    
    # Store refresh token
    REFRESH_TOKENS_STORE[refresh_token] = {
        "username": username,
        "created_at": datetime.utcnow()
    }
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user={
            "username": user["username"],
            "role": user["role"],
            "email": user["email"]
        }
    )

@app.post("/api/auth/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest):
    """Refresh access token using refresh token"""
    
    try:
        payload = decode_token(request.refresh_token)
        
        # Verify token type
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        # Check if refresh token is in store
        if request.refresh_token not in REFRESH_TOKENS_STORE:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        username = payload.get("sub")
        user = USERS_DB.get(username)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        # Create new access token
        access_token = create_token(
            data={"sub": username, "role": user["role"]},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            token_type="access"
        )
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not refresh token"
        )

@app.post("/api/auth/logout")
async def logout(
    current_user: dict = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Logout endpoint - invalidate refresh tokens"""
    
    # Remove all refresh tokens for this user
    tokens_to_remove = [
        token for token, data in REFRESH_TOKENS_STORE.items()
        if data["username"] == current_user["username"]
    ]
    
    for token in tokens_to_remove:
        del REFRESH_TOKENS_STORE[token]
    
    return {
        "message": "Successfully logged out",
        "timestamp": datetime.utcnow()
    }

@app.get("/api/protected/data", response_model=ProtectedDataResponse)
async def get_protected_data(current_user: dict = Depends(get_current_user)):
    """Protected endpoint requiring authentication"""
    
    # Check user permissions (role-based access control)
    if current_user["role"] == "admin":
        data = {
            "secret": "Admin-level classified information",
            "access_level": "ADMIN",
            "permissions": ["read", "write", "delete"]
        }
    else:
        data = {
            "secret": "User-level information",
            "access_level": "USER",
            "permissions": ["read"]
        }
    
    return ProtectedDataResponse(
        message=f"Hello {current_user['username']}, this is protected data!",
        timestamp=datetime.utcnow(),
        data=data
    )

@app.get("/api/admin/users")
async def get_all_users(current_user: dict = Depends(get_current_user)):
    """Admin-only endpoint"""
    
    # Check admin role
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    # Return sanitized user data
    users = []
    for username, user in USERS_DB.items():
        users.append({
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "requires_2fa": user.get("requires_2fa", False),
            "locked": user.get("locked_until") is not None
        })
    
    return {
        "users": users,
        "total": len(users),
        "timestamp": datetime.utcnow()
    }

# ===== Security Headers Middleware =====
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    # Remove server header
    response.headers.pop("Server", None)
    
    return response

# ===== Run the application =====
if __name__ == "__main__":
    import uvicorn
    
    # Run with SSL in production
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        # ssl_keyfile="path/to/key.pem",  # Uncomment in production
        # ssl_certfile="path/to/cert.pem"  # Uncomment in production
    )
            