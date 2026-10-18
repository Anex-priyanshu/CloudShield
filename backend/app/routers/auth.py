"""Auth router: login and current user."""
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from collections import defaultdict
import time

from app.db import get_db
from app.models import User
from app.schemas import LoginRequest, TokenResponse, UserOut
from app.auth import hash_password, verify_password, create_access_token, get_current_user
from app.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])

# Simple in-memory rate limiter: 5 attempts per IP per minute
_login_attempts: dict = defaultdict(list)


def _check_rate_limit(ip: str):
    now = time.time()
    attempts = _login_attempts[ip]
    # Remove attempts older than 60s
    _login_attempts[ip] = [t for t in attempts if now - t < 60]
    if len(_login_attempts[ip]) >= 5:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again in a minute.",
        )
    _login_attempts[ip].append(now)


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = create_access_token(
        {"sub": str(user.id), "email": user.email, "role": user.role.value},
        timedelta(minutes=settings.access_token_expire_minutes),
    )
    return TokenResponse(access_token=token, role=user.role.value, email=user.email)


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return current_user
