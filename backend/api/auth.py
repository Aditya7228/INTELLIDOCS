import json
import io
import base64
import secrets
import hashlib
import hmac
import logging
import os
import threading
import time
from urllib.parse import urlencode
import pyotp
import qrcode
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Union
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.user_repo import UserRepository
from backend.schemas.auth_schema import UserRegister, UserLogin, TokenResponse, UserOut, RefreshTokenRequest, ChangePassword, PasswordResetRequest, PasswordResetConfirm, EmailChangeRequest, EmailChangeVerifyRequest
from backend.schemas.mfa_schema import (
    MFASetupInitiate, MFASetupInitiateResponse,
    MFASetupConfirm, MFASetupConfirmResponse,
    MFAVerifyRequest, MFARequestWithPassword, MFAStatusResponse
)
from backend.schemas.settings_schema import SessionOut
from backend.security.password import PasswordManager
from backend.security.jwt_handler import JWTHandler
from backend.security.encryption import SecretCipher
from backend.models.session_token import Session as SessionModel
from backend.models.user_mfa import UserMFA
from backend.models.user import User
from backend.models.password_reset_token import PasswordResetToken
from backend.models.email_change_otp import EmailChangeOTP
from backend.api.deps import get_current_user
from backend.core.audit_service import AuditService
from backend.security import login_limiter
from backend.security.mfa_limiter import mfa_rate_limiter
from backend.security.mfa_challenge import (
    create_mfa_pending_challenge,
    hash_mfa_challenge_jti,
    is_mfa_pending_challenge_valid,
    consume_mfa_pending_challenge,
)
from backend.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Auth"])

def _get_client_ip(request: Request) -> Optional[str]:
    client_host = request.client.host if request.client else None
    if settings.TRUST_PROXY_HEADERS and client_host:
        trusted = {p.strip() for p in settings.TRUSTED_PROXIES.split(",") if p.strip()}
        if client_host in trusted:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return forwarded.split(",")[0].strip()
    return client_host

def _is_expired(expires_at_str: Optional[str]) -> bool:
    if not expires_at_str:
        return True
    try:
        exp_dt = datetime.fromisoformat(expires_at_str)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= exp_dt
    except ValueError:
        return True

def _verify_mfa_code_or_recovery(
    db: Session,
    user_id: int,
    code: Optional[str],
    recovery_code: Optional[str],
    ip: Optional[str] = None,
) -> tuple[bool, str]:
    lock_status = mfa_rate_limiter.check_locked(user_id, ip)

    if lock_status.is_locked:
        raise HTTPException(
            status_code=429,
            detail=f"Too many MFA attempts. Try again in {lock_status.retry_after_seconds} seconds.",
        )

    mfa = db.query(UserMFA).filter(UserMFA.user_id == user_id).first()

    if not mfa or not mfa.is_enabled:
        return False, ""

    supplied_code = (code or "").strip()
    supplied_recovery = (recovery_code or "").strip()

    if supplied_code:
        try:
            secret = SecretCipher.decrypt(mfa.secret_encrypted)

            if pyotp.TOTP(secret).verify(
                supplied_code,
                valid_window=1,
            ):
                mfa_rate_limiter.record_success(user_id, ip)
                return True, "totp"

        except Exception:
            pass

    if supplied_recovery:
        code_hash = hashlib.sha256(
            supplied_recovery.encode("utf-8")
        ).hexdigest()

        recovery_codes = json.loads(
            mfa.recovery_codes_hash or "[]"
        )

        if code_hash in recovery_codes:
            recovery_codes.remove(code_hash)
            mfa.recovery_codes_hash = json.dumps(recovery_codes)
            db.commit()

            mfa_rate_limiter.record_success(user_id, ip)

            return True, "recovery"

    lock_status = mfa_rate_limiter.record_failure(
        user_id,
        ip,
    )

    if lock_status.is_locked:
        raise HTTPException(
            status_code=429,
            detail=f"Too many MFA attempts. Try again in {lock_status.retry_after_seconds} seconds.",
        )

    return False, ""

@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(data: UserRegister, request: Request, db: Session = Depends(get_db)):
    valid, msg = PasswordManager.validate_password(data.password)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    repo = UserRepository(db)
    if repo.get_by_username(data.username):
        raise HTTPException(status_code=400, detail="Username is already registered")
    if repo.get_by_email(data.email):
        raise HTTPException(status_code=400, detail="Email address is already registered")

    password_hash = PasswordManager.hash_password(data.password)
    user = repo.create_user(username=data.username, email=data.email, password_hash=password_hash)

    AuditService.log(
        db, action="USER_REGISTER", user_id=user.id,
        resource_type="user", resource_id=str(user.id),
        ip_address=_get_client_ip(request),
        user_agent=request.headers.get("user-agent")
    )
    return user

@router.post("/login", response_model=TokenResponse)
def login(data: UserLogin, request: Request, db: Session = Depends(get_db)):
    ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent")

    lock_status = login_limiter.check_locked(data.username, ip)
    if lock_status.is_locked:
        AuditService.log(
            db, action="LOGIN_LOCKED", user_id=None,
            ip_address=ip, user_agent=user_agent,
            detail={"attempted_username": data.username, "retry_after": lock_status.retry_after_seconds},
            success=0
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Please try again in {lock_status.retry_after_seconds} seconds.",
            headers={"Retry-After": str(lock_status.retry_after_seconds)}
        )

    repo = UserRepository(db)
    user = repo.get_by_username(data.username)

    if not user or not PasswordManager.verify_password(data.password, user.password_hash):
        fail_status = login_limiter.record_failure(data.username, ip)
        AuditService.log(
            db, action="LOGIN_FAILED", user_id=user.id if user else None,
            ip_address=ip, user_agent=user_agent,
            detail={"attempted_username": data.username}, success=0
        )
        if fail_status.is_locked:
            AuditService.log(
                db, action="LOGIN_LOCKED", user_id=user.id if user else None,
                ip_address=ip, user_agent=user_agent,
                detail={"attempted_username": data.username, "retry_after": fail_status.retry_after_seconds},
                success=0
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Please try again in {fail_status.retry_after_seconds} seconds.",
                headers={"Retry-After": str(fail_status.retry_after_seconds)}
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    # Check if MFA is enabled for user
    mfa = db.query(UserMFA).filter(UserMFA.user_id == user.id, UserMFA.is_enabled == 1).first()
    if mfa:
        # Require MFA verification challenge
        mfa_token = JWTHandler.create_mfa_token(user.id)

        mfa_payload = JWTHandler.decode_access_token(mfa_token)
        mfa_jti = mfa_payload.get("jti") if mfa_payload else None

        if not mfa_jti:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not initialize MFA challenge",
            )

        create_mfa_pending_challenge(
            db=db,
            user_id=user.id,
            jti=mfa_jti,
            ip_address=ip,
        )
        return TokenResponse(
            access_token=None,
            refresh_token=None,
            token_type="bearer",
            mfa_required=True,
            mfa_token=mfa_token
        )

    login_limiter.record_success(data.username, ip)

    access_token, jti = JWTHandler.create_access_token(user.id, user.role)
    raw_refresh, refresh_hash = JWTHandler.create_refresh_token()

    now_utc = datetime.now(timezone.utc)
    expires_at = (now_utc + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)).isoformat()

    repo.update_last_login(user.id, now_utc.isoformat())

    session_rec = SessionModel(
        jti=jti,
        user_id=user.id,
        token_hash=refresh_hash,
        issued_at=now_utc.isoformat(),
        expires_at=expires_at,
        revoked=0,
        ip_address=ip
    )
    db.add(session_rec)
    db.commit()

    AuditService.log(
        db, action="USER_LOGIN", user_id=user.id,
        ip_address=ip, user_agent=user_agent
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        token_type="bearer",
        mfa_required=False
    )

# --- MFA SETUP & VERIFICATION ---

@router.get("/mfa/status", response_model=MFAStatusResponse)
def get_mfa_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    mfa = db.query(UserMFA).filter(UserMFA.user_id == current_user.id).first()
    if not mfa or mfa.is_enabled == 0:
        return MFAStatusResponse(is_enabled=False, has_recovery_codes=False, remaining_recovery_codes=0)

    hashes = json.loads(mfa.recovery_codes_hash) if mfa.recovery_codes_hash else []
    return MFAStatusResponse(
        is_enabled=True,
        has_recovery_codes=len(hashes) > 0,
        remaining_recovery_codes=len(hashes)
    )

@router.post("/mfa/setup/initiate", response_model=MFASetupInitiateResponse)
def initiate_mfa_setup(
    data: MFASetupInitiate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Password re-authentication
    if not PasswordManager.verify_password(data.password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    raw_secret = pyotp.random_base32()
    enc_secret = SecretCipher.encrypt(raw_secret)

    mfa = db.query(UserMFA).filter(UserMFA.user_id == current_user.id).first()
    if not mfa:
        mfa = UserMFA(user_id=current_user.id, secret_encrypted=enc_secret, is_enabled=0)
        db.add(mfa)
    else:
        mfa.secret_encrypted = enc_secret
        mfa.is_enabled = 0
        mfa.updated_at = datetime.now(timezone.utc).isoformat()

    db.commit()

    totp = pyotp.TOTP(raw_secret)
    otpauth_url = totp.provisioning_uri(name=current_user.email, issuer_name="IntelliDocs")

    img = qrcode.make(otpauth_url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")

    return MFASetupInitiateResponse(
        secret=raw_secret,
        otpauth_url=otpauth_url,
        qr_code_base64=qr_b64
    )

@router.post("/mfa/setup/confirm", response_model=MFASetupConfirmResponse)
def confirm_mfa_setup(
    data: MFASetupConfirm,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ip = _get_client_ip(request)
    mfa = db.query(UserMFA).filter(UserMFA.user_id == current_user.id).first()
    if not mfa or not mfa.secret_encrypted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA setup has not been initiated")

    raw_secret = SecretCipher.decrypt(mfa.secret_encrypted)
    totp = pyotp.TOTP(raw_secret)
    if not totp.verify(data.code.strip(), valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 6-digit verification code")

    mfa.is_enabled = 1
    mfa.updated_at = datetime.now(timezone.utc).isoformat()

    # Generate 8 single-use recovery codes
    raw_codes = [secrets.token_hex(16).upper() for _ in range(8)]
    formatted_codes = [f"{c[:4]}-{c[4:]}" for c in raw_codes]
    code_hashes = [hashlib.sha256(c.encode("utf-8")).hexdigest() for c in formatted_codes]

    mfa.recovery_codes_hash = json.dumps(code_hashes)
    db.commit()

    AuditService.log(
        db, action="MFA_ENABLED", user_id=current_user.id,
        ip_address=ip, user_agent=request.headers.get("user-agent")
    )

    return MFASetupConfirmResponse(
        is_enabled=True,
        recovery_codes=formatted_codes
    )

@router.post("/mfa/verify", response_model=TokenResponse)
def verify_mfa_login(
    data: MFAVerifyRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent")

    payload = JWTHandler.decode_access_token(data.mfa_token)
    if not payload or payload.get("type") != "mfa_pending":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA token")

    user_id = int(payload.get("sub"))
    repo = UserRepository(db)
    user = repo.get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account no longer active")

    mfa_jti = payload.get("jti")
    if not mfa_jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )

    challenge_hash = hash_mfa_challenge_jti(mfa_jti)

    if not is_mfa_pending_challenge_valid(
        db,
        challenge_hash,
        user.id,
    ):
        AuditService.log(
            db,
            action="MFA_CHALLENGE_REPLAY_OR_EXPIRED",
            user_id=user.id,
            ip_address=ip,
            user_agent=user_agent,
            success=0,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or already used MFA challenge",
        )

    ok, mode = _verify_mfa_code_or_recovery(
        db,
        user.id,
        data.code,
        data.recovery_code,
        ip,
    )
    if not ok:
        AuditService.log(db, action="MFA_VERIFY_FAILED", user_id=user.id, ip_address=ip, user_agent=user_agent, success=0)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=mode)

    if mode == "recovery":
        AuditService.log(db, action="MFA_RECOVERY_CODE_USED", user_id=user.id, ip_address=ip, user_agent=user_agent)

    if not consume_mfa_pending_challenge(
        db,
        challenge_hash,
        user.id,
    ):
        AuditService.log(
            db,
            action="MFA_CHALLENGE_REPLAY_OR_RACE",
            user_id=user.id,
            ip_address=ip,
            user_agent=user_agent,
            success=0,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA challenge has already been used or expired",
        )

    login_limiter.record_success(user.username, ip)
    access_token, jti = JWTHandler.create_access_token(user.id, user.role)
    raw_refresh, refresh_hash = JWTHandler.create_refresh_token()

    now_utc = datetime.now(timezone.utc)
    expires_at = (now_utc + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)).isoformat()

    repo.update_last_login(user.id, now_utc.isoformat())

    session_rec = SessionModel(
        jti=jti,
        user_id=user.id,
        token_hash=refresh_hash,
        issued_at=now_utc.isoformat(),
        expires_at=expires_at,
        revoked=0,
        ip_address=ip
    )
    db.add(session_rec)
    db.commit()

    AuditService.log(
        db, action="USER_LOGIN", user_id=user.id,
        ip_address=ip, user_agent=user_agent
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        token_type="bearer",
        mfa_required=False
    )

@router.post("/mfa/recovery-codes/regenerate", status_code=status.HTTP_200_OK)
def regenerate_recovery_codes(
    data: MFARequestWithPassword,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ip = _get_client_ip(request)
    if not PasswordManager.verify_password(data.password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    ok, mode = _verify_mfa_code_or_recovery(db, current_user.id, data.code, data.recovery_code, ip)
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=mode)

    mfa = db.query(UserMFA).filter(UserMFA.user_id == current_user.id).first()
    raw_codes = [secrets.token_hex(16).upper() for _ in range(8)]
    formatted_codes = [f"{c[:4]}-{c[4:]}" for c in raw_codes]
    code_hashes = [hashlib.sha256(c.encode("utf-8")).hexdigest() for c in formatted_codes]

    mfa.recovery_codes_hash = json.dumps(code_hashes)
    mfa.updated_at = datetime.now(timezone.utc).isoformat()
    db.commit()

    AuditService.log(
        db, action="MFA_RECOVERY_CODES_REGENERATED", user_id=current_user.id,
        ip_address=ip, user_agent=request.headers.get("user-agent")
    )

    return {"recovery_codes": formatted_codes}

@router.post("/mfa/disable", status_code=status.HTTP_200_OK)
def disable_mfa(
    data: MFARequestWithPassword,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ip = _get_client_ip(request)
    if not PasswordManager.verify_password(data.password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    ok, mode = _verify_mfa_code_or_recovery(db, current_user.id, data.code, data.recovery_code, ip)
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=mode)

    mfa = db.query(UserMFA).filter(UserMFA.user_id == current_user.id).first()
    if mfa:
        mfa.is_enabled = 0
        mfa.secret_encrypted = None
        mfa.recovery_codes_hash = None
        mfa.updated_at = datetime.now(timezone.utc).isoformat()

    # Revoke all active sessions for the user
    now_iso = datetime.now(timezone.utc).isoformat()
    db.query(SessionModel).filter(
        SessionModel.user_id == current_user.id,
        SessionModel.revoked == 0
    ).update({"revoked": 1, "revoked_at": now_iso})

    db.commit()

    AuditService.log(
        db, action="MFA_DISABLED", user_id=current_user.id,
        ip_address=ip, user_agent=request.headers.get("user-agent")
    )

    return {"detail": "MFA disabled successfully and active sessions revoked"}

# --- REFRESH & LOGOUT & CHANGE PASSWORD ---

@router.post("/refresh", response_model=TokenResponse)
def refresh_token(data: RefreshTokenRequest, request: Request, db: Session = Depends(get_db)):
    ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent")

    refresh_hash = JWTHandler.hash_token(data.refresh_token)

    session_rec = db.query(SessionModel).filter(
        SessionModel.token_hash == refresh_hash
    ).first()

    if not session_rec:
        AuditService.log(
            db, action="REFRESH_TOKEN_REJECTED", ip_address=ip, user_agent=user_agent,
            detail={"reason": "token_not_found"}, success=0
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked refresh token")

    if session_rec.revoked == 1:
        AuditService.log(
            db, action="REFRESH_TOKEN_REUSE_ATTEMPT", user_id=session_rec.user_id,
            ip_address=ip, user_agent=user_agent,
            detail={"jti": session_rec.jti}, success=0
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked refresh token")

    if _is_expired(session_rec.expires_at):
        AuditService.log(
            db, action="REFRESH_TOKEN_REJECTED", user_id=session_rec.user_id,
            ip_address=ip, user_agent=user_agent,
            detail={"reason": "session_expired", "jti": session_rec.jti}, success=0
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    repo = UserRepository(db)
    user = repo.get_by_id(session_rec.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account no longer active")

    now_utc = datetime.now(timezone.utc)
    session_rec.revoked = 1
    session_rec.revoked_at = now_utc.isoformat()

    access_token, new_jti = JWTHandler.create_access_token(user.id, user.role)
    new_raw_refresh, new_refresh_hash = JWTHandler.create_refresh_token()
    expires_at = (now_utc + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)).isoformat()

    new_session = SessionModel(
        jti=new_jti,
        user_id=user.id,
        token_hash=new_refresh_hash,
        issued_at=now_utc.isoformat(),
        expires_at=expires_at,
        revoked=0,
        ip_address=ip
    )
    db.add(new_session)
    db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_raw_refresh,
        token_type="bearer",
        mfa_required=False
    )

@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(
    request: Request,
    data: Optional[RefreshTokenRequest] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent")

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        payload = JWTHandler.decode_access_token(token)
        if payload and payload.get("jti"):
            jti = payload.get("jti")
            session_rec = db.query(SessionModel).filter(
                SessionModel.jti == jti,
                SessionModel.user_id == current_user.id
            ).first()
            if session_rec and session_rec.revoked == 0:
                session_rec.revoked = 1
                session_rec.revoked_at = datetime.now(timezone.utc).isoformat()

    if data and data.refresh_token:
        refresh_hash = JWTHandler.hash_token(data.refresh_token)
        session_rec2 = db.query(SessionModel).filter(
            SessionModel.token_hash == refresh_hash,
            SessionModel.user_id == current_user.id
        ).first()
        if session_rec2 and session_rec2.revoked == 0:
            session_rec2.revoked = 1
            session_rec2.revoked_at = datetime.now(timezone.utc).isoformat()

    db.commit()

    AuditService.log(
        db, action="USER_LOGOUT", user_id=current_user.id,
        ip_address=ip, user_agent=user_agent
    )
    return {"detail": "Successfully logged out"}

@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/change-password", status_code=status.HTTP_200_OK)
def change_password(
    data: ChangePassword,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = UserRepository(db)
    user = repo.get_by_id(current_user.id)
    if not user or not PasswordManager.verify_password(data.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    valid, msg = PasswordManager.validate_password(data.new_password)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    new_hash = PasswordManager.hash_password(data.new_password)
    repo.update_password(user.id, new_hash)

    AuditService.log(
        db, action="PASSWORD_CHANGE", user_id=user.id,
        ip_address=_get_client_ip(request),
        user_agent=request.headers.get("user-agent")
    )
    return {"detail": "Password changed successfully"}

# --- ACTIVE SESSIONS MANAGEMENT ---

@router.get("/sessions", response_model=List[SessionOut])
def list_active_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_jti = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        payload = JWTHandler.decode_access_token(token)
        if payload:
            current_jti = payload.get("jti")

    sessions = db.query(SessionModel).filter(
        SessionModel.user_id == current_user.id,
        SessionModel.revoked == 0
    ).all()

    result = []
    for s in sessions:
        if not _is_expired(s.expires_at):
            result.append(SessionOut(
                jti=s.jti,
                issued_at=s.issued_at,
                expires_at=s.expires_at,
                ip_address=s.ip_address,
                is_current=(s.jti == current_jti)
            ))
    return result

@router.delete("/sessions/{jti}", status_code=status.HTTP_200_OK)
@router.post("/sessions/{jti}/revoke", status_code=status.HTTP_200_OK)
def revoke_session(
    jti: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    session_rec = db.query(SessionModel).filter(
        SessionModel.jti == jti,
        SessionModel.user_id == current_user.id
    ).first()

    if not session_rec:
        raise HTTPException(status_code=404, detail="Session not found")

    session_rec.revoked = 1
    session_rec.revoked_at = datetime.now(timezone.utc).isoformat()
    db.commit()

    AuditService.log(
        db, action="SESSION_REVOKED", user_id=current_user.id,
        resource_type="session", resource_id=jti,
        ip_address=_get_client_ip(request),
        user_agent=request.headers.get("user-agent")
    )
    return {"detail": "Session revoked successfully"}

# --- PASSWORD RESET (additive V1) ---
_PASSWORD_RESET_REQUESTS: dict[str, list[float]] = {}
_PASSWORD_RESET_LOCK = threading.Lock()
_PASSWORD_RESET_GENERIC_MESSAGE = (
    "If an active account matches that email and email delivery is configured, "
    "password reset instructions will be sent shortly."
)


def _password_reset_ip_allowed(ip_address: Optional[str]) -> bool:
    """Process-local safety limit: max 10 requests per IP in 15 minutes."""
    now = time.monotonic()
    key = ip_address or "unknown"
    with _PASSWORD_RESET_LOCK:
        recent = [stamp for stamp in _PASSWORD_RESET_REQUESTS.get(key, []) if now - stamp < 900]
        if len(recent) >= 10:
            _PASSWORD_RESET_REQUESTS[key] = recent
            return False
        recent.append(now)
        _PASSWORD_RESET_REQUESTS[key] = recent
        # Bound memory if many different IPs are seen.
        if len(_PASSWORD_RESET_REQUESTS) > 2000:
            for old_key in list(_PASSWORD_RESET_REQUESTS)[:500]:
                if not _PASSWORD_RESET_REQUESTS.get(old_key):
                    _PASSWORD_RESET_REQUESTS.pop(old_key, None)
        return True


def _password_reset_smtp_config() -> Optional[dict[str, object]]:
    """Read credentials at request time; AUTH_* takes priority over SUPPORT_*.

    Configure AUTH_SMTP_HOST/PORT/USER/PASS/FROM, AUTH_PUBLIC_URL. Existing
    SUPPORT_SMTP_* variables are accepted as a convenient local fallback.
    """
    host = (os.getenv("AUTH_SMTP_HOST") or os.getenv("SUPPORT_SMTP_HOST") or "").strip()
    user = (os.getenv("AUTH_SMTP_USER") or os.getenv("SUPPORT_SMTP_USER") or "").strip()
    password = os.getenv("AUTH_SMTP_PASS") or os.getenv("SUPPORT_SMTP_PASS") or ""
    sender = (os.getenv("AUTH_SMTP_FROM") or os.getenv("SUPPORT_SMTP_FROM") or user).strip()
    raw_port = os.getenv("AUTH_SMTP_PORT") or os.getenv("SUPPORT_SMTP_PORT") or "587"
    try:
        port = int(raw_port)
    except ValueError:
        return None
    if not host or not sender or not (1 <= port <= 65535):
        return None
    if bool(user) != bool(password):
        return None
    public_url = (os.getenv("AUTH_PUBLIC_URL") or "http://127.0.0.1:8000").strip().rstrip("/")
    if not public_url.startswith(("https://", "http://")):
        return None
    return {"host": host, "port": port, "user": user, "password": password, "sender": sender, "public_url": public_url}


def _send_password_reset_email(recipient: str, reset_url: str, config: dict[str, object]) -> None:
    from email.message import EmailMessage
    from html import escape
    import smtplib
    import ssl

    message = EmailMessage()
    message["Subject"] = "Reset your IntelliDocs password"
    message["From"] = f"IntelliDocs <{config['sender']}>"
    message["To"] = recipient
    message.set_content(
        "We received a request to reset your IntelliDocs password.\n\n"
        f"Use this one-time link within 30 minutes: {reset_url}\n\n"
        "If you did not request this, you can ignore this email. Your password will not change.\n"
    )
    safe_url = escape(reset_url, quote=True)
    message.add_alternative(
        "<html><body style=\"font-family:Arial,sans-serif;color:#20233a\">"
        "<h2>Reset your IntelliDocs password</h2>"
        "<p>We received a request to reset your password.</p>"
        f"<p><a href=\"{safe_url}\" style=\"display:inline-block;padding:12px 18px;"
        "background:#6d55d9;color:#fff;text-decoration:none;border-radius:8px\">Reset password</a></p>"
        "<p>This one-time link expires in 30 minutes. If you did not request this, ignore this email.</p>"
        "</body></html>", subtype="html"
    )

    host, port = str(config["host"]), int(config["port"])
    user, password = str(config["user"]), str(config["password"])
    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=12, context=context) as server:
            if user:
                server.login(user, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=12) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if user:
                server.login(user, password)
            server.send_message(message)


@router.post("/forgot-password", status_code=status.HTTP_200_OK)
def request_password_reset(
    data: PasswordResetRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    ip_address = _get_client_ip(request)
    # Always return the same public response to avoid account enumeration.
    if not _password_reset_ip_allowed(ip_address):
        return {"message": _PASSWORD_RESET_GENERIC_MESSAGE}

    mail_config = _password_reset_smtp_config()
    if mail_config is None:
        # Do not create an unusable token or pretend delivery succeeded.
        logger.warning("Password reset requested while SMTP is not configured")
        return {"message": _PASSWORD_RESET_GENERIC_MESSAGE}

    user = db.query(User).filter(
        User.email.ilike(str(data.email)),
        User.is_active == 1,
    ).first()
    if not user:
        return {"message": _PASSWORD_RESET_GENERIC_MESSAGE}

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    cutoff_iso = (now - timedelta(minutes=15)).isoformat()
    recent_for_user = db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.created_at >= cutoff_iso,
    ).count()
    if recent_for_user >= 3:
        return {"message": _PASSWORD_RESET_GENERIC_MESSAGE}

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    # Invalidate previously unused reset links for this user before issuing a new one.
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None),
    ).update({"used_at": now_iso}, synchronize_session=False)
    record = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        created_at=now_iso,
        expires_at=(now + timedelta(minutes=30)).isoformat(),
        requested_ip=ip_address,
    )
    db.add(record)
    db.commit()

    reset_query = urlencode({"reset_token": raw_token})
    reset_url = f"{mail_config['public_url']}/?{reset_query}"
    try:
        _send_password_reset_email(user.email, reset_url, mail_config)
    except Exception:
        logger.exception("Password reset email delivery failed")
        record.used_at = datetime.now(timezone.utc).isoformat()
        db.commit()
    return {"message": _PASSWORD_RESET_GENERIC_MESSAGE}


@router.post("/reset-password", status_code=status.HTTP_200_OK)
def complete_password_reset(
    data: PasswordResetConfirm,
    request: Request,
    db: Session = Depends(get_db),
):
    token_hash = hashlib.sha256(data.token.encode("utf-8")).hexdigest()
    record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash,
    ).first()
    if not record or record.used_at or _is_expired(record.expires_at):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired password reset link")

    user = db.query(User).filter(User.id == record.user_id, User.is_active == 1).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired password reset link")

    valid, msg = PasswordManager.validate_password(data.new_password)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    now_iso = datetime.now(timezone.utc).isoformat()
    user.password_hash = PasswordManager.hash_password(data.new_password)
    # Consume this token and every other outstanding token for the same account.
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None),
    ).update({"used_at": now_iso}, synchronize_session=False)
    # Revoke all existing sessions so an old refresh/access session cannot persist.
    db.query(SessionModel).filter(SessionModel.user_id == user.id).update(
        {"revoked": 1, "revoked_at": now_iso}, synchronize_session=False
    )
    db.commit()
    AuditService.log(
        db, action="PASSWORD_RESET_COMPLETED", user_id=user.id,
        ip_address=_get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return {"message": "Password reset successfully. Please sign in with your new password."}

# --- AUTHENTICATED EMAIL CHANGE WITH EMAIL OTP ---
def _email_change_otp_digest(code: str) -> str:
    """Use a server-side HMAC key; never store a six-digit OTP in plaintext."""
    import hmac

    pepper = (
        os.getenv("AUTH_OTP_PEPPER")
        or os.getenv("AUTH_SMTP_PASS")
        or os.getenv("SUPPORT_SMTP_PASS")
        or ""
    )
    if not pepper:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email OTP security is not configured. Configure SMTP credentials and retry.",
        )
    return hmac.new(pepper.encode("utf-8"), code.encode("ascii"), hashlib.sha256).hexdigest()


def _send_email_change_otp(recipient: str, code: str, config: dict[str, object]) -> None:
    from email.message import EmailMessage
    import smtplib
    import ssl

    message = EmailMessage()
    message["Subject"] = "Verify your new IntelliDocs email address"
    message["From"] = f"IntelliDocs <{config['sender']}>"
    message["To"] = recipient
    message.set_content(
        "You requested to change the email address on your IntelliDocs account.\n\n"
        f"Your verification code is: {code}\n\n"
        "This code expires in 10 minutes and can be used only once. "
        "If you did not request this change, you can ignore this email.\n"
    )
    message.add_alternative(
        "<html><body style=\"font-family:Arial,sans-serif;color:#20233a\">"
        "<h2>Verify your new IntelliDocs email</h2>"
        "<p>Enter this verification code in IntelliDocs to confirm your new email address:</p>"
        f"<p style=\"font-size:28px;font-weight:700;letter-spacing:6px\">{code}</p>"
        "<p>This code expires in 10 minutes and can be used only once.</p>"
        "<p>If you did not request this change, you can ignore this email.</p>"
        "</body></html>", subtype="html"
    )

    host, port = str(config["host"]), int(config["port"])
    user, password = str(config["user"]), str(config["password"])
    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=12, context=context) as server:
            if user:
                server.login(user, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=12) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            if user:
                server.login(user, password)
            server.send_message(message)


@router.post("/email-change/request", status_code=status.HTTP_200_OK)
def request_email_change_otp(
    data: EmailChangeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == current_user.id, User.is_active == 1).first()
    if not user or not PasswordManager.verify_password(data.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    target_email = str(data.new_email).strip().lower()
    if target_email.casefold() == str(user.email).strip().casefold():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New email is the same as your current email")
    duplicate = db.query(User).filter(User.email.ilike(target_email), User.id != user.id).first()
    if duplicate:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="That email address is already in use")

    mail_config = _password_reset_smtp_config()
    if mail_config is None:
        logger.warning("Email change OTP requested while SMTP is not configured")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Email delivery is not configured. Check SMTP settings and restart the backend.")

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    cutoff_iso = (now - timedelta(minutes=15)).isoformat()
    recent_count = db.query(EmailChangeOTP).filter(
        EmailChangeOTP.user_id == user.id,
        EmailChangeOTP.created_at >= cutoff_iso,
    ).count()
    if recent_count >= 3:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many email verification requests. Try again in 15 minutes.")

    try:
        code = f"{secrets.randbelow(1_000_000):06d}"
        digest = _email_change_otp_digest(code)
    except HTTPException:
        raise

    db.query(EmailChangeOTP).filter(
        EmailChangeOTP.user_id == user.id,
        EmailChangeOTP.used_at.is_(None),
    ).update({"used_at": now_iso}, synchronize_session=False)
    record = EmailChangeOTP(
        user_id=user.id,
        target_email=target_email,
        otp_digest=digest,
        created_at=now_iso,
        expires_at=(now + timedelta(minutes=10)).isoformat(),
        attempts=0,
    )
    db.add(record)
    db.commit()

    try:
        _send_email_change_otp(target_email, code, mail_config)
    except Exception as exc:
        logger.exception("Email change OTP delivery failed")
        record.used_at = datetime.now(timezone.utc).isoformat()
        db.commit()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The verification email could not be sent. Check the backend terminal for the SMTP error.") from exc

    logger.info("Email change OTP sent for user_id=%s", user.id)
    return {"message": "Verification code sent to the new email address. It expires in 10 minutes."}


@router.post("/email-change/verify", status_code=status.HTTP_200_OK)
def verify_email_change_otp(
    data: EmailChangeVerifyRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == current_user.id, User.is_active == 1).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is unavailable")

    target_email = str(data.new_email).strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()
    record = db.query(EmailChangeOTP).filter(
        EmailChangeOTP.user_id == user.id,
        EmailChangeOTP.target_email.ilike(target_email),
        EmailChangeOTP.used_at.is_(None),
    ).order_by(EmailChangeOTP.created_at.desc(), EmailChangeOTP.id.desc()).first()
    if not record or _is_expired(record.expires_at):
        if record and not record.used_at:
            record.used_at = now_iso
            db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The code is invalid or expired. Request a new code.")
    if record.attempts >= 5:
        record.used_at = now_iso
        db.commit()
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many incorrect attempts. Request a new code.")

    record.attempts += 1
    try:
        submitted_digest = _email_change_otp_digest(data.otp)
    except HTTPException:
        db.commit()
        raise
    import hmac
    if not hmac.compare_digest(record.otp_digest, submitted_digest):
        if record.attempts >= 5:
            record.used_at = now_iso
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The code is incorrect")

    duplicate = db.query(User).filter(User.email.ilike(target_email), User.id != user.id).first()
    if duplicate:
        record.used_at = now_iso
        db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="That email address is already in use")

    user.email = target_email
    record.used_at = now_iso
    db.query(EmailChangeOTP).filter(
        EmailChangeOTP.user_id == user.id,
        EmailChangeOTP.used_at.is_(None),
    ).update({"used_at": now_iso}, synchronize_session=False)
    db.commit()
    logger.info("Email address changed for user_id=%s", user.id)
    return {"message": "Email address verified and updated successfully.", "email": user.email}

