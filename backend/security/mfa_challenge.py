import hashlib
from datetime import datetime, timezone, timedelta

from sqlalchemy import update
from sqlalchemy.orm import Session

from backend.models.mfa_pending_challenge import MFAPendingChallenge


MFA_CHALLENGE_TTL_SECONDS = 300


def hash_mfa_challenge_jti(jti: str) -> str:
    return hashlib.sha256(
        jti.encode("utf-8")
    ).hexdigest()


def create_mfa_pending_challenge(
    db: Session,
    user_id: int,
    jti: str,
    ip_address: str | None,
) -> MFAPendingChallenge:
    now = datetime.now(timezone.utc)
    issued_at = now.isoformat()
    expires_at = (
        now + timedelta(seconds=MFA_CHALLENGE_TTL_SECONDS)
    ).isoformat()

    # Remove expired challenges for this user to keep the table bounded.
    db.query(MFAPendingChallenge).filter(
        MFAPendingChallenge.user_id == user_id,
        MFAPendingChallenge.expires_at < issued_at,
    ).delete(synchronize_session=False)

    record = MFAPendingChallenge(
        challenge_hash=hash_mfa_challenge_jti(jti),
        user_id=user_id,
        issued_at=issued_at,
        expires_at=expires_at,
        used=0,
        used_at=None,
        ip_address=ip_address,
    )

    db.add(record)
    db.commit()

    return record


def is_mfa_pending_challenge_valid(
    db: Session,
    challenge_hash: str,
    user_id: int,
) -> bool:
    now = datetime.now(timezone.utc).isoformat()

    record = (
        db.query(MFAPendingChallenge)
        .filter(
            MFAPendingChallenge.challenge_hash == challenge_hash,
            MFAPendingChallenge.user_id == user_id,
            MFAPendingChallenge.used == 0,
            MFAPendingChallenge.expires_at > now,
        )
        .first()
    )

    return record is not None


def consume_mfa_pending_challenge(
    db: Session,
    challenge_hash: str,
    user_id: int,
) -> bool:
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    result = db.execute(
        update(MFAPendingChallenge)
        .where(
            MFAPendingChallenge.challenge_hash == challenge_hash,
            MFAPendingChallenge.user_id == user_id,
            MFAPendingChallenge.used == 0,
            MFAPendingChallenge.expires_at > now_iso,
        )
        .values(
            used=1,
            used_at=now_iso,
        )
    )

    if result.rowcount != 1:
        db.rollback()
        return False

    db.commit()
    return True
