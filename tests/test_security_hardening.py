import pytest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from backend.main import app
from backend.security import login_limiter
from backend.database.connection import SessionLocal
from backend.models.session_token import Session as SessionModel
from backend.models.audit_log import AuditLog
from backend.config import settings

@pytest.fixture(autouse=True)
def reset_limiter():
    login_limiter.reset_all_for_tests()
    yield
    login_limiter.reset_all_for_tests()

def test_successful_login_and_valid_session_expiry():
    with TestClient(app) as client:
        username = f"user_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        reg_res = client.post("/auth/register", json={"username": username, "email": email, "password": password})
        assert reg_res.status_code == 201

        login_res = client.post("/auth/login", json={"username": username, "password": password})
        assert login_res.status_code == 200
        token_data = login_res.json()
        assert "access_token" in token_data
        assert "refresh_token" in token_data

        # Verify database session expiration timestamp
        db = SessionLocal()
        try:
            session = db.query(SessionModel).filter(SessionModel.user_id == reg_res.json()["id"]).first()
            assert session is not None
            assert session.expires_at != ""
            exp_dt = datetime.fromisoformat(session.expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            assert exp_dt > datetime.now(timezone.utc)
        finally:
            db.close()

def test_wrong_password_and_generic_error():
    with TestClient(app) as client:
        username = f"user_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        client.post("/auth/register", json={"username": username, "email": email, "password": password})

        res = client.post("/auth/login", json={"username": username, "password": "WrongPassword123!"})
        assert res.status_code == 401
        assert res.json()["detail"] == "Invalid username or password"

def test_repeated_failed_login_attempts_and_lockout():
    with TestClient(app) as client:
        username = f"lockuser_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        client.post("/auth/register", json={"username": username, "email": email, "password": password})

        # Fail max attempts
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            res = client.post("/auth/login", json={"username": username, "password": "WrongPassword!"})

        # Next attempt should be locked out (429)
        lock_res = client.post("/auth/login", json={"username": username, "password": password})
        assert lock_res.status_code == 429
        assert "Too many failed login attempts" in lock_res.json()["detail"]

def test_successful_login_clears_failure_state():
    with TestClient(app) as client:
        username = f"clearuser_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        client.post("/auth/register", json={"username": username, "email": email, "password": password})

        # 3 failed attempts (less than max 5)
        for _ in range(3):
            client.post("/auth/login", json={"username": username, "password": "WrongPassword!"})

        assert login_limiter.get_failure_count(username) == 3

        # Successful login
        ok_res = client.post("/auth/login", json={"username": username, "password": password})
        assert ok_res.status_code == 200

        # Counter cleared
        assert login_limiter.get_failure_count(username) == 0

def test_expired_session_rejected():
    with TestClient(app) as client:
        username = f"expuser_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        reg_res = client.post("/auth/register", json={"username": username, "email": email, "password": password})
        user_id = reg_res.json()["id"]

        login_res = client.post("/auth/login", json={"username": username, "password": password})
        refresh_token = login_res.json()["refresh_token"]

        # Manually expire the session in DB
        db = SessionLocal()
        try:
            past_dt = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            db.query(SessionModel).filter(SessionModel.user_id == user_id).update(
                {"expires_at": past_dt}
            )
            db.commit()
        finally:
            db.close()

        # Try to refresh with expired session
        ref_res = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert ref_res.status_code == 401
        assert "expired" in ref_res.json()["detail"].lower()

def test_refresh_rotation_and_old_token_reuse_rejected():
    with TestClient(app) as client:
        username = f"rotuser_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        client.post("/auth/register", json={"username": username, "email": email, "password": password})
        login_res = client.post("/auth/login", json={"username": username, "password": password})
        r1 = login_res.json()["refresh_token"]

        # 1st refresh -> gets new token r2
        ref1_res = client.post("/auth/refresh", json={"refresh_token": r1})
        assert ref1_res.status_code == 200
        r2 = ref1_res.json()["refresh_token"]
        assert r2 != r1

        # Reuse old token r1 -> rejected
        reuse_res = client.post("/auth/refresh", json={"refresh_token": r1})
        assert reuse_res.status_code == 401

        # Verify REFRESH_TOKEN_REUSE_ATTEMPT is recorded in audit log
        db = SessionLocal()
        try:
            audit_entry = db.query(AuditLog).filter(
                AuditLog.action == "REFRESH_TOKEN_REUSE_ATTEMPT"
            ).order_by(AuditLog.id.desc()).first()
            assert audit_entry is not None, "REFRESH_TOKEN_REUSE_ATTEMPT audit event was not logged"
            assert audit_entry.success == 0
        finally:
            db.close()

        # New token r2 still valid
        ref2_res = client.post("/auth/refresh", json={"refresh_token": r2})
        assert ref2_res.status_code == 200

def test_logout_revokes_session():
    with TestClient(app) as client:
        username = f"logoutuser_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        client.post("/auth/register", json={"username": username, "email": email, "password": password})
        login_res = client.post("/auth/login", json={"username": username, "password": password})
        token = login_res.json()["access_token"]
        refresh_token = login_res.json()["refresh_token"]

        # Logout
        logout_res = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"}, json={"refresh_token": refresh_token})
        assert logout_res.status_code == 200

        # Attempt to use revoked access token
        me_res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 401

        # Attempt to refresh with revoked refresh token
        ref_res = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert ref_res.status_code == 401

def test_password_policy():
    with TestClient(app) as client:
        # Too short (<10 chars, e.g. 8 chars)
        res_short = client.post("/auth/register", json={"username": "usr1", "email": "usr1@example.com", "password": "Short123"})
        assert res_short.status_code == 400
        assert "at least" in res_short.json()["detail"]

        # Common weak password
        res_weak = client.post("/auth/register", json={"username": "usr2", "email": "usr2@example.com", "password": "password12345"})
        assert res_weak.status_code == 400
        assert "too common" in res_weak.json()["detail"].lower()

        # Repeated single character
        res_repeat = client.post("/auth/register", json={"username": "usr3", "email": "usr3@example.com", "password": "aaaaaaaaaaaa"})
        assert res_repeat.status_code == 400
        assert "repeated" in res_repeat.json()["detail"].lower()

def test_safe_auth_errors_account_enumeration_prevention():
    with TestClient(app) as client:
        res1 = client.post("/auth/login", json={"username": "nonexistent_user_999", "password": "SomePassword123!"})
        assert res1.status_code == 401
        assert res1.json()["detail"] == "Invalid username or password"

        # Register user
        client.post("/auth/register", json={"username": "exist_user", "email": "exist_user@example.com", "password": "StrongPassword123!"})

        res2 = client.post("/auth/login", json={"username": "exist_user", "password": "WrongPassword123!"})
        assert res2.status_code == 401
        assert res2.json()["detail"] == "Invalid username or password"

def test_change_password_endpoint():
    with TestClient(app) as client:
        username = f"chgpwd_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        old_pwd = "OldPassword123!"
        new_pwd = "NewPassword123!"

        client.post("/auth/register", json={"username": username, "email": email, "password": old_pwd})
        login_res = client.post("/auth/login", json={"username": username, "password": old_pwd})
        token = login_res.json()["access_token"]

        # Change password
        chg_res = client.post(
            "/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": old_pwd, "new_password": new_pwd}
        )
        assert chg_res.status_code == 200

        # Login with old password fails
        fail_res = client.post("/auth/login", json={"username": username, "password": old_pwd})
        assert fail_res.status_code == 401

        # Login with new password succeeds
        ok_res = client.post("/auth/login", json={"username": username, "password": new_pwd})
        assert ok_res.status_code == 200

def test_attacker_cannot_globally_lock_user_on_different_ip():
    with TestClient(app) as client:
        username = f"dos_target_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        orig_trust = settings.TRUST_PROXY_HEADERS
        orig_proxies = settings.TRUSTED_PROXIES
        settings.TRUST_PROXY_HEADERS = True
        settings.TRUSTED_PROXIES = "testclient,127.0.0.1"

        try:
            client.post("/auth/register", json={"username": username, "email": email, "password": password})

            # Attacker IP (X-Forwarded-For: 10.0.0.1) performs max failed attempts
            for _ in range(settings.LOGIN_MAX_ATTEMPTS):
                res = client.post(
                    "/auth/login",
                    json={"username": username, "password": "WrongPassword!"},
                    headers={"X-Forwarded-For": "10.0.0.1"}
                )

            # Attacker IP 10.0.0.1 is now locked for this username
            att_res = client.post(
                "/auth/login",
                json={"username": username, "password": password},
                headers={"X-Forwarded-For": "10.0.0.1"}
            )
            assert att_res.status_code == 429

            # Legitimate user IP 192.168.1.50 CAN STILL LOG IN!
            legit_res = client.post(
                "/auth/login",
                json={"username": username, "password": password},
                headers={"X-Forwarded-For": "192.168.1.50"}
            )
            assert legit_res.status_code == 200
        finally:
            settings.TRUST_PROXY_HEADERS = orig_trust
            settings.TRUSTED_PROXIES = orig_proxies

def test_untrusted_proxy_header_ignored():
    with TestClient(app) as client:
        orig_trust = settings.TRUST_PROXY_HEADERS
        settings.TRUST_PROXY_HEADERS = False

        try:
            username = f"untrusted_ip_{uuid.uuid4().hex[:8]}"
            email = f"{username}@example.com"
            password = "StrongPassword123!"

            client.post("/auth/register", json={"username": username, "email": email, "password": password})

            # Fake X-Forwarded-For sent, but TRUST_PROXY_HEADERS is False
            for i in range(settings.LOGIN_MAX_ATTEMPTS):
                client.post(
                    "/auth/login",
                    json={"username": username, "password": "WrongPassword!"},
                    headers={"X-Forwarded-For": f"1.2.3.{i}"}
                )

            # Untrusted header was ignored, so attempts mapped to real client host ("testclient")
            # Thus, client host gets locked out
            res = client.post("/auth/login", json={"username": username, "password": password})
            assert res.status_code == 429
        finally:
            settings.TRUST_PROXY_HEADERS = orig_trust

def test_limiter_memory_cleanup_and_eviction():
    limiter = login_limiter.LoginRateLimiter(max_user_ip_attempts=5, window_seconds=1)
    limiter.MAX_STORE_ENTRIES = 10

    # Record 25 failures for different users/IPs
    for i in range(25):
        limiter.record_failure(f"user_{i}", f"10.0.0.{i}")

    # Verify store size is strictly bounded to MAX_STORE_ENTRIES
    assert len(limiter._user_ip_attempts) <= 10
    assert len(limiter._ip_attempts) <= 10
