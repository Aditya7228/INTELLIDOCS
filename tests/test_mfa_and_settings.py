import pytest
import uuid
import json
import pyotp
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from backend.main import app
from backend.security import login_limiter
from backend.database.connection import SessionLocal
from backend.models.user_mfa import UserMFA
from backend.models.session_token import Session as SessionModel
from backend.security.encryption import SecretCipher

@pytest.fixture(autouse=True)
def reset_limiter():
    login_limiter.reset_all_for_tests()
    yield
    login_limiter.reset_all_for_tests()

def test_mfa_disabled_existing_login_works():
    with TestClient(app) as client:
        username = f"mfa_off_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        reg_res = client.post("/auth/register", json={"username": username, "email": email, "password": password})
        assert reg_res.status_code == 201

        login_res = client.post("/auth/login", json={"username": username, "password": password})
        assert login_res.status_code == 200
        data = login_res.json()
        assert data["mfa_required"] is False
        assert data["access_token"] is not None

def test_mfa_setup_requires_auth_and_valid_password():
    with TestClient(app) as client:
        username = f"mfa_init_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        client.post("/auth/register", json={"username": username, "email": email, "password": password})
        login_res = client.post("/auth/login", json={"username": username, "password": password})
        token = login_res.json()["access_token"]

        # No auth header -> 401
        res_noauth = client.post("/auth/mfa/setup/initiate", json={"password": password})
        assert res_noauth.status_code == 401

        # Wrong password -> 400
        res_wrongpwd = client.post(
            "/auth/mfa/setup/initiate",
            headers={"Authorization": f"Bearer {token}"},
            json={"password": "WrongPassword123!"}
        )
        assert res_wrongpwd.status_code == 400

        # Valid initiate
        res_ok = client.post(
            "/auth/mfa/setup/initiate",
            headers={"Authorization": f"Bearer {token}"},
            json={"password": password}
        )
        assert res_ok.status_code == 200
        data = res_ok.json()
        assert "secret" in data
        assert "otpauth_url" in data
        assert "qr_code_base64" in data
        assert data["qr_code_base64"].startswith("data:image/png;base64,")

def test_mfa_setup_confirm_valid_and_invalid_otp():
    with TestClient(app) as client:
        username = f"mfa_conf_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        client.post("/auth/register", json={"username": username, "email": email, "password": password})
        login_res = client.post("/auth/login", json={"username": username, "password": password})
        token = login_res.json()["access_token"]

        # Initiate
        init_res = client.post(
            "/auth/mfa/setup/initiate",
            headers={"Authorization": f"Bearer {token}"},
            json={"password": password}
        )
        secret = init_res.json()["secret"]

        # Invalid OTP -> 400
        bad_conf = client.post(
            "/auth/mfa/setup/confirm",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": "000000"}
        )
        assert bad_conf.status_code == 400

        # Valid OTP using pyotp
        valid_code = pyotp.TOTP(secret).now()
        ok_conf = client.post(
            "/auth/mfa/setup/confirm",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": valid_code}
        )
        assert ok_conf.status_code == 200
        data = ok_conf.json()
        assert data["is_enabled"] is True
        assert len(data["recovery_codes"]) == 8

def test_mfa_enabled_login_flow_otp_and_recovery():
    with TestClient(app) as client:
        username = f"mfa_flow_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        reg_res = client.post("/auth/register", json={"username": username, "email": email, "password": password})
        user_id = reg_res.json()["id"]

        login_res = client.post("/auth/login", json={"username": username, "password": password})
        token = login_res.json()["access_token"]

        # Setup MFA
        init_res = client.post(
            "/auth/mfa/setup/initiate",
            headers={"Authorization": f"Bearer {token}"},
            json={"password": password}
        )
        secret = init_res.json()["secret"]
        valid_code = pyotp.TOTP(secret).now()
        conf_res = client.post(
            "/auth/mfa/setup/confirm",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": valid_code}
        )
        recovery_codes = conf_res.json()["recovery_codes"]

        # Now login should return mfa_required
        mfa_login_res = client.post("/auth/login", json={"username": username, "password": password})
        assert mfa_login_res.status_code == 200
        mfa_data = mfa_login_res.json()
        assert mfa_data["mfa_required"] is True
        assert mfa_data["access_token"] is None
        mfa_token = mfa_data["mfa_token"]

        # Verify with bad OTP -> 401
        bad_verify = client.post("/auth/mfa/verify", json={"mfa_token": mfa_token, "code": "111222"})
        assert bad_verify.status_code == 401

        # Verify with valid OTP -> 200
        now_otp = pyotp.TOTP(secret).now()
        ok_verify = client.post("/auth/mfa/verify", json={"mfa_token": mfa_token, "code": now_otp})
        assert ok_verify.status_code == 200
        assert ok_verify.json()["access_token"] is not None

        # Test login with recovery code
        mfa_login2 = client.post("/auth/login", json={"username": username, "password": password})
        mfa_token2 = mfa_login2.json()["mfa_token"]
        rec_code = recovery_codes[0]

        rec_verify = client.post("/auth/mfa/verify", json={"mfa_token": mfa_token2, "recovery_code": rec_code})
        assert rec_verify.status_code == 200

        # Reuse recovery code -> 401
        mfa_login3 = client.post("/auth/login", json={"username": username, "password": password})
        mfa_token3 = mfa_login3.json()["mfa_token"]
        reuse_verify = client.post("/auth/mfa/verify", json={"mfa_token": mfa_token3, "recovery_code": rec_code})
        assert reuse_verify.status_code == 401

def test_recovery_codes_never_stored_plaintext_and_totp_secret_never_returned():
    with TestClient(app) as client:
        username = f"mfa_sec_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        reg_res = client.post("/auth/register", json={"username": username, "email": email, "password": password})
        user_id = reg_res.json()["id"]

        login_res = client.post("/auth/login", json={"username": username, "password": password})
        token = login_res.json()["access_token"]

        init_res = client.post(
            "/auth/mfa/setup/initiate",
            headers={"Authorization": f"Bearer {token}"},
            json={"password": password}
        )
        raw_secret = init_res.json()["secret"]
        valid_code = pyotp.TOTP(raw_secret).now()
        conf_res = client.post(
            "/auth/mfa/setup/confirm",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": valid_code}
        )
        recovery_codes = conf_res.json()["recovery_codes"]

        # Check DB UserMFA row
        db = SessionLocal()
        try:
            mfa = db.query(UserMFA).filter(UserMFA.user_id == user_id).first()
            assert mfa is not None
            assert mfa.secret_encrypted != raw_secret
            assert SecretCipher.decrypt(mfa.secret_encrypted) == raw_secret

            stored_hashes = json.loads(mfa.recovery_codes_hash)
            for c in recovery_codes:
                assert c not in mfa.recovery_codes_hash  # No plaintext in DB
        finally:
            db.close()

        # Check status endpoint
        status_res = client.get("/auth/mfa/status", headers={"Authorization": f"Bearer {token}"})
        assert status_res.status_code == 200
        st_data = status_res.json()
        assert "secret" not in st_data
        assert st_data["is_enabled"] is True
        assert st_data["remaining_recovery_codes"] == 8

def test_disable_mfa_requires_auth_password_otp_and_revokes_active_sessions():
    with TestClient(app) as client:
        username = f"mfa_dis_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        client.post("/auth/register", json={"username": username, "email": email, "password": password})
        login_res = client.post("/auth/login", json={"username": username, "password": password})
        token = login_res.json()["access_token"]

        # Setup MFA
        init_res = client.post(
            "/auth/mfa/setup/initiate",
            headers={"Authorization": f"Bearer {token}"},
            json={"password": password}
        )
        raw_secret = init_res.json()["secret"]
        valid_code = pyotp.TOTP(raw_secret).now()
        client.post(
            "/auth/mfa/setup/confirm",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": valid_code}
        )

        # Attempt disable with wrong password -> 400
        bad_dis = client.post(
            "/auth/mfa/disable",
            headers={"Authorization": f"Bearer {token}"},
            json={"password": "WrongPassword!", "code": pyotp.TOTP(raw_secret).now()}
        )
        assert bad_dis.status_code == 400

        # Valid disable
        now_code = pyotp.TOTP(raw_secret).now()
        ok_dis = client.post(
            "/auth/mfa/disable",
            headers={"Authorization": f"Bearer {token}"},
            json={"password": password, "code": now_code}
        )
        assert ok_dis.status_code == 200

        # Active session token is now revoked -> /auth/me returns 401
        me_res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 401

def test_active_sessions_owner_scoped_and_revocation():
    with TestClient(app) as client:
        u1 = f"sess_u1_{uuid.uuid4().hex[:8]}"
        u2 = f"sess_u2_{uuid.uuid4().hex[:8]}"
        pwd = "StrongPassword123!"

        client.post("/auth/register", json={"username": u1, "email": f"{u1}@example.com", "password": pwd})
        client.post("/auth/register", json={"username": u2, "email": f"{u2}@example.com", "password": pwd})

        # U1 logs in twice
        u1_log1 = client.post("/auth/login", json={"username": u1, "password": pwd})
        u1_log2 = client.post("/auth/login", json={"username": u1, "password": pwd})
        t1_1 = u1_log1.json()["access_token"]
        t1_2 = u1_log2.json()["access_token"]

        # U2 logs in once
        u2_log = client.post("/auth/login", json={"username": u2, "password": pwd})
        t2 = u2_log.json()["access_token"]

        # List U1 sessions
        u1_sess = client.get("/auth/sessions", headers={"Authorization": f"Bearer {t1_1}"})
        assert u1_sess.status_code == 200
        s_list = u1_sess.json()
        assert len(s_list) == 2

        # Check current session indicator
        curr_session = [s for s in s_list if s["is_current"]]
        assert len(curr_session) == 1

        # U1 revokes their second session
        other_jti = [s["jti"] for s in s_list if not s["is_current"]][0]
        rev_res = client.post(f"/auth/sessions/{other_jti}/revoke", headers={"Authorization": f"Bearer {t1_1}"})
        assert rev_res.status_code == 200

        # Using second token t1_2 now returns 401
        assert client.get("/auth/me", headers={"Authorization": f"Bearer {t1_2}"}).status_code == 401

        # U1 tries to revoke U2 session -> 404
        u2_sess_list = client.get("/auth/sessions", headers={"Authorization": f"Bearer {t2}"}).json()
        u2_jti = u2_sess_list[0]["jti"]

        bad_rev = client.post(f"/auth/sessions/{u2_jti}/revoke", headers={"Authorization": f"Bearer {t1_1}"})
        assert bad_rev.status_code == 404

def test_notification_settings_get_and_update():
    with TestClient(app) as client:
        username = f"notif_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        client.post("/auth/register", json={"username": username, "email": email, "password": password})
        login_res = client.post("/auth/login", json={"username": username, "password": password})
        token = login_res.json()["access_token"]

        # Get defaults
        get_res = client.get("/notifications/settings", headers={"Authorization": f"Bearer {token}"})
        assert get_res.status_code == 200
        assert get_res.json()["email_notifications"] is True

        # Update
        put_res = client.put(
            "/notifications/settings",
            headers={"Authorization": f"Bearer {token}"},
            json={"email_notifications": False, "security_alerts": True}
        )
        assert put_res.status_code == 200
        assert put_res.json()["email_notifications"] is False
        assert put_res.json()["security_alerts"] is True

def test_mfa_pending_token_cannot_be_reused():
    with TestClient(app) as client:
        username = f"mfa_replay_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "StrongPassword123!"

        # Register
        reg_res = client.post(
            "/auth/register",
            json={
                "username": username,
                "email": email,
                "password": password,
            },
        )
        assert reg_res.status_code == 201

        # Normal login before MFA setup
        login_res = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": password,
            },
        )
        assert login_res.status_code == 200
        access_token = login_res.json()["access_token"]

        # Initiate MFA
        init_res = client.post(
            "/auth/mfa/setup/initiate",
            headers={"Authorization": f"Bearer {access_token}"},
            json={"password": password},
        )
        assert init_res.status_code == 200
        secret = init_res.json()["secret"]

        # Confirm MFA
        setup_code = pyotp.TOTP(secret).now()
        confirm_res = client.post(
            "/auth/mfa/setup/confirm",
            headers={"Authorization": f"Bearer {access_token}"},
            json={"code": setup_code},
        )
        assert confirm_res.status_code == 200

        # Login now requires MFA
        mfa_login = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": password,
            },
        )
        assert mfa_login.status_code == 200

        mfa_data = mfa_login.json()
        assert mfa_data["mfa_required"] is True

        mfa_token = mfa_data["mfa_token"]

        # First verification must succeed.
        otp = pyotp.TOTP(secret).now()

        first_verify = client.post(
            "/auth/mfa/verify",
            json={
                "mfa_token": mfa_token,
                "code": otp,
            },
        )

        assert first_verify.status_code == 200
        assert first_verify.json()["access_token"] is not None

        # Reusing the exact same pending MFA token must fail.
        second_verify = client.post(
            "/auth/mfa/verify",
            json={
                "mfa_token": mfa_token,
                "code": otp,
            },
        )

        assert second_verify.status_code == 401
        assert "already used" in second_verify.json()["detail"]

