from types import SimpleNamespace
from sqlalchemy import create_engine, text
from backend.core.permission_service import PermissionService
from backend.database.migrations import run_migrations
from backend.database.repositories.group_repo import GroupRepository
from backend.database.repositories.share_repo import ShareRepository
from backend.security.share_key_service import ShareKeyService


def test_share_key_is_share_and_recipient_bound():
    key=ShareKeyService.generate_key()
    a=ShareKeyService.hash_key(101,7,key)
    assert a==ShareKeyService.hash_key(101,7,key)
    assert a!=ShareKeyService.hash_key(101,8,key)
    assert a!=ShareKeyService.hash_key(102,7,key)
    assert key not in a


def test_share_key_verification_rejects_wrong_input():
    key=ShareKeyService.generate_key(); digest=ShareKeyService.hash_key(44,9,key)
    assert ShareKeyService.verify_key(44,9,key,digest)
    assert not ShareKeyService.verify_key(44,9,key+'x',digest)
    assert not ShareKeyService.verify_key(44,10,key,digest)
    assert not ShareKeyService.verify_key(45,9,key,digest)


def test_share_key_migration_adds_columns():
    engine=create_engine('sqlite:///:memory:',future=True)
    with engine.begin() as c:
        c.execute(text("CREATE TABLE document_shares (id INTEGER PRIMARY KEY AUTOINCREMENT, document_id INTEGER NOT NULL, owner_id INTEGER NOT NULL, target_user_id INTEGER NOT NULL, permission TEXT NOT NULL DEFAULT 'READ', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revoked_at TEXT)"))
    run_migrations(engine)
    with engine.connect() as c:
        cols={r[1] for r in c.execute(text('PRAGMA table_info(document_shares)')).fetchall()}
    assert {'share_key_hash','share_key_required','share_key_verified_at','share_key_created_at','share_key_rotated_at'} <= cols


def test_unverified_protected_direct_share_is_blocked(monkeypatch):
    user=SimpleNamespace(id=20,role='user'); doc=SimpleNamespace(id=500,owner_id=1,is_access_locked=0)
    direct=SimpleNamespace(permission='WRITE',share_key_required=1,share_key_verified_at=None)
    monkeypatch.setattr(ShareRepository,'get_active_direct_share',lambda self,d,u: direct)
    monkeypatch.setattr(GroupRepository,'get_user_group_ids',lambda self,u: [])
    assert PermissionService.get_user_permission(None,user,doc)=='NONE'


def test_verified_protected_direct_share_is_allowed(monkeypatch):
    user=SimpleNamespace(id=20,role='user'); doc=SimpleNamespace(id=500,owner_id=1,is_access_locked=0)
    direct=SimpleNamespace(permission='WRITE',share_key_required=1,share_key_verified_at='2026-10-07T12:00:00+00:00')
    monkeypatch.setattr(ShareRepository,'get_active_direct_share',lambda self,d,u: direct)
    monkeypatch.setattr(GroupRepository,'get_user_group_ids',lambda self,u: [])
    assert PermissionService.get_user_permission(None,user,doc)=='WRITE'


def test_group_permission_remains_independent(monkeypatch):
    user=SimpleNamespace(id=20,role='user'); doc=SimpleNamespace(id=500,owner_id=1,is_access_locked=0)
    direct=SimpleNamespace(permission='WRITE',share_key_required=1,share_key_verified_at=None)
    group=SimpleNamespace(permission='READ')
    monkeypatch.setattr(ShareRepository,'get_active_direct_share',lambda self,d,u: direct)
    monkeypatch.setattr(GroupRepository,'get_user_group_ids',lambda self,u: [77])
    monkeypatch.setattr(ShareRepository,'get_active_group_shares_for_groups',lambda self,d,g:[group])
    assert PermissionService.get_user_permission(None,user,doc)=='READ'


def test_share_repository_has_key_helpers():
    assert hasattr(ShareRepository,'set_share_key')
    assert hasattr(ShareRepository,'mark_share_key_verified')
    assert hasattr(ShareRepository,'clear_share_key')
