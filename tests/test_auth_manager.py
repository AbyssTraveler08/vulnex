import tempfile

from auth_manager import APPROVED, AuthStore


def test_signup_requires_approval_before_login():
    store = AuthStore(tempfile.mkdtemp())
    ok, _ = store.create_admin("admin", "StrongAdminPass123!")
    assert ok
    ok, _ = store.signup("alice", "alice@example.com", "UserPass123!")
    assert ok

    ok, _ = store.authenticate("alice", "UserPass123!", "user")
    assert not ok

    ok, _ = store.set_user_status("alice", APPROVED, "admin")
    assert ok
    ok, user = store.authenticate("alice", "UserPass123!", "user")
    assert ok
    assert user["role"] == "user"


def test_roles_are_separated():
    store = AuthStore(tempfile.mkdtemp())
    store.create_admin("admin", "StrongAdminPass123!")
    store.signup("alice", "alice@example.com", "UserPass123!")
    store.set_user_status("alice", APPROVED, "admin")

    ok, _ = store.authenticate("alice", "UserPass123!", "admin")
    assert not ok
    ok, user = store.authenticate("admin", "StrongAdminPass123!", "admin")
    assert ok
    assert user["role"] == "admin"
