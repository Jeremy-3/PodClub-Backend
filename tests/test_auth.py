from datetime import datetime, timezone
from uuid import uuid4

from app.core.security import create_access_token
from app.models.users import Users


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_register_creates_user_with_default_user_role(client, seeded_core):
    suffix = uuid4().hex
    response = client.post(
        "/auth/register",
        json={
            "username": f"register_{suffix}",
            "email": f"register_{suffix}@podclub.io",
            "password": "Password123!",
        },
    )

    assert response.status_code == 200
    assert response.json()["data"]["role_id"] == seeded_core["user"]


def test_register_rejects_role_id(client, seeded_core):
    suffix = uuid4().hex
    response = client.post(
        "/auth/register",
        json={
            "username": f"spoof_{suffix}",
            "email": f"spoof_{suffix}@podclub.io",
            "password": "Password123!",
            "role_id": seeded_core["admin"],
        },
    )

    assert response.status_code == 422


def test_register_rejects_duplicate_email(client):
    suffix = uuid4().hex
    email = f"duplicate_{suffix}@podclub.io"
    first = client.post(
        "/auth/register",
        json={
            "username": f"first_{suffix}",
            "email": email,
            "password": "Password123!",
        },
    )
    second = client.post(
        "/auth/register",
        json={
            "username": f"second_{suffix}",
            "email": email,
            "password": "Password123!",
        },
    )

    assert first.status_code == 200
    assert second.status_code == 400


def test_login_accepts_username_or_email_case_insensitively(client, user_a):
    by_username = client.post(
        "/auth/login",
        data={"username": user_a["username"].upper(), "password": "Password123!"},
    )
    by_email = client.post(
        "/auth/login",
        data={"username": user_a["email"].upper(), "password": "Password123!"},
    )

    assert by_username.status_code == 200
    assert by_email.status_code == 200
    assert set(by_username.json()) == {"access_token", "token_type"}
    assert set(by_email.json()) == {"access_token", "token_type"}


def test_wrong_password_and_unknown_user_have_same_401_message(client, user_a):
    wrong_password = client.post(
        "/auth/login",
        data={"username": user_a["username"], "password": "WrongPassword123!"},
    )
    unknown_user = client.post(
        "/auth/login",
        data={
            "username": f"unknown_{uuid4().hex}",
            "password": "WrongPassword123!",
        },
    )

    assert wrong_password.status_code == 401
    assert unknown_user.status_code == 401
    assert wrong_password.json()["message"] == "Incorrect username/email or password"
    assert unknown_user.json()["message"] == wrong_password.json()["message"]


def test_banned_user_is_forbidden_and_inactive_user_is_unauthorized(
    client, db_session, user_a, user_b
):
    banned_user = db_session.get(Users, user_a["id"])
    inactive_user = db_session.get(Users, user_b["id"])
    banned_user.banned_at = datetime.now(timezone.utc)
    inactive_user.is_active = False
    db_session.commit()

    banned_login = client.post(
        "/auth/login",
        data={"username": user_a["username"], "password": "Password123!"},
    )
    banned_me = client.get("/auth/me", headers=_headers(user_a["token"]))
    inactive_login = client.post(
        "/auth/login",
        data={"username": user_b["username"], "password": "Password123!"},
    )
    inactive_me = client.get("/auth/me", headers=_headers(user_b["token"]))

    assert banned_login.status_code == 403
    assert banned_me.status_code == 403
    assert inactive_login.status_code == 401
    assert inactive_me.status_code == 401


def test_auth_me_requires_a_valid_token(client):
    missing_token = client.get("/auth/me")
    invalid_token = client.get("/auth/me", headers=_headers("not-a-jwt"))

    assert missing_token.status_code == 401
    assert invalid_token.status_code == 401


def test_auth_me_returns_permissions_loaded_from_database(
    client, user_a_token
):
    response = client.get("/auth/me", headers=_headers(user_a_token))

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["role"] == "user"
    assert "club.create" in data["permissions"]
    assert "user.view_one" in data["permissions"]
