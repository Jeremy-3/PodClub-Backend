from uuid import uuid4


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_user_cannot_list_users_but_admin_can(client, user_a_token, admin_token):
    user_response = client.get("/users", headers=_headers(user_a_token))
    admin_response = client.get("/users", headers=_headers(admin_token))

    assert user_response.status_code == 403
    assert admin_response.status_code == 200


def test_user_detail_is_self_or_admin_only(
    client, user_a, user_a_token, user_b, admin_token
):
    own_user = client.get(f"/users/{user_a['uid']}", headers=_headers(user_a_token))
    other_user = client.get(f"/users/{user_b['uid']}", headers=_headers(user_a_token))
    admin_user = client.get(f"/users/{user_b['uid']}", headers=_headers(admin_token))

    assert own_user.status_code == 200
    assert other_user.status_code == 403
    assert admin_user.status_code == 200


def test_admin_cannot_modify_or_assign_super_admin(
    client, admin_token, user_a, super_admin_user, seeded_core
):
    headers = _headers(admin_token)
    modify_super_admin = client.put(
        f"/users/{super_admin_user['uid']}",
        json={"is_active": False},
        headers=headers,
    )
    assign_super_admin = client.put(
        f"/users/{user_a['uid']}",
        json={"role_id": seeded_core["super_admin"]},
        headers=headers,
    )
    create_super_admin = client.post(
        "/users",
        json={
            "username": f"new_super_{uuid4().hex}",
            "email": f"new_super_{uuid4().hex}@podclub.io",
            "password": "Password123!",
            "role_id": seeded_core["super_admin"],
        },
        headers=headers,
    )

    assert modify_super_admin.status_code == 403
    assert assign_super_admin.status_code == 403
    assert create_super_admin.status_code == 403
