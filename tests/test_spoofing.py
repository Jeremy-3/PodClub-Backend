from uuid import uuid4


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_podclub_owner_id_cannot_be_supplied_by_client(client, user_a, user_a_token):
    response = client.post(
        "/podclubs",
        json={"name": f"spoofed_{uuid4().hex}", "owner_id": user_a["id"]},
        headers=_headers(user_a_token),
    )

    assert response.status_code == 422


def test_message_sender_id_cannot_be_supplied_by_client(
    client, user_a, user_a_token
):
    response = client.post(
        "/messages",
        json={
            "podclub_id": 1,
            "body": "spoofed sender",
            "sender_id": user_a["id"],
        },
        headers=_headers(user_a_token),
    )

    assert response.status_code == 422


def test_profile_update_rejects_role_id(client, user_a_token, seeded_core):
    response = client.put(
        "/users/me",
        json={"role_id": seeded_core["admin"]},
        headers=_headers(user_a_token),
    )

    assert response.status_code == 422


def test_public_profile_has_no_email(client, user_a, user_a_token, user_b):
    response = client.get(
        f"/users/{user_b['uid']}/profile",
        headers=_headers(user_a_token),
    )

    assert response.status_code == 200
    profile = response.json()["data"]
    assert set(profile) == {"uid", "username", "avatar_url", "created_at"}
    assert "email" not in profile
