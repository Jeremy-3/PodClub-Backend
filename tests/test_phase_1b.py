from uuid import uuid4

import pytest

from app.commands.seed import _seed_roles_and_permissions
from app.core.perm_names import (
    CLUB_ROLE_NAMES,
    GRANTS,
    PERMISSION_NAMES,
    PLATFORM_ROLE_NAMES,
    ROLE_NAMES,
    ROLE_USER,
    USER_UPDATE,
)
from app.core.security import hash_password
from app.dependencies.access import Access
from app.models.permissions import Permissions
from app.models.podclub_members import PodClubMembers
from app.models.podclubs import PodClubs
from app.models.role_permissions import RolePermission
from app.models.roles import RoleScope, Roles
from app.models.users import Users


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


ROLE_PERMISSION_CASES = [
    (role_name, permission_name)
    for role_name in ROLE_NAMES
    for permission_name in sorted(PERMISSION_NAMES)
]


@pytest.mark.parametrize(
    ("role_name", "permission_name"),
    ROLE_PERMISSION_CASES,
    ids=[f"{role}-{permission}" for role, permission in ROLE_PERMISSION_CASES],
)
def test_role_permission_matrix(
    role_name, permission_name, db_session, seeded_core
):
    platform_role_name = role_name if role_name in PLATFORM_ROLE_NAMES else ROLE_USER
    user_role = db_session.get(Roles, seeded_core[platform_role_name])
    user = Users(
        username=f"matrix_{uuid4().hex}",
        email=f"matrix_{uuid4().hex}@podclub.io",
        password_hash=hash_password("Password123!"),
        role_id=user_role.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()

    club = PodClubs(
        name=f"matrix_{uuid4().hex}",
        owner_id=user.id if role_name == "club_owner" else None,
        is_active=True,
        is_private=True,
    )
    db_session.add(club)
    db_session.flush()

    if role_name in {"club_moderator", "club_member"}:
        db_session.add(
            PodClubMembers(
                podclub_id=club.id,
                user_id=user.id,
                role_id=seeded_core[role_name],
            )
        )
        db_session.flush()

    access = Access(db_session, user)
    if role_name == "super_admin":
        expected_in_club = True
        expected_globally = True
    elif role_name in CLUB_ROLE_NAMES:
        expected_in_club = permission_name in (
            set(GRANTS[ROLE_USER]) | set(GRANTS[role_name])
        )
        expected_globally = permission_name in GRANTS[ROLE_USER]
    else:
        expected_in_club = permission_name in GRANTS[role_name]
        expected_globally = permission_name in GRANTS[role_name]

    assert access.can(permission_name, club) is expected_in_club
    assert access.can(permission_name) is expected_globally


def test_private_club_is_hidden_from_outsider_but_visible_to_member_and_admin(
    client, club_context, outsider_token, member_token, admin_token
):
    uid = club_context["club"].uid
    outsider_response = client.get(
        f"/podclubs/{uid}", headers=_headers(outsider_token)
    )
    member_response = client.get(f"/podclubs/{uid}", headers=_headers(member_token))
    admin_response = client.get(f"/podclubs/{uid}", headers=_headers(admin_token))

    assert outsider_response.status_code == 404
    assert member_response.status_code == 200
    assert admin_response.status_code == 200


def test_resources_cannot_be_moved_by_update_payload(
    client, club_context, super_admin_token
):
    headers = _headers(super_admin_token)
    podcast_response = client.put(
        f"/podcasts/{club_context['podcast'].uid}",
        json={"podclub_id": club_context["other_club"].id},
        headers=headers,
    )
    episode_response = client.put(
        f"/episodes/{club_context['member_episode'].uid}",
        json={"podcast_id": club_context["other_podcast"].id},
        headers=headers,
    )

    assert podcast_response.status_code == 422
    assert episode_response.status_code == 422


def test_club_ban_blocks_readd_read_and_post_until_unbanned(
    client, club_context, club_owner_token, banned_user, banned_user_token
):
    club = club_context["club"]
    owner_headers = _headers(club_owner_token)
    user_headers = _headers(banned_user_token)

    ban_response = client.post(
        f"/podclubs/{club.uid}/bans",
        json={"user_id": banned_user["id"], "reason": "test ban"},
        headers=owner_headers,
    )
    assert ban_response.status_code == 200

    readd_while_banned = client.post(
        "/podclub-members",
        json={"podclub_id": club.id, "user_id": banned_user["id"]},
        headers=owner_headers,
    )
    read_while_banned = client.get(
        f"/messages?podclub_id={club.id}", headers=user_headers
    )
    post_while_banned = client.post(
        "/messages",
        json={"podclub_id": club.id, "body": "should be blocked"},
        headers=user_headers,
    )

    assert readd_while_banned.status_code == 403
    assert read_while_banned.status_code == 404
    assert post_while_banned.status_code == 404

    unban_response = client.delete(
        f"/podclubs/{club.uid}/bans/{banned_user['id']}",
        headers=owner_headers,
    )
    readd_after_unban = client.post(
        "/podclub-members",
        json={"podclub_id": club.id, "user_id": banned_user["id"]},
        headers=owner_headers,
    )
    read_after_unban = client.get(
        f"/messages?podclub_id={club.id}", headers=user_headers
    )
    post_after_unban = client.post(
        "/messages",
        json={"podclub_id": club.id, "body": "access restored"},
        headers=user_headers,
    )

    assert unban_response.status_code == 200
    assert readd_after_unban.status_code == 200
    assert read_after_unban.status_code == 200
    assert post_after_unban.status_code == 200


def test_banned_from_club_fixture_cannot_be_readded_or_read(
    client, club_context, banned_from_club, banned_user_token, club_owner_token
):
    readd_response = client.post(
        "/podclub-members",
        json={
            "podclub_id": club_context["club"].id,
            "user_id": banned_from_club["id"],
        },
        headers=_headers(club_owner_token),
    )
    read_response = client.get(
        f"/messages?podclub_id={club_context['club'].id}",
        headers=_headers(banned_user_token),
    )

    assert readd_response.status_code == 403
    assert read_response.status_code == 404


def test_platform_ban_blocks_login_and_existing_token(
    client, admin_token, outsider, outsider_token
):
    ban_response = client.post(
        f"/users/{outsider['uid']}/ban",
        headers=_headers(admin_token),
    )
    token_response = client.get(
        "/auth/me", headers=_headers(outsider_token)
    )
    login_response = client.post(
        "/auth/login",
        data={"username": outsider["username"], "password": "Password123!"},
    )

    assert ban_response.status_code == 200
    assert token_response.status_code == 403
    assert login_response.status_code == 403


def test_admin_cannot_ban_super_admin_or_another_admin(
    client, admin_token, super_admin_user, second_admin
):
    super_admin_response = client.post(
        f"/users/{super_admin_user['uid']}/ban",
        headers=_headers(admin_token),
    )
    other_admin_response = client.post(
        f"/users/{second_admin['uid']}/ban",
        headers=_headers(admin_token),
    )

    assert super_admin_response.status_code == 403
    assert other_admin_response.status_code == 403


def test_role_scope_assignment_and_system_role_guards(
    client,
    db_session,
    seeded_core,
    admin_token,
    super_admin_token,
    club_owner_token,
    club_context,
):
    suffix = uuid4().hex
    assign_club_role_to_user = client.post(
        "/users",
        json={
            "username": f"club_role_user_{suffix}",
            "email": f"club_role_user_{suffix}@podclub.io",
            "password": "Password123!",
            "role_id": seeded_core["club_member"],
        },
        headers=_headers(admin_token),
    )
    assign_platform_role_to_member = client.put(
        f"/podclub-members/{club_context['member_membership'].uid}",
        json={"role": "user"},
        headers=_headers(club_owner_token),
    )

    system_role = db_session.get(Roles, seeded_core["user"])
    rename_system_role = client.put(
        f"/roles/{system_role.uid}",
        json={"name": "renamed_user"},
        headers=_headers(super_admin_token),
    )
    delete_system_role = client.delete(
        f"/roles/{system_role.uid}",
        headers=_headers(super_admin_token),
    )

    assert assign_club_role_to_user.status_code == 400
    assert assign_platform_role_to_member.status_code == 422
    assert rename_system_role.status_code == 409
    assert delete_system_role.status_code == 409


def test_role_in_use_cannot_be_deleted(
    client, db_session, outsider, super_admin_token
):
    role = Roles(
        name=f"in_use_{uuid4().hex}",
        active=True,
        scope=RoleScope.PLATFORM,
        is_system=False,
    )
    db_session.add(role)
    db_session.flush()
    user = db_session.get(Users, outsider["id"])
    user.role_id = role.id
    db_session.commit()

    response = client.delete(
        f"/roles/{role.uid}",
        headers=_headers(super_admin_token),
    )

    assert response.status_code == 409


def test_report_review_is_limited_to_the_owner_club(
    client, club_context, club_owner_token
):
    headers = _headers(club_owner_token)
    own_club_id = club_context["club"].id
    other_club_id = club_context["other_club"].id
    report_uid = club_context["own_report"].uid
    other_report_uid = club_context["other_report"].uid

    missing_scope = client.get("/reports", headers=headers)
    own_list = client.get(f"/reports?podclub_id={own_club_id}", headers=headers)
    other_list = client.get(f"/reports?podclub_id={other_club_id}", headers=headers)
    review_own = client.put(
        f"/reports/{report_uid}",
        json={"status": "reviewed"},
        headers=headers,
    )
    review_other = client.put(
        f"/reports/{other_report_uid}",
        json={"status": "reviewed"},
        headers=headers,
    )

    assert missing_scope.status_code == 422
    assert own_list.status_code == 200
    assert other_list.status_code == 404
    assert review_own.status_code == 200
    assert review_other.status_code == 404


def test_report_club_is_derived_from_referenced_message(
    client, club_context, member_token, moderator
):
    response = client.post(
        "/reports",
        json={
            "reported_user_id": moderator["id"],
            "reason": "Report a message",
            "message_id": club_context["owner_message"].id,
            "podclub_id": club_context["other_club"].id,
        },
        headers=_headers(member_token),
    )

    assert response.status_code == 200
    assert response.json()["data"]["podclub_id"] == club_context["club"].id


def test_report_create_rejects_client_managed_fields(
    client, club_context, member_token, moderator, member
):
    response = client.post(
        "/reports",
        json={
            "reported_user_id": moderator["id"],
            "reason": "Client-managed values must be rejected",
            "podclub_id": club_context["club"].id,
            "reporter_id": member["id"],
            "reviewed_by_id": member["id"],
            "status": "resolved",
        },
        headers=_headers(member_token),
    )

    assert response.status_code == 422


def test_message_and_episode_own_vs_any_permissions(
    client,
    club_context,
    member_token,
    admin_token,
):
    member_headers = _headers(member_token)
    admin_headers = _headers(admin_token)

    edit_own_message = client.put(
        f"/messages/{club_context['member_message'].uid}",
        json={"body": "edited by author"},
        headers=member_headers,
    )
    edit_other_message = client.put(
        f"/messages/{club_context['owner_message'].uid}",
        json={"body": "not the author"},
        headers=member_headers,
    )
    delete_own_message = client.delete(
        f"/messages/{club_context['member_message'].uid}",
        headers=member_headers,
    )
    delete_any_message = client.delete(
        f"/messages/{club_context['owner_message'].uid}",
        headers=admin_headers,
    )

    update_own_episode = client.put(
        f"/episodes/{club_context['member_episode'].uid}",
        json={"title": "updated by creator"},
        headers=member_headers,
    )
    update_other_episode = client.put(
        f"/episodes/{club_context['owner_episode'].uid}",
        json={"title": "not the creator"},
        headers=member_headers,
    )
    delete_own_episode = client.delete(
        f"/episodes/{club_context['member_episode'].uid}",
        headers=member_headers,
    )
    delete_any_episode = client.delete(
        f"/episodes/{club_context['owner_episode'].uid}",
        headers=admin_headers,
    )

    assert edit_own_message.status_code == 200
    assert edit_other_message.status_code == 403
    assert delete_own_message.status_code == 200
    assert delete_any_message.status_code == 200
    assert update_own_episode.status_code == 200
    assert update_other_episode.status_code == 403
    assert delete_own_episode.status_code == 200
    assert delete_any_episode.status_code == 200


def test_runtime_permission_change_takes_effect_without_new_token(
    client,
    db_session,
    club_context,
    member_token,
    seeded_core,
):
    headers = _headers(member_token)
    path = f"/messages?podclub_id={club_context['club'].id}"
    before_change = client.get(path, headers=headers)

    message_read = (
        db_session.query(Permissions)
        .filter(Permissions.name == "message.read")
        .one()
    )
    grant = (
        db_session.query(RolePermission)
        .filter(
            RolePermission.role_id == seeded_core["club_member"],
            RolePermission.permission_id == message_read.id,
        )
        .one()
    )
    db_session.delete(grant)
    db_session.commit()

    after_change = client.get(path, headers=headers)

    assert before_change.status_code == 200
    assert after_change.status_code == 403


def test_seed_is_idempotent_and_reset_restores_declared_grants(
    db_session, seeded_core
):
    def counts():
        return (
            db_session.query(Roles).count(),
            db_session.query(Permissions).count(),
            db_session.query(RolePermission).count(),
        )

    before = counts()
    _seed_roles_and_permissions(db_session)
    _seed_roles_and_permissions(db_session)
    assert counts() == before

    user_role = db_session.get(Roles, seeded_core[ROLE_USER])
    extra_permission = db_session.query(Permissions).filter(
        Permissions.name == USER_UPDATE
    ).one()
    obsolete_permission = (
        db_session.query(Permissions)
        .filter(Permissions.name == "obsolete.phase_1b_test")
        .one_or_none()
    )
    if obsolete_permission is None:
        obsolete_permission = Permissions(
            name="obsolete.phase_1b_test",
            description="Temporary test permission",
            category="obsolete",
        )
        db_session.add(obsolete_permission)
        db_session.flush()

    existing_extra_grant = (
        db_session.query(RolePermission)
        .filter(
            RolePermission.role_id == user_role.id,
            RolePermission.permission_id == extra_permission.id,
        )
        .one_or_none()
    )
    if existing_extra_grant is None:
        db_session.add(
            RolePermission(
                role_id=user_role.id,
                permission_id=extra_permission.id,
            )
        )
    db_session.flush()

    _seed_roles_and_permissions(db_session, reset_permissions=True)

    assert (
        db_session.query(Permissions)
        .filter(Permissions.name == "obsolete.phase_1b_test")
        .count()
        == 0
    )
    for role_name in ROLE_NAMES:
        role = db_session.get(Roles, seeded_core[role_name])
        actual_grants = {
            permission_name
            for (permission_name,) in (
                db_session.query(Permissions.name)
                .join(
                    RolePermission,
                    RolePermission.permission_id == Permissions.id,
                )
                .filter(RolePermission.role_id == role.id)
                .all()
            )
        }
        assert actual_grants == set(GRANTS[role_name])
