ROLE_SUPER_ADMIN = "super_admin"
ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLE_CLUB_OWNER = "club_owner"
ROLE_CLUB_MODERATOR = "club_moderator"
ROLE_CLUB_MEMBER = "club_member"

PLATFORM_SCOPE = "platform"
CLUB_SCOPE = "club"

ROLE_NAMES = (
    ROLE_SUPER_ADMIN,
    ROLE_ADMIN,
    ROLE_USER,
    ROLE_CLUB_OWNER,
    ROLE_CLUB_MODERATOR,
    ROLE_CLUB_MEMBER,
)
PLATFORM_ROLE_NAMES = (ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_USER)
CLUB_ROLE_NAMES = (ROLE_CLUB_OWNER, ROLE_CLUB_MODERATOR, ROLE_CLUB_MEMBER)
ROLE_SCOPES = {
    ROLE_SUPER_ADMIN: PLATFORM_SCOPE,
    ROLE_ADMIN: PLATFORM_SCOPE,
    ROLE_USER: PLATFORM_SCOPE,
    ROLE_CLUB_OWNER: CLUB_SCOPE,
    ROLE_CLUB_MODERATOR: CLUB_SCOPE,
    ROLE_CLUB_MEMBER: CLUB_SCOPE,
}

ROLE_CREATE = "role.create"
ROLES_VIEW_ALL = "roles.view_all"
ROLE_VIEW_ONE = "role.view_one"
ROLE_UPDATE = "role.update"
ROLE_DELETE = "role.delete"
ROLES_VIEW = "roles.view"
PERMISSION_CREATE = "permission.create"
PERMISSIONS_VIEW_ALL = "permissions.view_all"
PERMISSION_VIEW_ONE = "permission.view_one"
PERMISSION_UPDATE = "permission.update"
PERMISSION_DELETE = "permission.delete"
PERMISSIONS_MANAGE = "permissions.manage"

USERS_VIEW_ALL = "users.view_all"
USER_VIEW_ONE = "user.view_one"
USER_CREATE = "user.create"
USER_UPDATE = "user.update"
USER_BAN = "user.ban"
USER_UNBAN = "user.unban"

REPORTS_VIEW_ALL = "reports.view_all"
REPORT_VIEW_ONE = "report.view_one"
REPORT_UPDATE = "report.update"
REPORT_DELETE = "report.delete"
REPORT_CREATE = "report.create"
REPORT_REVIEW_CLUB = "report.review_club"

CLUB_CREATE = "club.create"
CLUB_UPDATE = "club.update"
CLUB_DELETE = "club.delete"
CLUB_READ_PRIVATE = "club.read_private"

MEMBER_READ = "member.read"
MEMBER_REMOVE = "member.remove"
MEMBER_BAN = "member.ban"
MEMBER_UNBAN = "member.unban"
MEMBER_INVITE = "member.invite"
MEMBER_SET_ROLE = "member.set_role"

PODCAST_DELETE = "podcast.delete"
PODCAST_CREATE = "podcast.create"
PODCAST_UPDATE = "podcast.update"

EPISODE_CREATE = "episode.create"
EPISODE_UPDATE_OWN = "episode.update_own"
EPISODE_DELETE_OWN = "episode.delete_own"
EPISODE_UPDATE_ANY = "episode.update_any"
EPISODE_DELETE_ANY = "episode.delete_any"

MESSAGE_READ = "message.read"
MESSAGE_DELETE_ANY = "message.delete_any"
MESSAGE_CREATE = "message.create"
MESSAGE_EDIT_OWN = "message.edit_own"
MESSAGE_DELETE_OWN = "message.delete_own"

PERMISSION_NAMES = frozenset(
    {
        ROLE_CREATE,
        ROLES_VIEW_ALL,
        ROLE_VIEW_ONE,
        ROLE_UPDATE,
        ROLE_DELETE,
        ROLES_VIEW,
        PERMISSION_CREATE,
        PERMISSIONS_VIEW_ALL,
        PERMISSION_VIEW_ONE,
        PERMISSION_UPDATE,
        PERMISSION_DELETE,
        PERMISSIONS_MANAGE,
        USERS_VIEW_ALL,
        USER_VIEW_ONE,
        USER_CREATE,
        USER_UPDATE,
        USER_BAN,
        USER_UNBAN,
        REPORTS_VIEW_ALL,
        REPORT_VIEW_ONE,
        REPORT_UPDATE,
        REPORT_DELETE,
        REPORT_CREATE,
        REPORT_REVIEW_CLUB,
        CLUB_CREATE,
        CLUB_UPDATE,
        CLUB_DELETE,
        CLUB_READ_PRIVATE,
        MEMBER_READ,
        MEMBER_REMOVE,
        MEMBER_BAN,
        MEMBER_UNBAN,
        MEMBER_INVITE,
        MEMBER_SET_ROLE,
        PODCAST_DELETE,
        PODCAST_CREATE,
        PODCAST_UPDATE,
        EPISODE_CREATE,
        EPISODE_UPDATE_OWN,
        EPISODE_DELETE_OWN,
        EPISODE_UPDATE_ANY,
        EPISODE_DELETE_ANY,
        MESSAGE_READ,
        MESSAGE_DELETE_ANY,
        MESSAGE_CREATE,
        MESSAGE_EDIT_OWN,
        MESSAGE_DELETE_OWN,
    }
)

GRANTS = {
    ROLE_SUPER_ADMIN: PERMISSION_NAMES,
    ROLE_ADMIN: frozenset(
        {
            USERS_VIEW_ALL,
            USER_VIEW_ONE,
            USER_CREATE,
            USER_UPDATE,
            USER_BAN,
            USER_UNBAN,
            REPORTS_VIEW_ALL,
            REPORT_VIEW_ONE,
            REPORT_UPDATE,
            REPORT_DELETE,
            REPORT_CREATE,
            CLUB_CREATE,
            CLUB_UPDATE,
            CLUB_DELETE,
            CLUB_READ_PRIVATE,
            MEMBER_READ,
            MEMBER_REMOVE,
            MEMBER_BAN,
            MEMBER_UNBAN,
            PODCAST_DELETE,
            EPISODE_CREATE,
            EPISODE_UPDATE_ANY,
            EPISODE_DELETE_ANY,
            MESSAGE_READ,
            MESSAGE_DELETE_ANY,
        }
    ),
    ROLE_USER: frozenset({CLUB_CREATE, REPORT_CREATE, USER_VIEW_ONE}),
    ROLE_CLUB_OWNER: frozenset(
        {
            CLUB_UPDATE,
            CLUB_DELETE,
            CLUB_READ_PRIVATE,
            MEMBER_READ,
            MEMBER_INVITE,
            MEMBER_REMOVE,
            MEMBER_BAN,
            MEMBER_UNBAN,
            MEMBER_SET_ROLE,
            REPORT_REVIEW_CLUB,
            PODCAST_CREATE,
            PODCAST_UPDATE,
            PODCAST_DELETE,
            EPISODE_CREATE,
            EPISODE_UPDATE_OWN,
            EPISODE_DELETE_OWN,
            EPISODE_UPDATE_ANY,
            EPISODE_DELETE_ANY,
            MESSAGE_READ,
            MESSAGE_CREATE,
            MESSAGE_EDIT_OWN,
            MESSAGE_DELETE_OWN,
            MESSAGE_DELETE_ANY,
        }
    ),
    ROLE_CLUB_MODERATOR: frozenset(
        {
            CLUB_READ_PRIVATE,
            MEMBER_READ,
            MEMBER_INVITE,
            PODCAST_CREATE,
            PODCAST_UPDATE,
            PODCAST_DELETE,
            EPISODE_CREATE,
            EPISODE_UPDATE_OWN,
            EPISODE_DELETE_OWN,
            EPISODE_UPDATE_ANY,
            EPISODE_DELETE_ANY,
            MESSAGE_READ,
            MESSAGE_CREATE,
            MESSAGE_EDIT_OWN,
            MESSAGE_DELETE_OWN,
            MESSAGE_DELETE_ANY,
        }
    ),
    ROLE_CLUB_MEMBER: frozenset(
        {
            CLUB_READ_PRIVATE,
            MEMBER_READ,
            EPISODE_CREATE,
            EPISODE_UPDATE_OWN,
            EPISODE_DELETE_OWN,
            MESSAGE_READ,
            MESSAGE_CREATE,
            MESSAGE_EDIT_OWN,
            MESSAGE_DELETE_OWN,
        }
    ),
}
