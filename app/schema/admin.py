from pydantic import BaseModel


class AdminStatsOut(BaseModel):
    users_total: int
    users_active: int
    users_banned: int
    podclubs_total: int
    podclubs_active: int
    podclubs_public: int
    memberships_total: int
    podcasts_total: int
    episodes_total: int
    messages_total: int
    reports_total: int
    reports_pending: int
    invites_total: int
