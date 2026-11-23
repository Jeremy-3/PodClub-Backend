from fastapi import APIRouter

from app.routes.episode import router as episode_router
from app.routes.invite import router as invite_router
from app.routes.message import router as message_router
from app.routes.permission import router as permission_router
from app.routes.podcast import router as podcast_router
from app.routes.podclub import router as podclub_router
from app.routes.podclub_member import router as podclub_member_router
from app.routes.report import router as report_router
from app.routes.role import router as role_router
from app.routes.role_permission import router as role_permission_router
from app.routes.user import router as user_router

api_router = APIRouter()
api_router.include_router(user_router)
api_router.include_router(role_router)
api_router.include_router(permission_router)
api_router.include_router(role_permission_router)
api_router.include_router(podclub_router)
api_router.include_router(podclub_member_router)
api_router.include_router(invite_router)
api_router.include_router(podcast_router)
api_router.include_router(episode_router)
api_router.include_router(message_router)
api_router.include_router(report_router)

__all__ = ["api_router"]
