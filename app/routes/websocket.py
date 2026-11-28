from uuid import UUID

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.core.perm_names import MESSAGE_READ
from app.db.session import get_db
from app.dependencies.access import Access
from app.dependencies.auth import _get_user_from_token
from app.models.podclubs import PodClubs
from app.services.websockets import connection_manager


router = APIRouter()


def _club_channel(podclub_id: int) -> str:
    return f"podclub:{podclub_id}"


@router.websocket("/ws/podclubs/{uid}")
async def podclub_events(
    websocket: WebSocket,
    uid: UUID,
    token: str | None = None,
):
    db: Session = next(get_db())
    try:
        if token is None:
            await websocket.close(code=1008, reason="Authentication required")
            return

        user = _get_user_from_token(token, db)
        club = db.query(PodClubs).filter(PodClubs.uid == uid).first()
        if club is None:
            await websocket.close(code=1008, reason="PodClub not found")
            return

        access = Access(db=db, user=user)
        if not access.club_visible(club):
            await websocket.close(code=1008, reason="PodClub not found")
            return
        access.require(MESSAGE_READ, club)

        channel = _club_channel(club.id)
        await connection_manager.connect(channel, websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            connection_manager.disconnect(channel, websocket)
    except Exception as exc:
        try:
            await websocket.close(code=1008, reason=str(exc))
        except Exception:
            pass
    finally:
        db.close()
